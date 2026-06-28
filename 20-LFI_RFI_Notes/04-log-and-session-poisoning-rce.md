# 04 — Log & Session Poisoning to RCE

When the wrappers in file 3 aren't available — `allow_url_include` is off, the
`expect` extension isn't installed, and `php://input` is consumed before you
can use it — the remaining strategy is: **find a file the server already
writes attacker-controlled data into, get PHP code embedded in it, then
`include()` that file.** This is a two-step attack: a poisoning step (getting
your payload written somewhere) and a triggering step (including that path).

## 1. Web server access log poisoning

### Step 1 — poison the log

```
GET / HTTP/1.1
Host: target.com
User-Agent: <?php system($_GET['c']); ?>
```

Mechanism:

- Apache and nginx both write every request's `User-Agent` header verbatim
  into their access log files by default (`/var/log/apache2/access.log` or
  `/var/log/nginx/access.log` on most Linux distributions).
- That log line is plain text from the web server's perspective — it has no
  idea the string happens to look like PHP. It's just logging what the client
  sent.
- By setting `User-Agent` to `<?php system($_GET['c']); ?>`, you've gotten
  PHP code written, byte for byte, into a file that **does** sit on disk and
  **is**, in most default configurations, readable by the web server process.

### Step 2 — trigger it through the inclusion point

```
?page=/var/log/apache2/access.log&c=id
```

- The vulnerable `include()` now loads the access log as if it were a PHP
  file.
- The log file is mostly plain text (timestamps, IPs, request paths — none of
  which is valid PHP and gets ignored/output verbatim by the parser), **except**
  for the line where your poisoned `User-Agent` sits, which contains a real
  `<?php ... ?>` block that the parser does recognize and execute.
- `$_GET['c']` is read from the *current* request triggering the include (the
  `&c=id` in this exact request), not from the original poisoning request —
  this is the same mechanism as any other LFI-to-RCE technique in this series:
  you're executing code, and that code can reference the current request's
  parameters normally.

### Conditions this depends on

- You need to know (or guess/brute-force) the **exact log file path** —
  this varies by distro, web server, and configuration. Common paths to try:
  `/var/log/apache2/access.log` (Debian/Ubuntu), `/var/log/httpd/access_log`
  (RHEL/CentOS), `/var/log/nginx/access.log`.
  - **macOS:** historically Apache (httpd) logs to `/private/var/log/apache2/access_log` on older macOS Server installs; modern macOS doesn't ship a default running web server, so this path is mostly historical/legacy-relevant rather than something you'd realistically encounter.
- The web user (`www-data`, `apache`, `nginx`, etc.) must have **read**
  permission on the log file — usually true, since the same process often
  writes it, but some hardened configurations route logging through a
  separate privileged process and restrict read access on the resulting
  files.
- Log rotation is a real practical obstacle: if the log file is large or
  rotates frequently, your poisoned line may no longer be near a position the
  application reads cleanly, or may have already rotated out before you
  trigger the include. In practice you poison and trigger back-to-back to
  minimize this window.

## 2. PHP session file poisoning

### Step 1 — get your payload into your own session file

```
GET /login.php?user=<?php system($_GET['c']); ?> HTTP/1.1
Cookie: PHPSESSID=abc123
```

Mechanism:

- PHP sessions are stored server-side, by default as flat files under a path
  like `/var/lib/php/sessions/sess_<PHPSESSID>` (Debian/Ubuntu) — the exact
  default path is set by the `session.save_path` directive.
- If the application stores any part of *your own input* into a session
  variable — a username field, a "remember this language" preference, a
  search term, anything reflected into `$_SESSION[...]` — that raw value gets
  serialized into your own session file on disk.
- Because it's *your* session, you already know its identifier: it's your own
  `PHPSESSID` cookie value, which you control/can read directly from your
  browser, eliminating the path-guessing problem that log poisoning has for
  the filename portion (though you still need to know `session.save_path`,
  see below).

### Step 2 — trigger it

```
?page=/var/lib/php/sessions/sess_abc123&c=id
```

- Same execution mechanism as log poisoning: the session file is mostly
  PHP's internal serialization format (which is not valid PHP syntax and is
  effectively ignored/output as inert text by the parser) except for the one
  field containing your injected `<?php ?>` block, which the parser executes
  when the file is included.

### Why this is often more reliable than log poisoning

- You don't need to guess a system-wide log path; `session.save_path` has a
  small number of common defaults per distro, and the filename pattern
  (`sess_<PHPSESSID>`) is standard and well known.
- You don't need to fight log rotation — your session file persists for the
  lifetime of your session, which you control.
- The main blocker is finding a parameter that actually gets reflected into a
  session variable at all — not every app does this, and you may need to test
  several input fields (login forms, "remember me" preferences, search/filter
  state) to find one that does.

## 3. `/proc/self/environ` poisoning (largely historical, included for completeness)

```
GET / HTTP/1.1
Host: target.com
User-Agent: <?php system($_GET['c']); ?>
```

then:

```
?page=/proc/self/environ&c=id
```

Mechanism:

- On Linux, every running process has a virtual file at `/proc/self/environ`
  containing its environment variables — and for a request handled by a CGI
  or mod_php-style worker process, the `User-Agent` header is commonly passed
  into the process environment (historically as `HTTP_USER_AGENT`), since
  CGI's design explicitly maps HTTP headers into environment variables.
- This means a poisoned `User-Agent` can land directly in the *current
  process's own* environment file, which is then read via the inclusion bug,
  exactly like the log file technique but without needing to know a log path
  at all — `/proc/self/environ` is a fixed, universal path on any Linux box.

Why this is "historical" rather than "still works" in most cases: it depends
on the web server running each request in a model where the requesting
process's own `/proc/self/environ` is what gets read — true for classic
CGI/mod_php worker-per-request models, but largely irrelevant for the
`php-fpm` + nginx/Apache reverse-proxy architecture that dominates production
PHP deployments today, where `/proc/self/environ` (relative to the PHP-FPM
worker process) may not contain the header the way it did under older
architectures, and where `suexec`/permission separation often blocks read
access entirely regardless. Still worth trying — it's a single extra request —
but don't rely on it as your primary plan against a modern stack.

## 4. Mail-based poisoning (brief mention, rare today)

Older writeups describe poisoning a mail spool file (e.g.
`/var/mail/www-data`) by sending crafted SMTP traffic containing a PHP payload
in the message body, then including the spool file path. This depends on a
locally-reachable mail service accepting attacker-influenced content and on
predictable spool file permissions/paths — narrow enough preconditions that
it's essentially a CTF/legacy technique today rather than something to expect
in a modern engagement. Mentioned for completeness; not worth spending
engagement time on unless you've already confirmed a reachable local mail
service.

## 5. Real-world notes

- Log poisoning is the technique most commonly demonstrated in bug bounty
  proof-of-concept writeups for LFI findings, specifically because it doesn't
  depend on any non-default `php.ini` setting — it works purely off default
  Apache/nginx logging behavior, which makes it the most universally
  applicable LFI-to-RCE technique when wrapper-based approaches (file 3) are
  unavailable.
- Session poisoning is underused relative to how reliable it actually is —
  many testers jump straight to log poisoning and skip checking whether any
  input gets reflected into `$_SESSION`, missing what's often the more
  reliable path because of the path-guessing advantages described in section
  2.
- A detail worth remembering for reporting/communicating impact: both
  techniques require **two separate requests minimum** (poison, then
  trigger) — when writing up a finding, demonstrate both steps explicitly
  rather than assuming the reviewer will infer the poisoning step from the
  trigger request alone.

## 6. What's next

File 5 covers the remaining major branch: Remote File Inclusion, where instead
of poisoning a *local* file, you host your payload yourself and get the
server to fetch and execute it directly from a URL you control.
