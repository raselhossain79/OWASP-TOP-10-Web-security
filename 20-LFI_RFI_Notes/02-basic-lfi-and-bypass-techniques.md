# 02 — Basic LFI Techniques & Filter Bypasses

This file covers the "pure disclosure" side of LFI: no wrappers, no poisoning,
just abusing `include()`/`require()` directly to read files the application
never intended to expose. This is almost always your *first* move against a
suspected inclusion point, because it confirms the vulnerability exists before
you invest time chasing RCE.

## 1. The baseline vulnerable pattern

```php
<?php
include($_GET['page'] . '.php');
```

Piece by piece:

- `$_GET['page']` — attacker-controlled input, no whitelist, no sanitization shown.
- `'.php'` concatenation — the developer's only "defense" is appending a fixed extension, assuming the parameter will only ever be a bare filename. This single assumption is what every bypass in this file attacks.
- `include(...)` — parses and executes whatever file path results.

A request like `?page=home` resolves to `include('home.php')` — normal,
intended behavior. The vulnerability surfaces the moment you can make the
*resolved path* point somewhere the developer didn't intend.

## 2. Basic traversal through the inclusion point

```
?page=../../../../etc/passwd
```

Why this works and what each piece does:

- `../` repeated four times — walks the resolved path up four directory levels from wherever `home.php` would have lived, aiming to reach the filesystem root. The exact count needed depends on how deep the including script lives; if you don't know, over-traverse (`../` six or eight times) — extra `../` past the root is simply ignored by the filesystem, so there's no downside to padding.
- `/etc/passwd` — the classic universal proof-of-concept target on Linux because it's world-readable by default and its presence/format is unambiguous proof you achieved arbitrary file read.
- The `.php` the developer appends now becomes `/etc/passwd.php` — and this is the detail that kills naive traversal against this exact pattern. `/etc/passwd.php` doesn't exist. You need to neutralize that trailing concatenation, which is exactly what sections 3 and 4 below are for.

## 3. Null byte injection (legacy — PHP < 5.3.4 only)

```
?page=../../../../etc/passwd%00
```

Mechanism:

- `%00` is the URL-encoded null byte (`\x00`).
- In C (which the PHP interpreter's underlying filesystem calls were written
  in), a null byte terminates a string. Older PHP versions passed the
  attacker's string straight down to the OS-level file-open call without
  re-validating that no extra data appeared after a null byte.
- The PHP-level string `../../../../etc/passwd\0.php` therefore gets truncated
  by the underlying C function to `../../../../etc/passwd` the moment it
  reaches the OS — the `.php` the developer appended is simply never seen by
  the file-open call.

**Why this is "legacy but still worth knowing" rather than "still works":**
this was patched in **PHP 5.3.4 (December 2010)**, which changed how PHP
handles null bytes in path strings before they reach the OS. You will not find
this working against any maintained, supported PHP install today. It earns its
place in this file for three reasons: (1) it shows up constantly in older
exam/lab material and CTF challenges deliberately running ancient PHP, (2) it's
a textbook example of "input validation happening at the wrong layer" that's
worth understanding conceptually even where it no longer applies, and (3)
during a real engagement, if you ever do encounter a server still running
PHP < 5.3.4 (rare, but legacy industrial/embedded systems and abandoned
internal tools do exist), this is free RCE-adjacent file read with no other
effort.

## 4. Path truncation (also legacy, slightly different mechanism, slightly longer-lived)

```
?page=../../../../etc/passwd/././././././././././ ... (repeated many times)
```

or equivalently with extra trailing slashes/dots padded to exceed the OS path
length limit.

Mechanism — this is a *different* bug from the null byte trick, even though
people often confuse the two:

- Most filesystems have a maximum path length (historically `PATH_MAX`, 4096
  bytes on Linux; `MAX_PATH`, 260 characters, on older Windows).
- Some PHP versions (pre-5.3, overlapping with the null byte window but driven
  by a separate underlying bug) would silently truncate an over-length path
  string when resolving it, **dropping whatever trailing garbage pushed it past
  the limit** — which, if you've padded with `/./././...` *after* your real
  target path and *before* the developer's appended extension, means the
  `.php` suffix gets cut off along with the padding.
- You pad with `/.`  sequences (each one is "current directory," semantically a
  no-op for the path it points to) purely to consume length, repeated roughly
  2000–4000 times depending on target OS, until the total string exceeds the
  limit.

This is included for the same reason as the null byte trick: real value against
genuinely ancient or embedded targets, otherwise a historical technique worth
recognizing by sight so you don't waste time trying to "fix" a payload that's
simply targeting a long-patched bug class.

## 5. Sensitive file targets worth knowing by heart

These aren't payloads to break down — they're just the standard disclosure
targets you reach for once the inclusion point itself is confirmed:

**Linux:**
- `/etc/passwd` — user account list, no passwords (those are in `/etc/shadow`, generally unreadable by the web user), but confirms RCE-class file read and gives you usernames for follow-up attacks.
- `/etc/hosts`, `/etc/hostname` — environment/recon info.
- `/proc/self/environ` — process environment variables; covered as an *RCE* vector (not just disclosure) in file 4.
- Application config files — e.g. `wp-config.php` for WordPress (contains DB credentials in plaintext), `.env` files for many modern frameworks, `config.php`/`settings.php` for countless custom apps.
- `/var/log/apache2/access.log` or `/var/log/nginx/access.log` — read-only here, but this exact file becomes your RCE vector in file 4.

**Windows:**
- `C:\Windows\System32\drivers\etc\hosts`
- `C:\inetpub\wwwroot\web.config` — IIS config, sometimes contains credentials.
- Application config equivalents (e.g. ASP.NET `web.config`, custom app configs).

## 6. Reading source code without it executing — the problem this file *can't* solve

If you try `?page=../config` to read `config.php`, the inclusion function will
*execute* it, not show it to you — and if `config.php` only contains PHP code
with no plain-text output statements, you'll see a blank page even though the
file was successfully included. This is the single biggest practical
frustration with basic LFI: **you can prove the bug exists by reading
non-PHP files (`/etc/passwd`), but you can't read the source of PHP files this
way, because `include()` runs them instead of showing them to you.**

Solving that problem — reading PHP source as text instead of executing it — is
exactly what file 3 opens with (`php://filter` with base64 encoding). That's
the natural next step from everything in this file.

## 7. Real-world notes

- In bug bounty triage, a basic LFI report that stops at "I read `/etc/passwd`"
  routinely gets paid at a lower severity than one that demonstrates source
  code disclosure of an app config file containing live credentials, or one
  that chains into RCE. Programs increasingly require you to demonstrate
  *impact*, not just the read primitive — which is the entire motivation for
  files 3 and 4 of this series.
- The "language/template selector" pattern (`?lang=`, `?template=`, `?page=`,
  `?module=`) remains, in 2026, one of the most commonly reported LFI sources
  in bug bounty programs against legacy PHP stacks — it is worth specifically
  fuzzing any parameter that looks like it's selecting a file or template name,
  even if the UI gives no visible hint that a file is being included.
- Automated discovery: tools like **fimap** and **kadimus** automate the
  process of fuzzing parameters for LFI indicators and trying common
  bypass/wrapper combinations. Covered with the rest of the automation
  tooling in file 6.

## 8. What's next

File 3 picks up exactly where section 6 above left off: using PHP's own stream
wrapper system to read source code as base64 text instead of having it
executed, and then escalating several of those same wrappers into direct code
execution.
