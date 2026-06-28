# Local & Remote File Inclusion (LFI / RFI) — Complete Reference Series

A from-scratch, mechanism-first reference series on File Inclusion vulnerabilities,
written to match the depth and structure of the SQL Injection note series in this
repository. Every payload is broken down piece by piece — nothing is presented as
"just run this."

## Why this series exists

Path traversal and File Inclusion are frequently lumped together, but they are not
the same bug class. Path traversal lets an attacker **read** a file outside the
intended directory. File Inclusion happens when the application doesn't just read
a file — it **passes that file to an interpreter** (`include()`, `require()`, a
templating engine, etc.). That second step is what turns "I can read your config"
into "I can run code on your server." This series treats File Inclusion as its own
vulnerability class, building from basic file disclosure up through several
different roads to Remote Code Execution (RCE).

## File index

| # | File | Covers |
|---|------|--------|
| 1 | [`01-overview-and-classification.md`](./01-overview-and-classification.md) | What file inclusion actually is, how it differs from path traversal, the PHP functions and `php.ini` directives that create the risk, where this shows up in real applications |
| 2 | [`02-basic-lfi-and-bypass-techniques.md`](./02-basic-lfi-and-bypass-techniques.md) | Basic LFI for sensitive file disclosure, filter/extension bypasses, null byte injection, path truncation (legacy but still tested) |
| 3 | [`03-php-wrapper-exploitation.md`](./03-php-wrapper-exploitation.md) | `php://filter` (base64 source disclosure and the filter-chain RCE technique), `php://input`, `data://`, `expect://`, wrapper requirement matrix |
| 4 | [`04-log-and-session-poisoning-rce.md`](./04-log-and-session-poisoning-rce.md) | Turning a "read-only" LFI into RCE by poisoning a file the server already writes to: access logs, PHP session files, `/proc/self/environ` |
| 5 | [`05-rfi-techniques.md`](./05-rfi-techniques.md) | Classic Remote File Inclusion, `allow_url_include`/`allow_url_fopen` mechanics, the SMB/UNC path trick on Windows hosts, why RFI is rare in 2026 |
| 6 | [`06-cheatsheet-and-lab-mapping.md`](./06-cheatsheet-and-lab-mapping.md) | Consolidated payload cheatsheet, sensitive-file target list, **honest** PortSwigger Academy lab mapping, automation tooling |

## How to use this series

Read in numeric order. Each file assumes the mechanism explained in the previous
one. File 6 is your quick-reference once you've gone through 1–5 at least once.

## Scope notes

- The primary language of focus is **PHP**, because `include()`/`require()`
  semantics combined with PHP's stream wrapper system (`php://`, `data://`,
  `expect://`, `zip://`, `phar://`) make PHP applications the overwhelming
  majority of real-world LFI/RFI findings and CVEs. Where another language's
  inclusion/templating mechanism is relevant (Node `require()`, JSP includes,
  classic ASP `#include`), it is noted, but the deep technical breakdowns are
  PHP-specific because that is where the bug class actually lives in practice.
- This series assumes you already understand basic path traversal (`../`
  sequences, encoding bypasses, null-byte truncation as a path-traversal
  technique). If you need that foundation first, see this repository's
  path traversal notes — this series picks up where "I can read `/etc/passwd`"
  ends and "I can execute code through that read primitive" begins.
- **Important honesty note on lab practice:** PortSwigger Web Security Academy
  does **not** have a dedicated "File Inclusion" topic. Its closest topic is
  **Path Traversal**, and those labs only exercise the file-*read* primitive —
  none of them involve PHP wrappers, log/session poisoning, or RFI. File 6
  explains exactly what Academy labs map to what here, and what doesn't have
  Academy coverage at all, so you know where to go for hands-on practice on
  the techniques Academy doesn't offer.

## Conventions used throughout this series

- Every payload is broken into its literal pieces, with each piece explained:
  what it does, why it's there, and what would happen if you removed it.
- "Real-world notes" in every file connect the technique to how it actually
  shows up in bug bounty reports, CVEs, and pentest engagements — not just lab
  theory.
- Where a PortSwigger lab exists that's genuinely relevant, it's cited in the
  Academy's own difficulty/topic order, with an explicit note on what part of
  the technique it does and doesn't cover.
