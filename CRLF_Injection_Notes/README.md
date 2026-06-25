# CRLF Injection / HTTP Header Injection — Note Series

Part of OWASP Top 10 (A03:2021 – Injection). This series follows the same depth and
structure as the SQL Injection, XSS, OS Command Injection, NoSQL Injection, SSTI,
XXE, and LDAP Injection series in this repository: full mechanism breakdowns,
real-world framing, PortSwigger Web Security Academy lab mapping, automation tool
reference, a dedicated filter/WAF bypass file, and a final cheatsheet.

## A note on lab mapping (read this first)

Unlike SQL injection or XSS, **PortSwigger does not run a standalone "CRLF
Injection" topic** with its own Apprentice → Practitioner → Expert lab ladder.
CRLF injection is a *mechanism*, not a topic on the Academy — it shows up inside
two real topics:

1. **Web cache poisoning** — header-injection-driven cache poisoning labs
   (these mostly use unkeyed headers like `X-Forwarded-Host`, not always raw
   `%0d%0a`, but the underlying cache-poisoning chain is the same one a CRLF
   payload is used to build in the wild).
2. **HTTP request smuggling → Advanced** — two labs are *explicitly* named
   and built around CRLF injection: `HTTP/2 request smuggling via CRLF
   injection` and `HTTP/2 request splitting via CRLF injection`. Both are
   Expert-tier.

Classic single-request **HTTP response splitting**, **session fixation via
injected `Set-Cookie`**, and **log injection** are real, well-documented,
industry-standard attack classes — but PortSwigger has no dedicated lab for
them (most modern frameworks now block raw CRLF in header-setting APIs, so
they don't lend themselves to a clean, reliably-vulnerable lab target). Those
files are built from real-world case studies, CVEs, and manual-testing
methodology instead of lab walkthroughs. This is called out honestly in each
file rather than inventing a lab that doesn't exist.

## File index

| File | Covers |
|---|---|
| `01_Overview_and_Classification.md` | What CRLF injection is, why `\r\n` breaks parsers, full taxonomy, root causes |
| `02_HTTP_Response_Splitting.md` | Classic response splitting, header injection, body injection, piece-by-piece payloads |
| `03_Header_Injection_Cache_Poisoning_Chains.md` | CRLF/header injection chained into cache poisoning — PortSwigger labs mapped in Academy order |
| `04_Session_Fixation_via_Header_Injection.md` | Injecting `Set-Cookie` via CRLF to fixate victim sessions |
| `05_Log_Injection.md` | Log forging, fake log entries, downstream log-processing injection |
| `06_WAF_Filter_Bypass.md` | Encoding variants, case manipulation, alternate line-ending tricks that evade signature detection |
| `07_Automation_crlfuzz.md` | crlfuzz — lightweight CRLF-detection fuzzer, when and how to use it |
| `08_Cheatsheet.md` | Condensed payload reference + full lab mapping table |

## How this series is built

- Full English only, no Bangla/Banglish, per documentation standard.
- Every payload is broken down piece by piece — what each byte/sequence does
  and why the parser breaks, never "just use this."
- Real-world notes in every file: what this actually looks like in bug
  bounty reports, pentest findings, and CVEs — not just lab theory.
- Practiced against PortSwigger Web Security Academy; labs referenced are
  mapped in their actual Academy difficulty order, with an explicit note
  where no lab exists for a technique.
