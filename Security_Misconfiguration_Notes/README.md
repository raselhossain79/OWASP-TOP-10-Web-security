# Security Misconfiguration — OWASP Top 10 A05:2021

A complete, GitHub-ready reference series on **Security Misconfiguration**, built to the same
depth and structure as the SQL Injection series in this repository.

## Scope note

This series covers Security Misconfiguration **excluding XML External Entity (XXE) injection**.
XXE is a misconfiguration-adjacent vulnerability class (it depends on insecure XML parser
configuration) but it is large enough, and distinct enough in exploitation technique, that it
is documented as its own separate note series elsewhere in this repository. Anywhere XXE would
normally be mentioned as an example of misconfiguration, this series links out instead of
duplicating content.

## Why this category matters

OWASP A05:2021 – Security Misconfiguration moved up from #6 in the 2017 list to #5 in the 2021
list. It is one of the most commonly found issues in real-world penetration tests and bug bounty
programs because it covers an enormous attack surface: every server, framework, library, cloud
service, and application setting that ships with an insecure default or gets configured carelessly
under deadline pressure. Unlike injection vulnerabilities, misconfiguration bugs rarely require
exploit-development skill — they require **method, patience, and checklist discipline**. This is
exactly why a structured note series is valuable: most misconfiguration findings come from
systematically checking known categories, not from creative payload crafting.

## File index

| # | File | What it covers |
|---|------|-----------------|
| 1 | [`01_Overview_and_Classification.md`](01_Overview_and_Classification.md) | What A05:2021 is, the seven sub-categories this series covers, real-world breach case studies, and a classification taxonomy for triage during engagements |
| 2 | [`02_Default_Credentials_and_Unnecessary_Features.md`](02_Default_Credentials_and_Unnecessary_Features.md) | Default/vendor credentials, unnecessary enabled features, services, sample apps, and debug interfaces |
| 3 | [`03_Verbose_Errors_and_Debug_Exposure.md`](03_Verbose_Errors_and_Debug_Exposure.md) | Verbose error messages, stack traces, debug pages, framework version disclosure |
| 4 | [`04_Security_Headers_Misconfiguration.md`](04_Security_Headers_Misconfiguration.md) | Missing/weak security headers — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 5 | [`05_CORS_Misconfiguration.md`](05_CORS_Misconfiguration.md) | Cross-Origin Resource Sharing misconfiguration patterns and exploitation |
| 6 | [`06_Directory_Listing_Exposure.md`](06_Directory_Listing_Exposure.md) | Autoindex/directory listing misconfiguration and the sensitive data it leaks |
| 7 | [`07_Cloud_Storage_and_Infrastructure_Misconfiguration.md`](07_Cloud_Storage_and_Infrastructure_Misconfiguration.md) | S3/GCS/Azure Blob misconfiguration, IAM over-permissioning, includes a full **S3Scanner** section |
| 8 | [`08_Nikto_Scanning_Misconfiguration_Detection.md`](08_Nikto_Scanning_Misconfiguration_Detection.md) | **Nikto** — full flag-by-flag breakdown for general misconfiguration scanning |
| 9 | [`09_Cheatsheet_and_Lab_Mapping.md`](09_Cheatsheet_and_Lab_Mapping.md) | Final condensed cheatsheet + PortSwigger Web Security Academy lab mapping in correct difficulty/Academy order |

## How to use this series

- Read files in numeric order — each one builds on framing established in `01`.
- Every command or tool usage in this series is broken down **flag by flag** — what it does,
  why it is used, and what the output means. There are no "just run this" black-box commands.
- Every technique file includes a **Real-World Notes** section connecting the lab-style technique
  to how it actually shows up in production environments, bug bounty reports, and breach
  post-mortems.
- File 9 is the fast-reference version — use it during live engagements once you've internalized
  the detail in files 1–8.

## Related series in this repository

- `SQL_Injection/` — template this series follows
- `XSS/`
- `OS_Command_Injection/`
- `NoSQL_Injection/`
- `SSTI/`
- `XXE/` — covers XML External Entity injection separately from this series
- `LDAP_Injection/`
