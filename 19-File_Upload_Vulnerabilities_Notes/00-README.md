# File Upload Vulnerabilities — Note Series

A complete, mechanism-first reference series on file upload vulnerabilities, built to the
same depth and structure as the SQL Injection series in this repository. Every technique
is broken down at the byte/header/parameter level — never presented as "just use this
payload."

## Why this category matters

File upload functionality is one of the most consistently profitable bug bounty
categories because the failure mode is binary and severe: get it wrong, and the result
is usually full remote code execution (RCE), not just data leakage. Profile picture
uploads, document management systems, CMS media libraries, support-ticket attachment
forms, and CI/CD artifact ingestion pipelines are all instances of the same underlying
problem — and they appear in almost every real-world web application.

## Scope note: where this sits in WSTG and OWASP Top 10

This is worth stating plainly because it is a common misconception (including one I
corrected while building this series): file upload testing is **not** filed under
OWASP WSTG's Input Validation Testing (INPV) chapter. It lives in the **Business Logic
Testing** chapter, specifically:

- **WSTG-BUSL-08** — Test Upload of Unexpected File Types
- **WSTG-BUSL-09** — Test Upload of Malicious Files

This makes sense once you think about it: validating a file's type and contents is
fundamentally a business-logic decision ("what kinds of files should this feature
accept?"), not a generic input-sanitization problem like SQL or command injection. The
exploitation techniques themselves, however, draw on input-validation-style thinking
(parsing discrepancies, blacklist gaps, encoding tricks), which is why the category gets
mentally filed under "input validation" so often.

There is also no single dedicated OWASP Top 10 (2021) category called "File Upload."
Depending on the specific failure, a file upload bug typically maps to one or more of:

- **A03:2021 – Injection** (if it leads to command/code execution via webshell)
- **A04:2021 – Insecure Design** (if there's no upload restriction strategy at all)
- **A05:2021 – Security Misconfiguration** (if the flaw is in server execution config,
  like `.htaccess` overrides)
- **A01:2021 – Broken Access Control** (if path traversal lets you write outside the
  intended directory)

## File index

| # | File | Covers |
|---|------|--------|
| 01 | `01-overview-and-classification.md` | What file upload vulns are, classification axes, impact tiers, real-world framing |
| 02 | `02-client-side-vs-server-side-validation-bypass.md` | Client-side vs server-side validation, why real apps mix both, bypass mechanics for each |
| 03 | `03-extension-and-mime-bypass-techniques.md` | Content-Type spoofing, path traversal in filename, extension blacklist bypass, obfuscated extensions, magic byte manipulation |
| 04 | `04-polyglot-file-construction.md` | Building files valid as two formats simultaneously (GIF+PHP, JPEG+EXIF) |
| 05 | `05-upload-to-rce-escalation-chains.md` | Full webshell chains, file overwrite attacks, race conditions, PUT-based uploads |
| 06 | `06-cheatsheet-and-lab-mapping.md` | Quick-reference cheatsheet + full PortSwigger Web Security Academy lab mapping in difficulty order |

## How to use this series

Read in order — each file builds on the previous one's mechanisms. File 03 assumes you
understand the multipart/form-data structure from File 02. File 04 (polyglots) assumes
you understand magic byte validation from File 03. File 05 assumes you understand both
extension bypass and content bypass, since real RCE chains combine them.

## Companion series

This series pairs with the SQL Injection series in this repository, and follows the same
conventions: PortSwigger Academy lab mappings in exact difficulty progression order,
honest disclosure where coverage gaps exist, real-world industry framing in every file,
and piece-by-piece mechanism breakdowns for every payload.
