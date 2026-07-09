# XML External Entity (XXE) Injection — Complete Note Series

A structured, GitHub-ready reference series on XML External Entity Injection, built for
real-world penetration testing engagements and mapped to PortSwigger Web Security
Academy labs in the correct difficulty progression order (Apprentice → Practitioner →
Expert).

XXE is classified under **OWASP Top 10 2021 — A05:2021 Security Misconfiguration**
(it is a consequence of an XML parser being misconfigured to resolve external entities
and DTDs by default), but it is treated here as its own vulnerability class because its
exploitation mechanics, attack surface, and tooling are distinct enough to warrant
dedicated, deep coverage — the same way SQL Injection and XSS were treated in their own
series in this repository.

## How This Series Is Organized

Every payload shown in every file is broken down piece by piece: what the `DOCTYPE`
declares, what the entity definition does, what the `SYSTEM`/`PUBLIC` keyword means,
and how the parser actually processes each token. Nothing is presented as "just copy
this" — the goal is to understand the XML parser's behavior well enough to adapt
payloads to any real engagement, not just to solve a lab.

| File | Title | What It Covers |
|---|---|---|
| 1 | [01_XXE_Overview_and_Classification.md](01_XXE_Overview_and_Classification.md) | XML/DTD/entity fundamentals, why XXE happens, the four attack classes, OWASP A05:2021 mapping |
| 2 | [02_Classic_InBand_XXE.md](02_Classic_InBand_XXE.md) | Classic file-read XXE, parameter entities, XInclude, file upload (SVG) and content-type attack surface |
| 3 | [03_Blind_OOB_and_Error_Based_XXE.md](03_Blind_OOB_and_Error_Based_XXE.md) | Blind XXE detection, out-of-band exfiltration via DNS/HTTP, error-based exfiltration, repurposing local DTDs |
| 4 | [04_XXE_to_SSRF_Chaining.md](04_XXE_to_SSRF_Chaining.md) | Using XXE as an SSRF primitive, cloud metadata abuse, internal network reach |
| 5 | [05_XXE_WAF_Filter_Bypass.md](05_XXE_WAF_Filter_Bypass.md) | WAF/signature-filter evasion: character reference encoding, UTF-7, parameter entity splitting, whitespace tricks, OOB-DTD intent hiding |
| 6 | [06_XXEinjector_Automation_Tool.md](06_XXEinjector_Automation_Tool.md) | XXEinjector — full flag reference, automation workflow, what it can't replace |
| 7 | [07_Cheatsheet_and_Lab_Mapping.md](07_Cheatsheet_and_Lab_Mapping.md) | Quick-reference payload cheatsheet (including bypass payloads) + complete PortSwigger XXE lab mapping in Academy order |

## Recommended Reading Order

Read files 1 → 7 in sequence. Each file assumes the concepts from the previous one are
already understood. File 7 is meant to be kept open as a working reference during labs
or engagements.

## Prerequisites

- Basic familiarity with XML syntax (elements, attributes, well-formedness)
- Burp Suite (Community or Professional) for intercepting and modifying requests
- A Burp Collaborator client or equivalent OOB listener (e.g. `interactsh`) for blind XXE
- Access to PortSwigger Web Security Academy for lab practice

## Scope Note

This series focuses on web application XXE — XML parsed as part of HTTP request/response
handling. It does not cover XML signature wrapping attacks, SOAP-specific WS-Security
attacks, or XXE in desktop/offline document parsers, which are adjacent but separate
topics.
