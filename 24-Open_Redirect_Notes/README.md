# Open Redirect (CWE-601) — Note Series

Standalone reference series on Open Redirect vulnerabilities: detection methodology, blocklist-bypass techniques, real-world impact chains, and honest PortSwigger Web Security Academy lab mapping.

This topic was originally only mentioned as a chaining ingredient inside SSRF-focused notes. It gets full standalone treatment here because it is one of the most common standalone bug bounty findings and one of the most frequent chain ingredients in real assessments — phishing, OAuth/SSO token theft, SSRF filter bypass, and Referer-based trust bypass.

## File Index

| # | File | Covers |
|---|------|--------|
| 1 | `01-Open-Redirect-Overview-and-Classification.md` | What open redirect is, CWE-601, the 4-way issue-type classification (reflected / stored / DOM-based reflected / DOM-based stored), DOM sink list, detection methodology, parameter wordlist, real-world severity/triage framing |
| 2 | `02-Open-Redirect-Bypass-Techniques.md` | Blocklist bypass techniques broken down piece-by-piece: protocol-relative URLs, malformed/double slash sequences, `@` userinfo trick, backslash conversion, whitespace/control-character/null-byte tricks, and a combined real-audit-style payload |
| 3 | `03-OAuth-Redirect-URI-Exploitation.md` | OAuth `redirect_uri` validation bypass, authorization-code and implicit-grant token theft chained through open redirect, full payload breakdowns, defensive guidance |
| 4 | `04-Open-Redirect-Cheatsheet-and-Lab-Mapping.md` | Quick payload reference table, detection checklist, full consolidated PortSwigger lab mapping in official Academy progression order, honest coverage-gap notes |

## Recommended Reading Order

Read in numeric order. Each file assumes the terminology and classification established in the previous one — file 3 in particular assumes you've read the bypass mechanics in file 2.

## Prerequisites

- Basic HTTP request/response and 3xx redirect mechanics (`Location` header)
- Burp Suite (Community Edition is sufficient for every technique in this series)
- A PortSwigger Web Security Academy account for the mapped labs: https://portswigger.net/web-security

## Scope Note

This series focuses specifically on the **open redirect vulnerability class itself** and its two most-cited real-world chains (phishing credibility, OAuth `redirect_uri` token theft), plus a shorter look at Referer-based trust bypass. It does not re-cover SSRF or CSRF in depth — see the dedicated SSRF and CSRF note series for those topics. Where a PortSwigger lab exists for a technique, it is mapped honestly; where one does not exist, that gap is stated explicitly rather than papered over.
