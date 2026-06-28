# XPath Injection — Complete Reference Series

Part of OWASP Top 10 2021 — **A03:2021 Injection**.

This series documents XPath Injection at the same depth as the SQL Injection series: every
payload is broken down piece by piece (axis, function, operator, predicate), every technique is
framed against real-world industry usage, and every PortSwigger Web Security Academy mapping is
verified rather than assumed.

## Files in this series

| # | File | Covers |
|---|------|--------|
| 1 | [01-Overview-and-Classification.md](01-Overview-and-Classification.md) | What XPath injection is, the XML/XPath data model, XPath vs SQL injection, where it shows up in production systems, OWASP A03 mapping |
| 2 | [02-Exploitation-Techniques.md](02-Exploitation-Techniques.md) | Authentication bypass, blind boolean-based extraction, data extraction via node-set manipulation — every payload explained mechanism-first |
| 3 | [03-Automation-xcat.md](03-Automation-xcat.md) | `xcat` — the real-world automation tool for blind XPath injection, flag by flag |
| 4 | [04-Filter-WAF-Bypass.md](04-Filter-WAF-Bypass.md) | Filter evasion, encoding tricks, WAF bypass for XPath injection |
| 5 | [05-Cheatsheet-and-Lab-Mapping.md](05-Cheatsheet-and-Lab-Mapping.md) | Quick-reference cheatsheet + **honest** PortSwigger Web Security Academy lab mapping |

## Honesty note on lab coverage

PortSwigger Web Security Academy does **not** currently provide dedicated server-side
XPath injection labs (no equivalent to its SQLi "login bypass" or "blind SQLi" labs). It only
covers **client-side, DOM-based** XPath injection (two labs: reflected and stored), which is a
different vulnerability mechanism — a JavaScript sink (`document.evaluate()` /
`element.evaluate()`) rather than a server-side query built from request data. This is disclosed
in detail in file 5 rather than glossed over. Where Academy coverage is thin, this series leans
more heavily on CTF-style practice targets (the NetSPI `XPath-Injection-Lab` Docker app referenced
in file 5) to keep the hands-on component honest.

## How this series was built

- Every payload is broken into its components — axis, node test, predicate, function, operator —
  with an explanation of *why* it works, not just *that* it works.
- Real-world framing is included in every file: how this vulnerability class actually appears in
  production (SOAP services, LDAP/XML hybrid auth stores, legacy XML-backed CMS systems, SAML/XML
  config parsers, mobile app backends using XML data stores).
- Full English only, no Bangla/Banglish, matching the rest of the note repository.
