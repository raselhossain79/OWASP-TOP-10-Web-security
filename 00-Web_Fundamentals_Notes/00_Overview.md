# Web Fundamentals for Pentesting — Overview

> This is the prerequisite knowledge layer. Read this entire folder BEFORE starting 
> SQLi_Notes or any other vulnerability-specific folder. Every vulnerability note series 
> in this repo assumes you already understand everything in this folder — they won't 
> re-explain "what is a header" or "what is a cookie" again.

---

## Why This Folder Exists

Every vulnerability you'll study (SQLi, XSS, CSRF, SSRF, request smuggling — all of it) 
is ultimately a manipulation of HTTP at some level: a header, a parameter, a cookie, an 
encoding trick, a trust assumption between client and server. If you don't have the 
underlying protocol/browser model solid, you'll be memorizing payloads without 
understanding why they work — which is exactly the trap this entire repo is trying to 
avoid (see the main README's "command breakdown" rule).

This is not optional reading. Skipping this and jumping straight to SQLi will mean 
constantly hitting unexplained terms (Host header, Same-Origin Policy, Set-Cookie 
attributes, Content-Type) inside the vulnerability files, since those files assume this 
foundation is already in place.

---

## File Map

| File | Covers |
|---|---|
| `01_HTTP_HTTPS_Fundamentals.md` | HTTP methods, status codes, request/response anatomy, HTTPS/TLS basics |
| `02_HTTP_Headers_Complete_Reference.md` | Every header category you'll see repeatedly across vulnerability types |
| `03_Cookies_and_Sessions.md` | Cookie attributes, session vs token-based auth, why this matters for almost every vuln class |
| `04_Same_Origin_Policy_and_Web_Security_Model.md` | The single most important browser security concept — underlies CORS, XSS, CSRF, clickjacking, CSWSH |
| `05_URL_Structure_and_Encoding.md` | URL anatomy, encoding schemes (URL/Base64/Hex/Unicode) used in nearly every bypass technique in this repo |
| `06_Web_Architecture_Basics.md` | Client-server model, REST, DOM, how AJAX/fetch work — needed for XSS/DOM-based vulns specifically |
| `07_Burp_Suite_Fundamentals.md` | The core tool you'll use for every single note series in this repo — Proxy, Repeater, Intruder, Decoder |
| `08_Networking_Basics_for_Web_Pentest.md` | TCP/IP, DNS, ports — the minimum networking layer needed before touching web app testing |

---

## How To Use This Folder

Read in order: 01 → 02 → 03 → 04 → 05 → 06 → 07 → 08. Each file is intentionally short 
and reference-style — this isn't meant to be memorized in one sitting, it's meant to be 
skimmed once fully, then referenced back to whenever a vulnerability file mentions a 
term you're unsure about.

**Practical tip:** Install Burp Suite Community Edition and a Firefox/Chrome profile 
configured to proxy through it (file `07`) before reading 01-06 — then as you read about 
headers, cookies, and HTTP structure, actually browse a site through Burp and watch the 
raw requests/responses in real time. Reading about a Host header is fine; watching one 
in Burp Proxy's HTTP history while you visit five different sites makes it permanent.

---

## What This Folder Deliberately Does NOT Cover

- General networking/CCNA-level depth (subnetting, routing protocols) — only the 
  minimum relevant to web traffic
- Full HTML/CSS/JavaScript language tutorials — only enough JS/DOM concept to 
  understand client-side vulnerabilities later (file 06 covers exactly this much, no more)
- Linux fundamentals, Python/Bash scripting — assumed already covered in your earlier 
  foundational notes (Linux privesc, Bash/Python reference guides)

This folder is scoped tightly to "what do I need to understand HTTP and the browser 
security model well enough that every vulnerability note series in this repo makes 
sense the first time I read it."
