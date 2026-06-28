# Web Fundamentals for Pentesting — README

This is the **prerequisite folder** — read this entire folder before starting any 
vulnerability-specific note series in this repo (SQLi, XSS, and everything after).

## File Index

| # | File | Covers |
|---|---|---|
| 00 | `00_Overview.md` | Why this folder exists and how to use it |
| 01 | `01_HTTP_HTTPS_Fundamentals.md` | HTTP methods, status codes, request/response anatomy, HTTPS/TLS basics |
| 02 | `02_HTTP_Headers_Complete_Reference.md` | Every header you'll see repeatedly across every vulnerability note series |
| 03 | `03_Cookies_and_Sessions.md` | Cookie attributes, session vs token-based auth |
| 04 | `04_Same_Origin_Policy_and_Web_Security_Model.md` | The core browser security concept underlying CORS, XSS, CSRF, clickjacking, CSWSH |
| 05 | `05_URL_Structure_and_Encoding.md` | URL anatomy and the encoding schemes used in nearly every bypass technique in this repo |
| 06 | `06_Web_Architecture_Basics.md` | Client-server model, DOM, sources/sinks, AJAX, REST |
| 07 | `07_Burp_Suite_Fundamentals.md` | Proxy, Repeater, Intruder, Decoder — the tool used across every note series |
| 08 | `08_Networking_Basics_for_Web_Pentest.md` | TCP/IP, ports, DNS — the web-specific networking layer |

## Reading Order

```
00 → 01 → 02 → 03 → 04 → 05 → 06 → 07 → 08
```

File `04` (Same-Origin Policy) is the single most important concept in this folder — 
if short on time, that file is non-negotiable; everything else here is more 
straightforward reference material.

## After This Folder

Move to `SQLi_Notes/` — see the main repo README for the full sequence and priority 
guidance across all topics.
