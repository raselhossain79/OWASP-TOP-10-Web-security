# Web Security Practice Roadmap

This file tells you **where to practice** each topic in the notes repo and **in what order** to follow.

## Rules

1. Read the notes folder first, then do the labs, then write a writeup using `00-Practice_Methodology_Notes/01_Writeup_Template.md`.
2. Finish each topic's labs before moving on. Do not skip Apprentice and Practitioner levels. Do Expert labs after finishing the whole phase.
3. After each topic, compare your lab list with the topic's `Cheatsheet_and_Lab_Mapping` file and tick off what you completed.
4. Stuck for more than 30-45 minutes: use the hint, then the solution, then redo the lab from scratch without help.
5. Keep a progress table (bottom of this file) updated.

## Platforms

| Short name | Platform | Best for |
|---|---|---|
| PS | PortSwigger Web Security Academy (free) | Most core topics, structured labs |
| DVWA | Damn Vulnerable Web Application (local) | SQLi, XSS, LFI/RFI, command injection, file upload, CSRF |
| bWAPP | bWAPP (local) | LDAP, XPath, HPP, many extra bug types |
| JS | OWASP Juice Shop (local) | Mixed OWASP Top 10, client side, JWT, NoSQL |
| WG | OWASP WebGoat (local) | Deserialization, XXE, JWT, SQLi lessons |
| THM | TryHackMe rooms | Guided rooms for LFI/RFI, LDAP, WordPress, subdomain takeover |
| HTB | HackTheBox Academy / machines | Deeper practice after the basics |
| PL | PentesterLab | CRLF, HPP, deserialization, real-world style exercises |
| Local | Your own setup | WordPress, TLS, DNS rebinding |

---

## Phase 0: Foundation (do first)

| Order | Repo folder | Where to practice |
|---|---|---|
| 0.1 | `00-Web_Fundamentals_Notes` | PS: Getting started and Burp Suite basics, set up Burp proxy and browser |
| 0.2 | `00-Practice_Methodology_Notes` | Read fully, set up your writeup folder |

Goal: comfortable with HTTP, cookies, Burp Proxy, Repeater, Intruder.

## Phase 1: Core injection and client-side (start here for labs)

| Order | Topic (repo folder) | Primary platform | Extra practice |
|---|---|---|---|
| 1 | 01 SQL Injection | PS: SQL injection (all labs), then sqlmap on a few | DVWA, JS, WG |
| 2 | 02 XSS | PS: Cross-site scripting (all labs) | DVWA, JS, XSS Game by Google |
| 3 | 11 CSRF | PS: CSRF | DVWA |
| 4 | 22 CORS | PS: CORS | JS |
| 5 | 23 Clickjacking | PS: Clickjacking | JS |
| 6 | 24 Open Redirect | PS: DOM-based vulnerabilities and OAuth labs (partial) | JS, PL |

## Phase 2: Server-side injection and file handling

| Order | Topic | Primary platform | Extra practice |
|---|---|---|---|
| 7 | 06 Command Injection | PS: OS command injection | DVWA, bWAPP, THM |
| 8 | 03 SSTI | PS: Server-side template injection | THM, HTB Academy |
| 9 | 04 XXE | PS: XXE injection | WG, THM |
| 10 | 14 SSRF | PS: SSRF | THM, local metadata practice |
| 11 | 20 LFI / RFI | PS: Path traversal (partial only) | DVWA, bWAPP, THM LFI rooms |
| 12 | 19 File Upload | PS: File upload vulnerabilities | DVWA, THM |
| 13 | 07 NoSQL Injection | PS: NoSQL injection | JS |
| 14 | 05 LDAP Injection | Not on PS | bWAPP, THM, local OpenLDAP lab |
| 15 | 08 XPath Injection | Not on PS | bWAPP, local XML lab |

## Phase 3: Authentication, access control, sessions

| Order | Topic | Primary platform | Extra practice |
|---|---|---|---|
| 16 | 12 Auth Failures | PS: Authentication | DVWA brute force, JS |
| 17 | 10 Broken Access Control | PS: Access control (IDOR) | JS, WG |
| 18 | 13 Cryptographic Failures (JWT part) | PS: JWT | JS, WG |
| 19 | 24 OAuth part | PS: OAuth authentication | THM |
| 20 | 27 Mass Assignment | PS: API testing (partial) | JS, crAPI |
| 21 | 15 Host Header Injection | PS: HTTP Host header attacks | PL |

## Phase 4: Advanced web

| Order | Topic | Primary platform | Extra practice |
|---|---|---|---|
| 22 | 16 HTTP Request Smuggling | PS: Request smuggling | PL |
| 23 | 17 Web Cache Poisoning and Deception | PS: Web cache poisoning, Web cache deception | none needed at first |
| 24 | 21 Insecure Deserialization | PS: Insecure deserialization | WG, PL |
| 25 | 26 Race Conditions | PS: Race conditions | PL |
| 26 | 25 Client-side JS (Prototype Pollution, DOM Clobbering, WebSocket, postMessage) | PS: Prototype pollution, DOM clobbering, WebSockets | JS |
| 27 | 28 Insecure Design | PS: Business logic vulnerabilities | JS |
| 28 | 18 HTTP Parameter Pollution | PS: API testing (server-side parameter pollution) | bWAPP, PL |
| 29 | 09 CRLF Injection | No dedicated PS lab | PL, local test apps |

## Phase 5: Misconfiguration, recon, infrastructure (mostly outside PortSwigger)

| Order | Topic | Where to practice |
|---|---|---|
| 30 | 29 Security Misconfiguration | PS: Information disclosure labs (partial), JS, local Nikto scans |
| 31 | 30 Vulnerable Components | THM, local vulnerable app versions with Retire.js / Dependency-Check |
| 32 | 31 Integrity Failures | WG, own CI/CD test repo on GitHub |
| 33 | 32 Logging and Monitoring Failures | Local app log review, THM |
| 34 | 33 Subdomain Takeover and Recon | can-i-take-over-xyz, THM, own test domain, bug bounty recon on in-scope programs only |
| 35 | 35 WordPress Pentest | Local WordPress install + WPScan, THM WordPress rooms |
| 36 | 36 TLS Security Assessment | testssl.sh against badssl.com and your own server |
| 37 | 37 DNS Rebinding | Local lab only, follow the notes |

## Phase 6: Chaining and real-world

| Order | Topic | Where to practice |
|---|---|---|
| 38 | 34 Real World Chaining | PS Expert labs, HTB machines, THM web rooms, mock reports |

Finish by doing PortSwigger **Expert** labs for every topic you completed, then write one full chained report.

---

## Legal reminder

Only test systems you own, local labs, or targets explicitly in scope of an authorized program or engagement.

## Progress tracker

| Topic | Notes read | Labs done | Writeups done | sqlmap/tool practice | Date finished |
|---|---|---|---|---|---|
| 01 SQLi | [ ] | [ ] | [ ] | [ ] | |
| 02 XSS | [ ] | [ ] | [ ] | [ ] | |
| 11 CSRF | [ ] | [ ] | [ ] | [ ] | |
| 22 CORS | [ ] | [ ] | [ ] | [ ] | |
| 23 Clickjacking | [ ] | [ ] | [ ] | [ ] | |
| 24 Open Redirect | [ ] | [ ] | [ ] | [ ] | |
| 06 Command Injection | [ ] | [ ] | [ ] | [ ] | |
| 03 SSTI | [ ] | [ ] | [ ] | [ ] | |
| 04 XXE | [ ] | [ ] | [ ] | [ ] | |
| 14 SSRF | [ ] | [ ] | [ ] | [ ] | |
| 20 LFI/RFI | [ ] | [ ] | [ ] | [ ] | |
| 19 File Upload | [ ] | [ ] | [ ] | [ ] | |
| 07 NoSQL | [ ] | [ ] | [ ] | [ ] | |
| 05 LDAP | [ ] | [ ] | [ ] | [ ] | |
| 08 XPath | [ ] | [ ] | [ ] | [ ] | |
| 12 Auth Failures | [ ] | [ ] | [ ] | [ ] | |
| 10 Access Control | [ ] | [ ] | [ ] | [ ] | |
| 13 Crypto / JWT | [ ] | [ ] | [ ] | [ ] | |
| 27 Mass Assignment | [ ] | [ ] | [ ] | [ ] | |
| 15 Host Header | [ ] | [ ] | [ ] | [ ] | |
| 16 Request Smuggling | [ ] | [ ] | [ ] | [ ] | |
| 17 Cache Poisoning | [ ] | [ ] | [ ] | [ ] | |
| 21 Deserialization | [ ] | [ ] | [ ] | [ ] | |
| 26 Race Conditions | [ ] | [ ] | [ ] | [ ] | |
| 25 Client-side JS | [ ] | [ ] | [ ] | [ ] | |
| 28 Insecure Design | [ ] | [ ] | [ ] | [ ] | |
| 18 HPP | [ ] | [ ] | [ ] | [ ] | |
| 09 CRLF | [ ] | [ ] | [ ] | [ ] | |
| 29-37 Misconfig, recon, infra | [ ] | [ ] | [ ] | [ ] | |
| 34 Chaining | [ ] | [ ] | [ ] | [ ] | |
