# Broken Access Control — OWASP A01:2021 Note Series

A complete, GitHub-ready reference series on Broken Access Control vulnerabilities, built to the same depth and structure as the SQL Injection, XSS, OS Command Injection, NoSQL Injection, SSTI, XXE, and LDAP Injection series in this repository: every technique is broken down piece by piece, framed against real-world engagement/bug-bounty practice (not just lab theory), and mapped to PortSwigger Web Security Academy labs in their **correct, verified Apprentice → Practitioner progression order.**

## File Index

| File | Contents |
|---|---|
| [`01_Overview_and_Classification.md`](./01_Overview_and_Classification.md) | What access control is, how it differs from authentication/session management, the three control models (vertical/horizontal/context-dependent), root-cause taxonomy, and why this is the most common critical-severity finding in real engagements |
| [`02_IDOR_Techniques.md`](./02_IDOR_Techniques.md) | Insecure Direct Object References — sequential IDs, GUID-based IDOR, static file enumeration, redirect data leakage, blind/action IDOR, and a manual testing methodology |
| [`03_Privilege_Escalation_Horizontal_and_Vertical.md`](./03_Privilege_Escalation_Horizontal_and_Vertical.md) | Horizontal vs. vertical escalation, parameter/cookie role tampering, mass-assignment role changes, unprotected and obscured admin functionality, and horizontal-to-vertical chaining |
| [`04_Missing_Function_Level_Access_Control.md`](./04_Missing_Function_Level_Access_Control.md) | Platform-layer misconfiguration (`X-Original-URL`, HTTP method substitution), URL-matching discrepancies (case, suffix pattern, trailing slash), and client-side-only role gating |
| [`05_Path_Traversal_as_Access_Control.md`](./05_Path_Traversal_as_Access_Control.md) | Path traversal framed as a filesystem-level IDOR — all six Academy bypass variants broken down piece by piece, including the absolute-path, non-recursive-strip, double-decode, prefix-validation, and null-byte techniques |
| [`06_Forced_Browsing.md`](./06_Forced_Browsing.md) | Discovery methodology (robots.txt, sitemap.xml, JS bundle inspection, wordlist brute-forcing), multi-step process abuse, and Referer-based access control bypass |
| [`07_Autorize_and_AuthMatrix_Automation.md`](./07_Autorize_and_AuthMatrix_Automation.md) | The closest tool-equivalent for this category — setup, result interpretation, and limitations of the Autorize and AuthMatrix Burp extensions |
| [`08_Cheatsheet_and_Lab_Mapping.md`](./08_Cheatsheet_and_Lab_Mapping.md) | Consolidated technique cheatsheet, full PortSwigger Access Control lab table (13 labs, verified order), full Path Traversal lab table (6 labs, verified order), and a combined practice sequence |

## How This Series Is Built

- **Full English only** — no Bangla/Banglish anywhere in this series.
- **Every example is broken down mechanically** — what specifically is being changed in the request, and exactly why that change defeats the control in place. No "just try this" payloads.
- **Real-world framing throughout** — each technique file includes notes on how the issue actually shows up in production systems, bug bounty programs, and professional engagements, not only how it appears in a lab.
- **Lab mappings follow the Academy's own published order**, not a thematic regrouping — confirmed directly against the current Access Control and Path Traversal topic pages and cross-checked against multiple independent lab-order references before being finalized in this series.

## Practice Platform

All techniques in this series are designed for hands-on practice on [PortSwigger Web Security Academy](https://portswigger.net/web-security), using Burp Suite as the testing proxy.
