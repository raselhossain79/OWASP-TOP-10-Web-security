# XSS Notes — Cross-Site Scripting (OWASP A03:2021 - Injection)

A comprehensive, from-scratch reference series on Cross-Site Scripting, built with the same depth and structure as the SQLi_Notes series. Every payload and command is broken down mechanism-by-mechanism — what each part does and why it executes in its specific context — rather than given as a copy-paste line.

## File Index

| # | File | Covers |
|---|---|---|
| 01 | [Overview_Classification.md](./01_Overview_Classification.md) | XSS types (Reflected, Stored, DOM, Blind, mXSS), the five injection contexts (HTML, attribute, JS, URL, CSS), core methodology, real-world framing |
| 02 | [Reflected_XSS.md](./02_Reflected_XSS.md) | Mechanics, worked examples per context, delivery-vector nuance, PortSwigger lab mapping |
| 03 | [Stored_XSS.md](./03_Stored_XSS.md) | Persistence testing, second-order XSS, file-upload/metadata vectors, lab mapping |
| 04 | [DOM_Based_XSS.md](./04_DOM_Based_XSS.md) | Sources/sinks catalog, DOM clobbering, mutation XSS (mXSS), postMessage XSS, lab mapping |
| 05 | [Blind_XSS.md](./05_Blind_XSS.md) | Out-of-band detection theory, Burp Collaborator setup, self-hosted webhook/listener setup, payload shotgunning strategy |
| 06 | [CSP_Bypass.md](./06_CSP_Bypass.md) | Reading CSP headers, JSONP-host bypass, `unsafe-eval` + AngularJS sandbox escape, base-uri/dangling-markup gaps, nonce leakage |
| 07 | [Filter_WAF_Bypass_Encoding.md](./07_Filter_WAF_Bypass_Encoding.md) | Character-probing methodology, tag/attribute allowlist bypass, custom tags, double encoding, polyglots, WAF-specific evasion |
| 08 | [XSStrike_and_Dalfox.md](./08_XSStrike_and_Dalfox.md) | Full flag-by-flag usage of both tools, what each can/can't automate, manual-testing gaps |
| 09 | [Exploitation_Impact.md](./09_Exploitation_Impact.md) | Cookie theft, keylogging, phishing overlays, CSRF-token theft chains, CSS-based data exfiltration |
| 10 | [Cheatsheet_Lab_Mapping.md](./10_Cheatsheet_Lab_Mapping.md) | Compressed quick-reference + the complete, difficulty-ordered PortSwigger lab sequence in one place |

## How This Series Is Organized

- **Files 01-04** build the foundational classification and per-type mechanics (Reflected → Stored → DOM, in PortSwigger's own teaching order).
- **File 05** is a detection-methodology deep dive specific to the cases where you can't directly observe execution.
- **Files 06-07** separate two distinct, sequential obstacles: getting a payload *into* the page past filters/WAFs (07) versus getting an already-landed payload to actually *execute* past the browser's own CSP enforcement (06).
- **File 08** covers automation tooling honestly, including its real limits, so it's used to accelerate testing rather than replace manual analysis.
- **File 09** moves from "proving JS executes" to "proving real business impact" — the difference between a low-priority and a critical finding in most reports.
- **File 10** is the fast-lookup companion for active engagement use, plus the full PortSwigger lab list in correct sequence for structured practice.

## Conventions Used Throughout
- `alert(document.domain)` is used as the standard PoC payload (industry convention) rather than `alert(1)`, since it proves execution in the actual vulnerable origin.
- Every payload includes a piece-by-piece breakdown — no "just use this" lines.
- Every file ends with **Real-World Engagement Notes**, **Common Mistakes**, and **Report-Writing Notes** sections, consistent with the SQLi_Notes format.
- Written entirely in English, independent of any prior XSS note set.

## Suggested Study Path
Read files 01-04 in order first to build solid classification/mechanism foundations, then 05-07 (detection and bypass techniques), then 08 (tooling), then 09-10 (impact and quick reference). Pair this with the lab sequence in file 10 for hands-on PortSwigger practice in the correct difficulty order.
