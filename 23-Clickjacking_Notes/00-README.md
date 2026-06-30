# Clickjacking / UI Redressing — Vulnerability Note Series

A structured, GitHub-ready reference series on Clickjacking (UI Redressing), built for
hands-on penetration testing and bug bounty work. This series follows the same
mechanism-first, lab-mapped format as the rest of this notes repository (SQL Injection,
XSS, SSRF, etc.).

## Scope

This series covers:

- Classic clickjacking (invisible iframe overlay attacks)
- Clickjacking with prefilled form input via URL parameters
- Frame busting scripts and how attackers bypass them
- Clickjacking chained with DOM-based XSS
- Multistep clickjacking
- Double-clickjacking (the 2024 Yibelo technique that bypasses X-Frame-Options,
  CSP `frame-ancestors`, and SameSite cookies entirely — not iframe-based)
- Server-side defenses: X-Frame-Options and CSP `frame-ancestors`, including
  misconfiguration and bypass scenarios
- PortSwigger Web Security Academy lab mapping, in official difficulty-progression order

## File Index

| File | Contents |
|---|---|
| [`01-overview-and-classification.md`](./01-overview-and-classification.md) | What clickjacking is, how it differs from CSRF, full attack-variant classification, real-world industry impact |
| [`02-poc-building-techniques.md`](./02-poc-building-techniques.md) | Step-by-step, piece-by-piece construction of working clickjacking PoC pages — basic overlay, prefilled-form variant, multistep, double-clickjacking |
| [`03-bypass-scenarios-partial-protections.md`](./03-bypass-scenarios-partial-protections.md) | Frame buster bypass, weak/missing X-Frame-Options, weak/missing CSP `frame-ancestors`, SameSite cookie nuances, why double-clickjacking defeats all conventional defenses |
| [`04-cheatsheet-and-lab-mapping.md`](./04-cheatsheet-and-lab-mapping.md) | Quick-reference payload templates, header syntax cheatsheet, full PortSwigger Academy lab table in official order, manual testing checklist |

## How to Use This Series

Read in order if you're new to the topic: `01 → 02 → 03 → 04`. If you already understand
the basic overlay mechanism and just need lab payloads or header syntax, jump straight to
`04-cheatsheet-and-lab-mapping.md`.

All PortSwigger lab references use the official lab titles and difficulty tags
(APPRENTICE / PRACTITIONER) as published on the Web Security Academy, in the order they
appear in the official Clickjacking learning path.

## Conventions Used Throughout This Series

- Every PoC snippet is broken down property-by-property — nothing is presented as
  "copy this and it'll work" without an explanation of *why* it works.
- Lab mappings reflect the Academy's own difficulty progression, not an arbitrary
  ordering.
- Where no dedicated Academy lab exists for a technique (e.g. double-clickjacking, which
  is too new to have an Academy lab as of this writing), that gap is stated explicitly
  rather than glossed over.
- Real-world framing is included in every file — this is written for paid engagements
  and bug bounty reports, not just lab completion.
