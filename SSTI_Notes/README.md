# Server-Side Template Injection (SSTI) — Complete Note Series

**OWASP Category:** A03:2021 — Injection
**Scope:** Detection → Engine Identification → Exploitation → Automation → Reference

This series follows the same depth and structure as the SQL Injection note series. It is built for
real-world penetration testing and bug bounty work, not just lab theory, and every payload is broken
down piece by piece so the *mechanism* is understood, not memorized.

## How This Series Is Organized

| File | Purpose |
|---|---|
| `01_SSTI_Overview_and_Detection.md` | What SSTI is, how it differs from XSS, plaintext vs code context, polyglot fuzzing, engine fingerprinting |
| `02_SSTI_Jinja2_Exploitation.md` | Jinja2 (Python/Flask) — syntax, sandbox internals, object-chain RCE, filter bypasses |
| `03_SSTI_Twig_Exploitation.md` | Twig (PHP/Symfony) — syntax, `_self` abuse, sandbox bypass, RCE |
| `04_SSTI_Other_Engines.md` | FreeMarker, Velocity, Smarty, Tornado, ERB, Handlebars |
| `05_SSTI_Detection_to_RCE_Escalation.md` | The full attack chain end-to-end, written as a single escalation narrative |
| `06_tplmap_Automation.md` | `tplmap` — the SSTI-equivalent of `sqlmap` — install, flags, output interpretation |
| `07_SSTI_Cheatsheet_and_Lab_Mapping.md` | Fast-lookup payload tables + full PortSwigger Academy lab progression |

## Recommended Reading Order

1. Read file `01` fully before touching any lab — detection logic is the foundation everything else builds on.
2. Read `02` (Jinja2) and `03` (Twig) in detail — these two engines cover the overwhelming majority of
   real-world SSTI findings (Flask/Django-adjacent stacks and PHP/Symfony stacks).
3. Skim `04` for engine recognition — you don't need to memorize every engine's RCE chain, but you need
   to recognize *which* engine you're looking at from its syntax and error messages.
4. Read `05` once you're comfortable with the building blocks — it ties detection, identification, and
   exploitation into one continuous methodology, the way you'd actually run an engagement.
5. Use `06` when you want to automate confirmation/exploitation, and understand what the tool is doing
   under the hood rather than trusting it blindly.
6. Use `07` as your live reference during labs, CTFs, or real engagements.

## Practice Mapping

This series maps every applicable technique to its corresponding lab on **PortSwigger Web Security
Academy**, in the exact order those labs appear in the Academy's own SSTI topic (not grouped by theme).
The full progression table lives in `07_SSTI_Cheatsheet_and_Lab_Mapping.md`.

## Conventions Used Throughout This Series

- Every payload is shown, then immediately broken down token-by-token underneath it.
- "Real-world note" call-outs appear in every file — these describe how the technique shows up in actual
  production stacks, CVEs, or bug bounty reports, not just academy labs.
- All content is written in full English. No Bangla or Banglish text appears anywhere in this series.
- Commands assume a Linux attack host (Kali-style) with Python 3 and pip available unless stated otherwise.

## Disclaimer

All techniques in this series are intended for authorized penetration testing, bug bounty programs with
explicit scope permission, and PortSwigger Academy / lab environments you are authorized to test. Do not
run any of this against systems you do not own or have written authorization to test.
