# Cross-Site Request Forgery (CSRF) — Complete Reference Series

A standalone, GitHub-ready note series on Cross-Site Request Forgery: classification,
token-validation bypass techniques, SameSite/cookie-based bypass techniques, PoC
construction for bug bounty reports, and a final cheatsheet with full PortSwigger Web
Security Academy lab mapping.

## Why CSRF gets its own series

CSRF was removed as a standalone category in the OWASP Top 10 2021 list, largely
because modern frameworks (Django, Rails, Spring, ASP.NET Core) ship CSRF protection
by default and because browsers now apply `SameSite=Lax` cookies by default in Chrome
and other major browsers. It still falls conceptually under **A01:2021 — Broken Access
Control** when it appears, since a CSRF vulnerability is ultimately a failure to verify
that a request was *intentionally* issued by the authenticated user.

In practice, CSRF has not gone away:

- Legacy applications and internal/enterprise tools frequently lack any CSRF defense.
- Custom-built APIs and SPAs often roll their own token logic, which is exactly where
  the flawed-validation patterns in this series show up.
- SameSite defaults only protect *cross-site* requests — they do nothing for
  same-site-but-cross-origin scenarios (sibling subdomains), and they can be bypassed
  with documented techniques covered in file 03.
- CSRF is still a frequently paid bug class on HackerOne and Bugcrowd, especially when
  chained with XSS or CORS misconfiguration to defeat the very defenses meant to stop it.

## File index

| File | Contents |
|---|---|
| [`01-CSRF-Overview-and-Classification.md`](./01-CSRF-Overview-and-Classification.md) | What CSRF is, the three preconditions, classic no-defense CSRF, GET-based CSRF, the CORS↔CSRF relationship, and the XSS→CSRF chaining pattern |
| [`02-Token-Validation-Bypass.md`](./02-Token-Validation-Bypass.md) | Token removal, method-dependent validation, tokens not tied to session, tokens tied to non-session cookies, double-submit cookie bypass, predictable/weak tokens |
| [`03-SameSite-Cookie-Bypass.md`](./03-SameSite-Cookie-Bypass.md) | SameSite `Strict`/`Lax`/`None` mechanics, Lax-via-GET bypass, on-site gadget bypass, sibling-domain bypass, Lax-with-newly-issued-cookie bypass |
| [`04-PoC-Building.md`](./04-PoC-Building.md) | Constructing auto-submitting HTML PoCs for POST/GET/JSON/multi-step flows, line-by-line breakdown of every PoC, exploit server delivery mechanics, report-writing checklist |
| [`05-Cheatsheet-and-Lab-Mapping.md`](./05-Cheatsheet-and-Lab-Mapping.md) | Quick-reference decision tree + full PortSwigger Academy CSRF lab list in exact progression order |

## How to use this series

1. Read file 01 first — it establishes the three preconditions for CSRF and the
   vocabulary (site vs. origin, same-site vs. cross-site) that every later file depends on.
2. Work through files 02 and 03 in order while solving the matching PortSwigger labs
   listed in file 05. Each technique file explains the mechanism *before* showing the
   payload, and breaks every payload down piece by piece — there are no "just use this"
   examples anywhere in this series.
3. Use file 04 when you actually find a CSRF bug in the field or in a bug bounty target
   and need to build a working, victim-deliverable exploit page for the report.
4. Use file 05 as the fast lookup table during an engagement or while grinding labs.

## Conventions used across this series

- Every HTTP request/response and every HTML PoC is broken down line by line or
  attribute by attribute — what it does, and *why* it defeats the specific defense
  being discussed.
- PortSwigger lab mappings are listed in the exact order they appear on the Web
  Security Academy under the CSRF topic (Bypassing CSRF token validation →
  Bypassing SameSite cookie restrictions → Bypassing Referer-based defenses), not
  grouped thematically. Where no PortSwigger lab exists for a technique (e.g. the
  XSS-steals-token chaining pattern), this is stated honestly rather than mapped to
  an unrelated lab.
- All files are written in full English. No Bangla or Banglish anywhere in the
  deliverables.
- This series assumes you already understand HTTP, cookies, and basic browser
  same-origin policy concepts. It does not re-explain those from zero.
