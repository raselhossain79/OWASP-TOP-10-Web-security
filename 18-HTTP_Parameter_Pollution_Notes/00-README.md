# HTTP Parameter Pollution (HPP) — Complete Reference Series

## Scope

This series gives HTTP Parameter Pollution full, standalone treatment. HPP was previously
only mentioned as a one-line WAF-bypass trick inside other note series (SSTI, XXE). This
series corrects that — covering HPP as a technique family with three meaningfully different
sub-classes, each with its own root cause, its own exploitation pattern, and its own real-world
impact.

## Why HPP gets its own series

HPP is not one vulnerability. It is a **parsing-inconsistency class**. Different layers of a
web stack — browser, CDN, WAF, web server, application framework, backend API — each have their
own opinion about what should happen when a parameter name appears more than once in a request.
Every technique in this series, from WAF bypass to business logic abuse to backend API injection,
is a different way of weaponizing the gap between two layers that disagree with each other.

## File index

| # | File | Covers |
|---|------|--------|
| 1 | `01-HPP-Overview-and-Classification.md` | What HPP is, the 3 sub-classes, full technology-by-technology duplicate-parameter parsing table, why the inconsistency exists architecturally |
| 2 | `02-HPP-WAF-and-Filter-Bypass.md` | Using duplicate parameters to desynchronize what the WAF inspects from what the app server executes |
| 3 | `03-HPP-Business-Logic-Manipulation.md` | Overriding price, quantity, role, and discount parameters via duplication; parameter-precedence abuse in real checkout/admin flows |
| 4 | `04-HPP-Server-Side-Parameter-Pollution-Downstream-APIs.md` | HPP/SSPP against internal/backend API calls — the only sub-class with dedicated PortSwigger Academy labs, mapped in official order |
| 5 | `05-HPP-Cheatsheet.md` | One-page condensed reference: parsing table, payload library, detection checklist, full lab map |

## Conventions used throughout this series

- **Mechanism first.** Every payload or request is broken down parameter-by-parameter:
  which parameter is duplicated, how each backend technology parses that duplication
  differently, and exactly why that difference creates the exploitable condition.
- **Real-world framing.** Each technique file explains where this shows up in production
  systems (load balancers, CDNs, WAF appliances, microservice meshes), not just lab theory.
- **Honest PortSwigger Web Security Academy lab mapping.** Labs are listed in the exact
  difficulty/topic order they appear in on the Academy. Where Academy coverage doesn't exist
  for a technique, that gap is stated directly rather than papered over.
- **English only.** No Bangla/Banglish anywhere in this series, per your standing requirement.

## Suggested reading order

Read in file order (01 → 05). File 01 is required background for everything after it — the
parsing table it builds is referenced by name in every other file. Files 02–04 can technically
be read independently once you've read 01, but 04 (server-side parameter pollution) is the
section with real hands-on Academy labs, so prioritize that one for practice time.
