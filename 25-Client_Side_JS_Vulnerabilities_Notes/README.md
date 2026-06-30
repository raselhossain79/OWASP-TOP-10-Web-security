# Client-Side JavaScript Vulnerabilities — Note Series

A GitHub-ready reference series covering five modern, related-but-distinct browser-side
vulnerability classes that don't fit cleanly inside the standard XSS category. Built with
the same depth and structure as the SQL Injection series: mechanism-first explanations,
piece-by-piece payload breakdowns, official PortSwigger Web Security Academy lab mapping
in difficulty-progression order, and real-world industry framing throughout.

## Scope

This series treats "Client-Side JavaScript Vulnerabilities" as a cluster, not a single
bug class. Each sub-topic has its own root cause, its own detection method, and its own
exploitation path — but all five share a common theme: the browser's JavaScript runtime
trusts data or structure it should not trust.

## File Index

| File | Topic | Focus |
|---|---|---|
| `00-Overview-and-Index.md` | Series overview | How the five topics relate, shared mental model, how to use this series |
| `01-Prototype-Pollution.md` | Prototype Pollution | Client-side + Node.js server-side, sources/sinks/gadgets, up to RCE |
| `02-DOM-Clobbering.md` | DOM Clobbering | HTML-only attacks against JS via `id`/`name`, CSP-bypass relevance |
| `03-PostMessage-Vulnerabilities.md` | Cross-Origin `postMessage` | Missing origin validation, web-message DOM XSS |
| `04-Client-Side-Storage-Issues.md` | Client-Side Storage | Sensitive data exposure, storage-based XSS sinks |
| `05-Cross-Site-WebSocket-Hijacking.md` | CSWSH | Missing origin validation on the WebSocket handshake |
| `06-Cheatsheet-and-Lab-Mapping.md` | Combined reference | Quick-reference payloads, full PortSwigger lab map, tooling |

## Conventions Used Throughout

- **English only.** No Bangla/Banglish in any file, per series-wide documentation standard.
- **Mechanism before payload.** Every payload is broken down piece by piece — what each
  token does, why the browser/engine behaves that way, and why that behavior is dangerous.
- **Lab mapping in Academy order.** Labs are listed in PortSwigger's own difficulty
  progression (Apprentice → Practitioner → Expert) where applicable.
- **Honest gap disclosure.** Where the Academy has no dedicated lab for a sub-technique,
  this is stated explicitly rather than implied or glossed over.
- **Real-world framing.** Each file includes a "Real-World Notes" section connecting the
  lab-scale vulnerability to actual disclosed bugs, bug bounty patterns, or industry
  defenses (CSP, framework hardening, etc.).

## Suggested Reading Order

1. `00-Overview-and-Index.md` — orientation
2. `01-Prototype-Pollution.md` and `02-DOM-Clobbering.md` — both are "control flow via
   object/DOM manipulation" and build on each other conceptually
3. `03-PostMessage-Vulnerabilities.md` and `04-Client-Side-Storage-Issues.md` — both are
   "trusting the wrong data source" issues
4. `05-Cross-Site-WebSocket-Hijacking.md` — origin-trust failure on a different transport
5. `06-Cheatsheet-and-Lab-Mapping.md` — keep open during active lab/engagement work

## Author Context

Maintained as part of an ongoing web application security reference library, alongside
completed series on SQL Injection, XSS, SSRF, CSRF, Web Cache Poisoning, HTTP Request
Smuggling, and the OWASP Top 10 categories.
