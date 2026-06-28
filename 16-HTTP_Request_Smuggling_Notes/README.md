# HTTP Request Smuggling — Note Series

A complete, self-contained reference series on HTTP Request Smuggling (OWASP-adjacent
desync category, primarily associated with A05:2021 Security Misconfiguration and
A04:2021 Insecure Design in classification schemes that don't give it a dedicated
slot), built to the same structure and depth as this repository's SQL Injection
series.

## Why this category matters

HTTP request smuggling exploits a disagreement between a front-end proxy/load
balancer and a back-end application server over where one HTTP/1.1 request ends and
the next begins. It is one of the highest-severity, highest-payout categories in
modern bug bounty hunting precisely because the impact is structural: a single
successful exploitation can poison a shared cache for every visitor, or hijack an
arbitrary other authenticated user's session — not just the tester's own.

## File index

| File | Covers |
|---|---|
| [`01-concept-and-root-cause.md`](./01-concept-and-root-cause.md) | The front-end/back-end architecture that makes this possible; the `Content-Length` vs `Transfer-Encoding` ambiguity; CL.TE, TE.CL, and TE.TE (including obfuscated `Transfer-Encoding` header variants) explained line by line; why HTTP/2 end-to-end is immune and why HTTP/2-downgrade reintroduces the risk |
| [`02-detection-techniques.md`](./02-detection-techniques.md) | Timing-based detection for CL.TE and TE.CL; why probe order matters; escalating a timing hit into a proven, repeatable differential-response confirmation |
| [`03-exploitation-outcomes.md`](./03-exploitation-outcomes.md) | Request queue poisoning as the core primitive; bypassing front-end access controls; revealing front-end rewriting; forging trusted internal headers; capturing other users' requests; zero-interaction reflected XSS; open redirects; cache poisoning; cache deception |
| [`04-burp-http-request-smuggler-extension.md`](./04-burp-http-request-smuggler-extension.md) | Installing and using PortSwigger's **HTTP Request Smuggler** Burp extension (the closest tool-equivalent for this category) — Smuggle probe, Smuggle attack, Turbo Intruder integration, v3.0 parser discrepancy detection, and the standalone Smuggler.py alternative |
| [`05-cheatsheet-and-lab-mapping.md`](./05-cheatsheet-and-lab-mapping.md) | Quick payload skeletons, a detection decision tree, an exploitation-outcome quick index, full PortSwigger Web Security Academy lab mapping in Academy progression order, an honest list of advanced/expert-tier labs beyond this series' scope, and a defense/severity-framing checklist for writeups |

## How to use this series

1. Read `01-concept-and-root-cause.md` first. Every other file assumes you understand
   why two servers disagreeing on request length is the entire root cause — there is
   no shortcut around this for understanding the rest of the category.
2. Work through `02-detection-techniques.md` and `03-exploitation-outcomes.md` in
   order, ideally side by side with the matching PortSwigger Academy labs listed in
   `05-cheatsheet-and-lab-mapping.md`.
3. Use `04-burp-http-request-smuggler-extension.md` once you've done at least the
   first few labs by hand — understanding the manual mechanism first makes the
   automated tooling far more legible (you'll know what it's actually doing instead
   of just trusting a green checkmark).
4. Treat `05-cheatsheet-and-lab-mapping.md` as the living quick-reference once you've
   been through the full series once.

## Conventions used throughout this series

- Every raw HTTP request shown is broken down header-by-header / line-by-line —
  nothing is presented as "just send this."
- Every technique is mapped to its real PortSwigger Web Security Academy lab, in the
  exact order those labs appear in the Academy's difficulty progression.
- Real-world framing (how this shows up in actual production architectures and bug
  bounty reports) is included throughout, not just lab theory.
- Scope limitations are disclosed honestly rather than glossed over — see §5 of the
  cheatsheet file for what this series does *not* cover (HTTP/2 downgrade-specific
  vectors, response queue poisoning, request tunnelling, and the
  browser-powered/client-side desync family), flagged as natural follow-on topics
  rather than claimed coverage.
- Written entirely in English.
