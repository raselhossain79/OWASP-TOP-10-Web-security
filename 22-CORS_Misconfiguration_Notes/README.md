# CORS (Cross-Origin Resource Sharing) Misconfiguration — Note Series

A standalone, GitHub-ready reference series on CORS misconfiguration vulnerabilities,
built to the same depth and structure as the SQL Injection reference series in this
repository. CORS was previously only mentioned briefly inside the CSRF notes as a
related bypass mechanism — this series gives it full, independent treatment because
its root cause, exploitation primitives, and PoC mechanics are distinct from CSRF.

## Why CORS Gets Its Own Series

CSRF and CORS are often confused because both involve a malicious page making a
cross-origin request to a victim application. The difference is what the attacker
gets back:

- **CSRF** — the attacker's page fires a request and relies on the browser
  auto-attaching cookies. The attacker cannot read the response. The attack is
  "blind": it works by causing a side effect (change password, transfer funds).
- **CORS misconfiguration** — the attacker's page fires a request, and because the
  server's CORS headers wrongly grant permission, the browser hands the **response
  body back to attacker JavaScript**. The attacker can read data, not just trigger
  actions. This is what makes CORS misconfiguration a direct data-disclosure
  vulnerability, not just an action-triggering one.

That distinction is the reason CORS deserves its own attack-pattern taxonomy,
its own PoC construction file, and its own lab progression.

## File Index

| File | Contents |
|---|---|
| `01-CORS-Overview-and-Classification.md` | Same-Origin Policy fundamentals, how CORS actually works at the HTTP level, preflight vs simple requests, full classification of every misconfiguration pattern |
| `02-CORS-Exploitation-Techniques.md` | Technique-by-technique exploitation: origin reflection, null origin trust, wildcard + credentials combinations, subdomain trust abuse, protocol-downgrade trust, internal network pivoting |
| `03-CORS-PoC-Building.md` | Constructing a working HTML/JS PoC from scratch, line-by-line breakdown of every PoC variant, exploit-server delivery mechanics |
| `04-CORS-Cheatsheet-and-Lab-Mapping.md` | Quick-reference header table, a CORS misconfiguration detection checklist, PortSwigger Academy lab mapping in official difficulty order, real-world bug bounty framing |

## How to Use This Series

Read in numeric order. `01` builds the mental model you need before any of the
exploitation content in `02` will make sense — CORS bugs are easy to misdiagnose
if you don't understand exactly which header the browser is checking and when.
`03` assumes you've already identified a misconfiguration using the detection
steps from `02`. `04` is the fast-recall file to keep open during an actual
test or bug bounty hunt.

## Lab Environment

All lab references point to PortSwigger Web Security Academy
(`portswigger.net/web-security/cors`), confirmed against the live Academy lab
listing. There are **4 labs** in this topic, and they are listed in `04` in their
official progression order (Apprentice → Practitioner). This is the same honest
mapping discipline used in every other series in this repository: if a technique
discussed in the notes has no corresponding Academy lab, that gap is explicitly
disclosed rather than papered over.

## Conventions Used Throughout This Series

- Every HTTP header shown is broken down field-by-field: what it tells the
  browser, who sets it (server vs browser), and why a specific misconfigured
  value makes the response readable to an attacker.
- Every PoC script is broken down line-by-line — no payload is shown without an
  explanation of what each statement does and why it's necessary.
- Real-world framing is included in every file: how this surfaces in actual APIs,
  SPAs, and microservice architectures, not just synthetic lab apps.
- Written entirely in English. No Bangla or Banglish anywhere in this series,
  per standing documentation convention.
