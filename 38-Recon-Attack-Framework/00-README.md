# Recon-Attack-Framework

A practical, modular reference for authorized bug bounty hunting and penetration
testing. This is not a payload dump — it is a decision-making framework: at every
stage, the question answered is "what do I do next, and why."

> **Scope**: for use only on programs/targets where you have explicit written
> authorization (bug bounty program in-scope assets, a signed pentest engagement, or
> your own lab). Read `01-Scope-and-Authorization.md` before touching any target.

## How the Lifecycle Fits Together

```
Scope & Authorization
        ↓
Asset Discovery (subdomains, live hosts, ports, tech stack)
        ↓
Origin Infrastructure (origin IP, CDN/WAF identification)
        ↓
Attack Surface Mapping (endpoints, parameters, JS, APIs)
        ↓
Input & Auth Mapping (input surfaces, authN, authZ)
        ↓
Hypothesis-Driven Vulnerability Testing
        ↓
WAF / Filter Analysis (only when testing is blocked)
        ↓
Validation & Evidence Collection
        ↓
Professional Reporting
```

Each stage's output becomes the next stage's input. If you find yourself guessing
at a stage ("I'll just try some XSS payloads here"), that's a signal you skipped
the mapping stage that should have told you *where* and *why*.

## Module Map

| Folder / File | Purpose |
|---|---|
| `AUDIT-REPORT.md` | What was wrong in the original 4-file version and how it was corrected |
| `01-Scope-and-Authorization.md` | Confirm you're allowed to test, and how far, before you test |
| `02-Asset-Discovery/subdomain-enumeration.md` | Find all domains/subdomains in scope |
| `02-Asset-Discovery/live-host-discovery.md` | Confirm which assets are actually live |
| `02-Asset-Discovery/port-service-enumeration.md` | Find open ports/services per host |
| `02-Asset-Discovery/technology-fingerprinting.md` | Identify frameworks, CMS, languages in use |
| `03-Origin-Infrastructure/origin-ip-discovery.md` | Find the real server behind a CDN/WAF, correctly scoped |
| `03-Origin-Infrastructure/cdn-waf-identification.md` | Distinguish CDN vs WAF vs reverse proxy vs app filtering |
| `04-Attack-Surface-Mapping/endpoint-discovery.md` | Map all reachable endpoints |
| `04-Attack-Surface-Mapping/parameter-discovery.md` | Find hidden/undocumented parameters |
| `04-Attack-Surface-Mapping/javascript-analysis.md` | Extract endpoints/logic/secrets from JS bundles |
| `04-Attack-Surface-Mapping/api-discovery.md` | Map REST/GraphQL/other API surface |
| `05-Input-and-Authentication/input-surface-analysis.md` | Catalog every input per endpoint |
| `05-Input-and-Authentication/authentication-mapping.md` | Map login/session/token mechanisms |
| `05-Input-and-Authentication/authorization-mapping.md` | Map roles/permissions for IDOR/BAC testing |
| `06-Vulnerability-Testing/testing-methodology.md` | The generic test loop (class-agnostic) |
| `06-Vulnerability-Testing/sqli.md` | SQLi specifics |
| `06-Vulnerability-Testing/xss.md` | XSS specifics |
| `06-Vulnerability-Testing/ssrf.md` | SSRF specifics |
| `06-Vulnerability-Testing/idor.md` | IDOR specifics |
| `06-Vulnerability-Testing/business-logic.md` | Business logic flaw testing |
| `06-Vulnerability-Testing/authentication.md` | Username enumeration, rate limiting, reset-token strength, session fixation |
| `06-Vulnerability-Testing/broken-access-control.md` | Forced browsing, verb tampering, client-trusted role fields (BFLA) |
| `06-Vulnerability-Testing/file-upload.md` | Extension/content-type bypass, stored-XSS-via-upload |
| `06-Vulnerability-Testing/path-traversal-lfi.md` | Directory traversal, encoded bypasses, LFI |
| `06-Vulnerability-Testing/csrf.md` | State-changing request forgery, SameSite/token checks |
| `06-Vulnerability-Testing/ssti.md` | Server-side template injection, engine-specific probes |
| `06-Vulnerability-Testing/xxe.md` | XML external entity injection, in-band and OOB |
| `06-Vulnerability-Testing/cors.md` | Origin-reflection + credentials misconfiguration |
| `06-Vulnerability-Testing/open-redirect.md` | Redirect-target manipulation and bypass patterns |
| `07-WAF-and-Filter-Analysis/waf-detection.md` | Fingerprinting WAF/filtering layers |
| `07-WAF-and-Filter-Analysis/request-parsing.md` | The actual mechanism behind evasion techniques |
| `07-WAF-and-Filter-Analysis/authorized-bypass-testing.md` | Bypass techniques, with policy/stop-condition framing |
| `08-Validation-and-Evidence/validation-and-evidence.md` | Eliminating false positives, building proof |
| `09-Reporting/professional-reporting.md` | Writing a report that gets acted on |
| `10-Tools-and-Cheatsheets/` | Quick-reference tables for all tools/commands used above |
| `11-Testing-Management/Testing-Matrix.md` | Reusable tracking template for systematic test coverage |
| `12-Workflow-Examples/hypothesis-driven-testing.md` | How to choose which vuln class to test per endpoint — 5 worked examples |

## Content Standard Used Per File

Each technique file follows this structure, skipping sections that genuinely don't
apply to that technique:

1. Purpose 2. When to use 3. Prerequisites 4. Methodology 5. Commands
6. Command breakdown 7. Expected output 8. Interpretation 9. False positives
10. Next action 11. Safety considerations 12. Documentation

## Ground Rules Carried Through Every File

- **A blocked request proves nothing** about whether a vulnerability exists behind
  the block, and an unblocked request proves nothing about whether one doesn't.
- **An HTTP status code alone is never treated as proof** — it's a signal to
  investigate, not a finding.
- **Confirmed vs candidate** is maintained throughout — e.g. a "candidate origin
  IP" is not "the origin" until independently verified.
- **Finding something ≠ permission to exploit it further** — program scope and rate
  limits govern what you do with every finding, at every stage.
- Where a command's behavior depends on tool version or target environment, that is
  stated explicitly rather than assumed.

## Not Yet Built — Advanced / Less Frequently Encountered Classes

Per the framework's own priority principle (common, practical classes first),
these remain pending for a future batch: **Race Conditions, JWT-specific
attacks, HTTP Request Smuggling, WebSocket security, and the API-specific
cluster (Mass Assignment, Excessive Data Exposure, API-specific Rate Limiting —
BOLA/BFLA are already covered within `idor.md` and `broken-access-control.md`
respectively)**. These are real, valid classes but are encountered less
frequently in typical web/API bug bounty work than the classes already built,
and several (request smuggling especially) require infrastructure-level nuance
(connection reuse behavior, HTTP/1.1 vs HTTP/2 differences) that deserves its
own careful treatment rather than a rushed addition.

## Remaining Limitations and Unverified Items

Stated plainly, as the framework itself asks you to do with your own findings:

- **Tool syntax/flags may drift from what's shown here** over time as tools
  (`subfinder`, `httpx`, `ffuf`, `arjun`, `sqlmap`, `wafw00f`, `katana`,
  `trufflehog`) release new versions. Always check `--help` or official docs for the
  installed version before relying on a flag described in this framework.
- **WAF/filter behavior described in `07-WAF-and-Filter-Analysis/` is inherently
  target-specific.** No bypass technique is claimed to work universally — several
  modern WAF products are explicitly noted as likely to resist classic
  signature-evasion approaches.
- **Cloud metadata endpoint details in `ssrf.md`** (`169.254.169.254`) reflect
  common historical AWS behavior; actual reachability depends on the specific
  provider, configuration, and any metadata-service protections (e.g. IMDSv2-style
  token requirements) in place on the target's infrastructure — verify rather than
  assume.
- **This framework does not replace a program's own rules of engagement.** Every
  module defers to `01-Scope-and-Authorization.md` and, through it, to whatever the
  specific program/engagement states — where the two conflict, the program's own
  rules always win.
- **The MSSQL OOB SQLi syntax in `sqli.md`** (`xp_dirtree` UNC-path technique) is
  marked explicitly as unverified by direct testing in this framework — confirm
  current syntax and stored-procedure availability against Microsoft's own
  documentation before relying on it.
- **Engine-specific SSTI escalation beyond the arithmetic-evaluation proof**
  (e.g. achieving full code execution from a confirmed Jinja2/Twig/FreeMarker/
  Velocity evaluation) is version- and configuration-dependent and is
  deliberately not given a single "universal" payload in `ssti.md` — research
  the specific engine's current state against official references.
- **CORS header-combination behavior** described in `cors.md` reflects the CORS
  specification as browsers are expected to enforce it; always confirm actual
  behavior in a real browser PoC rather than trusting header presence alone, as
  noted in that file.
