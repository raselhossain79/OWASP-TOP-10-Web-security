# 04 — CORS Cheatsheet and Lab Mapping

Fast-recall reference. Keep this file open during live testing.

## 1. Header Quick Reference

| Header | Direction | Meaning | Red Flag Value |
|---|---|---|---|
| `Origin` | Request (set by browser, not attacker-controllable in the request itself — but attacker chooses what context the request runs from) | The origin the request is coming from | N/A — this is the probe; you control it during testing |
| `Access-Control-Allow-Origin` | Response | Which origin(s) may read the response | Reflects request's `Origin` verbatim; or literal `null`; or matches an overly broad subdomain/protocol pattern |
| `Access-Control-Allow-Credentials` | Response | Whether the response may be read when the request was credentialed (cookies/auth attached) | `true`, present alongside any of the red-flag `Allow-Origin` values above |
| `Access-Control-Allow-Methods` | Response (preflight) | Which methods are permitted | Overly broad (`*` or all methods) when only `GET`/`POST` are actually needed |
| `Access-Control-Allow-Headers` | Response (preflight) | Which request headers are permitted | Overly broad, especially if it permits `Authorization` from any origin |
| `Vary: Origin` | Response | Tells caches the response varies by `Origin` | **Absence** when using reflection-based CORS — risk of cache poisoning across origins |

## 2. Detection Checklist (Run This on Every Session-Bound Endpoint)

1. [ ] Does the endpoint return session-bound or otherwise sensitive data
       (account info, tokens, internal data)?
2. [ ] Does a baseline request to it already include
       `Access-Control-Allow-Credentials: true`? If yes, it's CORS-aware —
       continue.
3. [ ] Resend with `Origin: https://<random-unrelated-domain>`. Is it
       reflected into `Access-Control-Allow-Origin`? → **Technique 1**
4. [ ] Resend with `Origin: null`. Is `null` reflected/allowed? →
       **Technique 2**
5. [ ] Is `Access-Control-Allow-Origin: *` present together with
       `Access-Control-Allow-Credentials: true` in any response (rare due to
       browser enforcement, but check library/framework configs directly,
       not just live responses)? → **Technique 3**
6. [ ] Resend with `Origin: https://<random-string>.<target-domain>`. Is an
       arbitrary, nonexistent subdomain accepted? → **Technique 4** —
       follow up by checking real subdomains for XSS or takeover potential.
7. [ ] Resend with `Origin: http://<known-trusted-subdomain>` (HTTP instead
       of HTTPS). Is it accepted? → **Technique 5**
8. [ ] (Whitebox / internal engagement context) Does the application or its
       CORS middleware trust private IP ranges or internal hostname patterns?
       → **Technique 6**

## 3. Severity Quick-Reference

| Scenario | Typical Severity |
|---|---|
| Reflection/null-origin/wildcard-equivalent on a session-bound endpoint, `Allow-Credentials: true` | Critical — direct account takeover / full data exposure |
| Subdomain or protocol trust, with a real chainable XSS or takeover available | Critical — same end-state as above, via a chain |
| Subdomain or protocol trust, with **no** currently chainable bug found | Medium — real exposure if circumstances change; report as a hardening/defense-in-depth issue and say so honestly |
| CORS misconfiguration on an endpoint returning only public, unauthenticated data | Low / informational — bad practice, low immediate impact |
| Internal network trust enabling pivot | Critical in internal/red-team context; usually out of scope (and not reproducible) in public bug bounty programs unless explicitly in scope |

Be precise and honest about severity in reports — a reflected-origin
misconfiguration on a public, non-sensitive endpoint is not a critical finding
just because "CORS misconfiguration" sounds alarming on its own. Triagers see
this overclaim constantly and it costs credibility on future reports.

## 4. PortSwigger Web Security Academy — Lab Mapping (Official Progression Order)

Verified against the live Academy CORS topic listing. There are 4 labs total in
this topic, ordered Apprentice → Practitioner exactly as the Academy presents
them.

| Order | Lab Name | Difficulty | Maps to Technique |
|---|---|---|---|
| 1 | **CORS vulnerability with basic origin reflection** | Apprentice | Technique 1 — Reflected-Origin Misconfiguration |
| 2 | **CORS vulnerability with trusted null origin** | Apprentice | Technique 2 — Null Origin Bypass |
| 3 | **CORS vulnerability with trusted insecure protocols** | Apprentice | Technique 5 — Trusted Insecure Protocols (this lab also demonstrates the subdomain-trust mechanics of Technique 4, since it trusts any subdomain over both HTTP and HTTPS) |
| 4 | **CORS vulnerability with internal network pivot attack** | Practitioner | Technique 6 — Internal Network Pivot |

### Honest Gap Disclosure

- **Technique 3 (wildcard + credentials misconfiguration via library default)**
  has no dedicated Academy lab. The Academy's lab set demonstrates the
  *outcome* of this pattern through lab 1 (reflection), since — as explained in
  `02` — real-world wildcard+credentials misconfigurations virtually always
  manifest as reflection under the hood. There is no lab that specifically
  frames the bug as "a CORS library's permissive default," because that's a
  whitebox/code-review observation more than a black-box-testable lab
  scenario. Treat lab 1's mechanics as fully transferable to this case.
- **Technique 4 in isolation (subdomain trust without the protocol-downgrade
  angle)** is folded into lab 3 rather than getting a standalone lab — the
  Academy's lab 3 demonstrates both the "any subdomain" trust and the
  "any protocol" trust in a single scenario, since they're implemented by the
  same underlying broken regex pattern in that lab's vulnerable application.
- All four labs award credit toward the Academy's API Security learning path
  completion; none currently require Burp Suite Professional-only features —
  all are solvable with Community Edition plus the Academy's exploit server,
  consistent with the existing tooling setup already in use.

## 5. Real-World / Bug Bounty Framing Summary

- Reflected-origin and null-origin misconfigurations are **the most commonly
  reported CORS findings** in public bug bounty programs — they require no
  chaining and are trivially confirmed with a single Repeater request.
- Programs increasingly **downgrade or close as informational** any CORS
  report that doesn't demonstrate impact against a genuinely sensitive,
  session-bound endpoint. Always target an authenticated, sensitive endpoint
  in your PoC, not a public one — this is the single biggest factor in
  whether a CORS report gets triaged as Critical or closed as Informational.
- Subdomain-trust chains (Technique 4/5) are higher-value precisely because
  they require correlating two separate weaknesses — programs tend to reward
  this kind of chained finding more highly, and it's worth explicitly framing
  the report as a chain ("CORS trust policy + XSS on trusted subdomain X
  together enable Y") rather than two disconnected low-severity reports.
- Internal network pivot findings are rarely in scope for public programs but
  are a standard, expected finding category in internal penetration tests and
  red team assessments — frame them in those engagement reports as a defense-
  in-depth and network segmentation issue, not purely an application bug.

## 6. Mitigation Reference (For Report Recommendations Sections)

| Misconfiguration | Correct Fix |
|---|---|
| Origin reflection | Maintain an explicit, exact-match allowlist of trusted origins; never derive `Access-Control-Allow-Origin` directly from the request's `Origin` header without comparing it against that allowlist first |
| Null origin trust | Remove `null` from any allowlist; if a legitimate internal use case requires it, isolate that use case to a separate endpoint that doesn't also serve session-bound data |
| Wildcard + credentials | Never combine credentialed responses with any all-origins-equivalent policy, including reflection; if credentials aren't actually needed for a given endpoint, omit `Access-Control-Allow-Credentials` entirely and a literal `*` becomes safe |
| Subdomain trust | Enumerate and allowlist specific, individually-vetted subdomains rather than pattern-matching "any subdomain"; treat each subdomain's security posture as independent |
| Insecure protocol trust | Enforce HTTPS-only matching in any origin validation logic; never accept `http://` for a trusted origin pattern |
| Internal network trust | Apply real authentication to internal tools regardless of network location; do not rely on IP range or internal hostname pattern as a substitute for authentication |

---

This concludes the CORS Misconfiguration note series. Cross-reference with the
CSRF series for the broader same-origin-policy context, since several real
findings during testing turn out to be CSRF rather than CORS (or vice versa) —
the detection checklist in section 2 above is the fastest way to confirm which
class you're actually looking at before building out a PoC.
