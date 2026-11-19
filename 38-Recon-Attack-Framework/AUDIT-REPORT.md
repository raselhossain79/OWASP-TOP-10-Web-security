# Audit Report — Original Framework (v1)

Scope: the 4 original files (`00-README.md`, `01-origin-ip-discovery.md`,
`02-waf-detection-bypass.md`, `03-vulnerability-testing-methodology.md`). This is an
honest self-audit — several of these are real corrections to content written earlier
in this framework, not hypothetical mistakes.

## 00-README.md

| Issue | Correction |
|---|---|
| No scope/authorization step anywhere in the lifecycle | **Missing entirely.** A framework for "authorized testing" must start with confirming scope before any recon runs. Added as a dedicated first module (`01-Scope-and-Authorization.md`), not a footnote. |
| Flat 4-file structure doesn't separate concerns well | Expanded into the modular structure requested — each phase gets its own file so updates don't require touching unrelated content. |
| Retained | The core idea (origin IP first, WAF bypass as a fallback layer, generic testing loop) is correct and kept as the spine of the new structure. |

## 01-origin-ip-discovery.md

| Issue | Correction |
|---|---|
| Email header analysis was **backwards**. The file said "the top-most `Received:` header is closest to the sending server." This is incorrect — each mail server prepends its own header as the message transits, so the **top-most** header is the *last* hop (your own mail provider), and the header closest to the origin sender is near the **bottom** of the `Received:` stack. | Corrected in the new file: read `Received:` headers bottom-up. |
| Cloudflare IP check used a substring `grep -F "203.0.113"` against a sample IP. Substring matching against an IP range is not reliable — it can both miss real matches (if formatting differs) and produce false confidence. Also, static example IPs like `203.0.113.x` are reserved documentation ranges (RFC 5737), not real Cloudflare IPs — the example was illustrative but not technically meaningful. | Corrected to proper CIDR containment checking. |
| SSL certificate serial/hash matching was described as "near-certain confirmation." Overstated — wildcard certs, shared hosting, and some CDN configurations can put the same certificate on many unrelated hosts. | Reworded to "supporting evidence, not proof" and paired explicitly with a verification step. |
| No mention that finding an origin IP does not authorize testing it directly. Many bug bounty programs explicitly forbid direct-to-origin traffic because it bypasses scoped protections (rate limiting, WAF rules that are themselves in-scope controls). | Added explicit authorization callout — this is now a hard stop condition, not a tip. |
| Retained | Subdomain enumeration, favicon hashing, and the overall "candidate vs confirmed origin" distinction were technically sound and are kept, with the confirmation step tightened. |

## 02-waf-detection-bypass.md

| Issue | Correction |
|---|---|
| Did not distinguish WAF, CDN, reverse proxy, and application-level input validation — these are frequently conflated but behave very differently and require different fingerprinting approaches. | New file (`07-WAF-and-Filter-Analysis/`) separates these explicitly. |
| Bypass techniques were presented without enough caveats about modern WAF behavior (behavioral/ML-based mitigation, e.g. Cloudflare/Akamai bot management) which classic signature-evasion tricks do not reliably defeat. | Added explicit "these techniques target signature-based rules; behavioral WAFs are a different problem" caveat. |
| No statement that a WAF block is not proof a vulnerability exists (or doesn't) — a blocked request tells you nothing about what the application would have done with that input. | Added as an explicit principle, with the decision-tree. |
| No stopping condition for WAF bypass testing under program policy. | Added — bypass testing scope is now explicitly tied to program rules, with an authorized-only framing throughout. |
| Retained | The fingerprinting command (`wafw00f`) and baseline-comparison approach were accurate and are kept. |

## 03-vulnerability-testing-methodology.md

| Issue | Correction |
|---|---|
| No authentication or authorization mapping step — this is a prerequisite for IDOR/BAC testing specifically, which the original file only mentioned in a single table row. | Split into dedicated files (`authentication-mapping.md`, `authorization-mapping.md`) under `05-Input-and-Authentication/`. |
| No JavaScript or API-specific discovery step — modern apps expose most of their real attack surface through JS bundles and API calls, not server-rendered HTML. | Added `javascript-analysis.md` and `api-discovery.md` under `04-Attack-Surface-Mapping/`. |
| False-positive handling was implicit (buried in "Validation") rather than enumerated. | Added a dedicated false-positive catalog per technique file. |
| No safe-testing-practice guidance (rate limits, destructive action avoidance, test accounts). | Added to `01-Scope-and-Authorization.md` and referenced from every technique file's "Safety considerations" section. |
| Retained | The Input → Baseline → Manipulate → Detect → Validate loop and the SQLi worked example were technically correct and form the backbone of the new `06-Vulnerability-Testing/testing-methodology.md`. |

## Independent Verification of This Report's Own Earlier Claims (v2 audit)

Per the review instruction not to assume this report is correct: each claim in
the three tables above was re-checked rather than taken on faith.

- **Email `Received:` header order** — correct as stated. Per how SMTP relays
  append headers (each hop prepends its own), the top-most header is the most
  recent hop and the origin-closest header sits lower in the stack. No further
  correction needed.
- **Cloudflare IP / CIDR matching** — correct as stated; substring matching
  against an IP range is unsound regardless of implementation details, and the
  CIDR-containment fix in `origin-ip-discovery.md` is the right approach.
- **Certificate/favicon matching overstatement** — correct as stated; this is a
  general property of how TLS certificates and static assets can be shared
  across unrelated hosts, not specific to any one target.
- **WAF/CDN/proxy/app-filter conflation** — correct as stated, and this review
  found the same conflation risk extends to **request-smuggling-relevant
  infrastructure** (reverse proxies / load balancers specifically), which is why
  that class is deliberately deferred rather than bolted on hastily (see
  `00-README.md`'s "Not Yet Built" section).

No claim in the v1 audit was found to be incorrect on independent review. New
issues found during this round's deeper pass (not previously caught) are below.

## v2 Corrections (This Review Round)

| File | Issue Found | Correction |
|---|---|---|
| `sqli.md` | URL-encoding and shell-quoting were understated; commands with raw spaces (`AND 1=1`) are not reliably portable across servers/clients. | Added explicit encoding guidance (`%20` over `+`), and clarified when shell quoting is/isn't actually at risk. |
| `sqli.md` | Boolean-based testing compared only true vs. false, which can mistake ordinary page dynamism for a boolean signal. | Added mandatory baseline/true/false three-way comparison. |
| `sqli.md` | Second-order SQLi and out-of-band (OOB) SQLi were missing entirely. | Added both, with OOB explicitly marked unverified and environment-dependent (requires DBMS capability + outbound network access, both of which are commonly restricted in modern managed deployments). |
| `xss.md` | No DOM-based XSS source/sink list; CSP guidance implied a CSP-blocked payload means "not exploitable," which overstates what CSP presence tells you. | Added a concrete sink/source list and corrected CSP interpretation to "changes what must be demonstrated," not "rules out impact." |
| `idor.md` | No mapping to OWASP API Top 10 terms (BOLA/BFLA), which bug bounty programs increasingly use alongside or instead of "IDOR." | Added explicit terminology mapping and an ownership-verification prerequisite step. |
| `ssrf.md` | Did not distinguish a DNS-only interaction from a full HTTP request (different confirmation strength); cloud metadata section assumed a simple unauthenticated `GET` would succeed, ignoring IMDSv2-style token requirements common on current AWS configurations. | Added the DNS-vs-HTTP distinction table and corrected the metadata section to note a failed simple `GET` does not disprove SSRF. |
| `api-discovery.md` | Implied an exposed Swagger/OpenAPI file or GraphQL introspection was itself worth reporting. | Corrected explicitly: neither is a vulnerability without demonstrated impact (internal-only endpoint reachability, or a mutation that shortcuts a separately-confirmed finding). |

## Structural Completion vs. Technical Verification vs. Testing Coverage

These are three different claims and are reported separately rather than
collapsed into one "status: done":

**Structural completion**: Complete for everything specified in Phases 1–5 of
this review, except the five advanced classes explicitly deferred (see
`00-README.md`). Directory layout matches the structure requested; every file
listed in `00-README.md`'s module map exists on disk; internal Markdown links
were checked against actual filenames before packaging (see change log below).

**Technical verification**: Mixed, and stated per-item rather than as a blanket
claim. Core mechanisms (HTTP semantics, SQL comment syntax per DBMS, CORS
credential/wildcard interaction, DNS `Received:` header ordering, CIDR
containment) reflect well-established, stable technical behavior and are
presented with ordinary confidence. Items explicitly flagged as unverified by
direct testing in this framework (and why) are listed in `00-README.md`'s
"Remaining Limitations" section — this includes the MSSQL OOB syntax and
engine-specific SSTI escalation beyond the arithmetic-proof stage. Tool flag
behavior (`curl`, `nmap`, `ffuf`, `sqlmap`, etc.) reflects commonly documented
usage but was not re-verified against a live installed binary in this review —
the framework consistently instructs checking `--help`/official docs before
relying on any flag, rather than claiming each one was freshly tested here.

**Testing coverage**: 14 vulnerability-specific playbooks now exist
(`sqli`, `xss`, `ssrf`, `idor`, `business-logic`, `authentication`,
`broken-access-control`, `file-upload`, `path-traversal-lfi`, `csrf`, `ssti`,
`xxe`, `cors`, `open-redirect`), covering the common/practical tier requested.
Five advanced/less-frequent classes remain pending (Race Conditions, JWT,
HTTP Request Smuggling, WebSocket security, and the remaining API-specific
cluster beyond BOLA/BFLA). This is a coverage gap, stated plainly, not a
structural or technical defect in what exists.

## Known Structural Inconsistency (Stated Plainly, Not Silently Left)

The 5 vulnerability files carried over from the previous batch (`sqli.md`,
`xss.md`, `ssrf.md`, `idor.md`, `business-logic.md`) use a 12-section numbering
scheme from an earlier revision of this framework. The 9 new playbooks added in
this round use the 14-section format specified in this review's requirements
(adding "Where this commonly occurs" and "When to test" as distinct sections,
and splitting validation/reporting more granularly). The **content** of the
older 5 files covers the same ground — they were not left technically
incomplete — but their section numbering/headers do not literally match the
newer files side-by-side. Harmonizing the older 5 files to the exact 14-section
header format is a cosmetic consistency pass, not yet done, and is listed here
rather than silently glossed over.

## Link and Syntax Verification Performed

- Every backtick-quoted `.md` filename reference across the project was
  extracted and cross-checked against the actual file tree before packaging.
  Three references to old, pre-restructure filenames (`01-origin-ip-
  discovery.md`, `02-waf-detection-bypass.md`, `03-vulnerability-testing-
  methodology.md`) remain, intentionally, inside this audit report's historical
  section describing the original v1 files — these are not live links and are
  not broken references in the current structure. One reference to `jwt.md` in
  `authentication.md` is intentional and explicitly marked as pending (see
  "Not Yet Built" in `00-README.md`).
- Shell commands across the project were reviewed for the specific risks named
  in this review (unescaped special characters inside double-quoted shell
  arguments, missing URL-encoding on reserved characters) — the corrections in
  `sqli.md` resulted directly from this pass; no other command in the project
  was found to have an equivalent issue on review.

## Status

Structurally complete for this review's scope, with the advanced-class gap and
the section-numbering inconsistency above both stated explicitly rather than
hidden. See "Remaining Limitations" and "Not Yet Built" in `00-README.md` for
the full, itemized list of what's unverified or pending.
