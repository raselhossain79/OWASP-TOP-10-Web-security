# 01 — Overview and Methodology: A06:2021 Vulnerable and Outdated Components

## 1. What this category actually is

OWASP A06:2021 covers risk introduced by using software components — frameworks,
libraries, CMS platforms, server software, OS packages, JavaScript dependencies —
that are out of date, unsupported, or contain known (publicly disclosed)
vulnerabilities.

This is fundamentally different from the other categories in this note series.
SQL Injection, XSS, SSTI, XXE, and LDAP Injection are all about **unsafe handling
of user input by application code**. A06 is about **unsafe handling of
third-party code by the organization running it**. The "vulnerability" you are
hunting is not a flaw you craft a payload for — it is a flaw that already exists,
already has a CVE number, and already (often) has a public exploit. Your job as
a tester is recon, identification, and verification — not creative payload
engineering.

This matters for how you write findings: the fix is almost never "sanitize
input." The fix is "upgrade to version X.Y.Z or apply vendor patch Z."

## 2. Why this category exists — real-world framing

A06 was added/elevated in the OWASP Top 10 2021 specifically because data
showed it is one of the highest-incidence categories in real breaches, despite
being conceptually "simple." A few cases worth knowing because they show the
realistic blast radius:

- **Equifax (2017):** Attackers exploited an unpatched Apache Struts
  vulnerability (CVE-2017-5638) in a consumer complaint web portal. The patch
  had been available for over two months before the breach. Roughly 147
  million people's PII was exposed. This is the canonical "known component,
  known fix, not applied" case study, and it is the single most-cited example
  in industry training material for this exact category.
- **Log4Shell (2021, CVE-2021-44228):** A deserialization-adjacent RCE in the
  ubiquitous Java logging library Log4j. Because Log4j is a transitive
  dependency buried inside thousands of other libraries and products, most
  affected organizations did not even know they were exposed — they had never
  directly chosen to use Log4j, it came in through something else they used.
  This is the textbook supply-chain angle of A06: risk you inherit without
  directly deciding to take it on.
- **Apache Struts "Showcase" RCE family (CVE-2017-9805 and related):** Multiple
  Struts CVEs over the years have been exploited in the wild within days of
  disclosure, because Struts is widely deployed and slow to patch in large
  enterprises. This is also the exact framework PortSwigger uses in its
  Information Disclosure lab (see file 05) precisely because it is such a
  realistic, well-known case.
- **WordPress/Drupal plugin ecosystem:** A large share of real-world A06
  findings in bug bounty and CMS-based engagements are not the core
  CMS itself, but outdated third-party plugins/themes — exactly the same
  "inherited risk" pattern as Log4Shell, just at a much smaller scale per
  incident.

Industry takeaway: A06 findings are rarely glamorous zero-days. They are almost
always "this is a known, patched issue, and the patch was not applied." That is
precisely why they are so common — patch management is an operational discipline
problem, not just a technical one.

## 3. End-to-end methodology

This is the phase structure used across the rest of this series. Each phase
maps to one or more of the other files.

### Phase 1 — Passive and active recon (→ File 02)
Identify what software is running without assuming anything from the client's
documentation. Use HTTP response headers, error pages, default file paths,
favicon hashes, JS file paths/comments, robots.txt, and CMS-specific
fingerprints. Confirm with active tools (WhatWeb, Wappalyzer, Nmap version
detection) only after passive recon has narrowed the field — this keeps noise
down and avoids tipping off detection systems unnecessarily early.

### Phase 2 — Dependency-level enumeration (→ File 03)
If you have any code-level or build-artifact access (common in grey-box/white-box
engagements, CI/CD security reviews, or client-provided source), enumerate
the actual dependency tree, not just the visible front-end stack. This is
where Retire.js (client-side JS dependencies) and OWASP Dependency-Check
(server-side/Java/.NET/etc. dependencies) come in. In a pure black-box
external test, you are normally limited to what Phase 1 surfaces — flag this
limitation explicitly in your report scope notes.

### Phase 3 — Version-to-CVE mapping (→ File 04)
Take every concrete version string you found in Phases 1–2 and run it through
a disciplined CVE research workflow: NVD for canonical, scored vulnerability
data; Exploit-DB for known public exploit code/PoCs; vendor advisories for
the authoritative patch timeline. Never treat "this version number appears in
a CVE title" as proof of exploitability on its own — see the verification
discipline below.

### Phase 4 — Responsible verification
Before you report (or before you escalate to active exploitation, if in
scope), verify the finding without crossing into unauthorized impact:

- **Version confirmation, not exploitation, is the default action.** If the
  version string alone is enough to know it's vulnerable and unpatched (e.g.
  it predates the fixed version in the vendor advisory), that is often
  sufficient to report — you do not need to detonate an RCE PoC just to prove
  a point, especially in production environments.
- **If verification requires deeper proof** (e.g. client disputes the version
  is accurate, or the engagement scope explicitly calls for proof-of-exploit),
  use the least invasive technique available: a non-destructive PoC (e.g. a
  benign SSRF callback, a harmless file read, a sleep-based timing check)
  rather than a full RCE chain, unless full exploitation is explicitly
  authorized in the rules of engagement.
- **Always check the Rules of Engagement (RoE) / scope document** before
  running any public Exploit-DB PoC against a live target — many PoCs are
  unstable, can crash services, or have destructive side effects (e.g. dropping
  webshells, modifying data). This is a real operational risk distinct from
  the legal/authorization risk.
- **Document version evidence even if you don't exploit it.** A finding of
  "Apache Struts 2.3.31, last patched version is 2.3.34/2.5.16, CVE-2017-9805
  (CVSS 8.1) is unpatched on this host" is a complete, defensible, reportable
  finding without ever firing the exploit.

### Phase 5 — Reporting
Map every finding back to: the exact component + version, the CVE(s) affecting
it, the CVSS score, whether a public exploit exists, and the concrete remediation
(target patched version, or compensating control if patching isn't immediately
possible — e.g. WAF rule, network segmentation, disabling the vulnerable
feature).

## 4. How this differs from a vulnerability scanner's job

Tools like Nessus or Qualys do large-scale automated version-to-CVE matching
already. As a manual pentester, your value-add in this category is:

1. Finding components automated scanners miss (custom-built internal tools,
   obscure JS libraries bundled and renamed, forked/patched-but-still-vulnerable
   code).
2. Validating false positives — scanners frequently flag a version string that
   was actually backported/patched by the vendor without a version bump.
3. Chaining a vulnerable component finding into a real, demonstrated impact
   for the client (e.g. confirming the Struts RCE actually executes a command,
   not just that the version number matches a CVE).

**Real-world note:** Clients increasingly expect pentesters to also flag
*unsupported/EOL* software even when no specific CVE is currently known — e.g.
a server running an OS or framework version that has reached end-of-life and
will receive no further security patches. This is a forward-looking risk, not
a current-CVE risk, and it belongs in A06 findings too.
