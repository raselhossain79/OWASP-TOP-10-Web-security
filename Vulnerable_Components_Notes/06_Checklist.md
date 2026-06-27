# 06 — Final Checklist: A06 Vulnerable and Outdated Components

Use this as a pre-report / pre-engagement gate check. Each box should be
answerable with evidence, not a guess.

## Recon coverage

- [ ] Checked HTTP response headers (`Server`, `X-Powered-By`, etc.) across
      all in-scope hosts, not just the main landing page.
- [ ] Checked for verbose error messages / stack traces (manually triggered
      where safe to do so, e.g. malformed parameter values).
- [ ] Checked HTML source comments, JS file paths/filenames, and `robots.txt`
      for platform/CMS/library version hints.
- [ ] Ran WhatWeb (with `-v` for evidence strings) against all in-scope hosts.
- [ ] Ran Wappalyzer (CLI or extension) against all in-scope hosts/key pages,
      including pages with distinct functionality (checkout, login, admin)
      that may load different tech than the homepage.
- [ ] Ran Nmap `-sV` with relevant `http-*` NSE scripts against in-scope ports.
- [ ] Cross-validated every version string with at least two independent
      sources before treating it as confirmed.

## Dependency-level coverage (if scope allows)

- [ ] Ran Retire.js against all collected client-side JS assets, not just the
      main bundle (check vendor/CDN-hosted scripts too).
- [ ] If source/build access was provided: ran OWASP Dependency-Check against
      the full dependency manifest, not just top-level direct dependencies.
- [ ] Noted explicitly in scope/limitations section if dependency-level
      scanning was NOT possible (pure black-box engagement) — don't let a
      client assume full SCA coverage happened if it didn't.

## CVE research discipline (per finding)

- [ ] Looked up the component + version in NVD (keyword or CPE).
- [ ] Confirmed the CVE's affected-version range actually includes the
      observed version — not just a name match.
- [ ] Pulled the CVSS score AND read the vector string, not just the headline
      number.
- [ ] Checked Exploit-DB / searchsploit for public exploit availability.
- [ ] If a PoC was used: read the full PoC source before running it, checked
      submission date vs. patch date, and confirmed it wasn't run against
      production without RoE authorization for that level of impact.
- [ ] Checked the vendor advisory for the exact patched version / official
      remediation guidance.
- [ ] Flagged unsupported/EOL software even where no specific current CVE
      exists, if applicable.

## Supply chain framing (where relevant)

- [ ] Distinguished direct vs. transitive dependencies in the finding writeup.
- [ ] Checked whether the upstream project is still actively maintained.
- [ ] Noted version-pinning posture (pinned vs. floating) if build config was
      visible.

## Responsible verification

- [ ] Defaulted to version-confirmation-only evidence where that was
      sufficient to support the finding (didn't detonate exploits
      unnecessarily).
- [ ] Confirmed RoE/scope explicitly authorized exploitation before running
      any live PoC with real impact potential.
- [ ] Used the least invasive verification technique available when proof
      beyond version-matching was required.

## Reporting

- [ ] Each finding states: exact component name, confirmed version, CVE
      ID(s), CVSS score, exploit-public-availability status, and concrete
      target remediation version or compensating control.
- [ ] Evidence trail (which tool/method produced which version string) is
      documented and reproducible, not just asserted.
- [ ] Distinguished "confirmed exploitable" findings from "version-matched,
      not actively exploited" findings — don't overstate confidence.
