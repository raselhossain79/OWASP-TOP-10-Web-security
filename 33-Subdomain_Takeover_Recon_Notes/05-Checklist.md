# 05 — End-to-End Checklist

A field reference tying together every file in this series. Use this during a live
engagement once the methodology and tooling in files 01–04 are understood.

## Stage 1 — Subdomain Enumeration

- [ ] Confirm scope: which domains and subdomains are explicitly in-scope for this
      engagement or program before running any active technique.
- [ ] Run Subfinder with `-all -recursive` against every in-scope root domain.
- [ ] Run Amass passive pass (`-passive`) against every in-scope root domain.
- [ ] Configure API keys (SecurityTrails, Censys, Shodan, VirusTotal) for both tools if
      not already set up — meaningfully improves coverage.
- [ ] Run Amass active pass with brute-forcing (`-active -brute -w wordlist`) using a
      curated wordlist, only if active techniques are within scope/permitted.
- [ ] Merge and deduplicate all output (`cat ... | sort -u`) into one master subdomain list.
- [ ] Run httpx against the master list with `-sc -title -tech-detect -cname -ip` to
      identify live hosts and pull CNAME data in the same pass.
- [ ] Save all raw output files in a per-target project directory for later reference
      and for diffing against future re-runs.

## Stage 2 — Subdomain Takeover

- [ ] Filter the httpx CNAME output for matches against known third-party hosting
      platform domains (GitHub Pages, S3, Heroku, Azure, etc.).
- [ ] Run an automated takeover scan (Nuclei takeover templates, subzy, or
      provider-specific tooling like Subdominator for Azure) against the live host list.
- [ ] For each candidate match, manually verify the response against the current
      `can-i-take-over-xyz` fingerprint for that provider — do not trust automation
      output alone.
- [ ] Confirm the resource is genuinely unclaimed, not an actively owned backend
      returning a generic 404.
- [ ] Re-check program scope and rules specifically for subdomain takeover before
      claiming any resource — some programs require pre-authorization or exclude this
      class entirely.
- [ ] Claim the resource minimally (a single placeholder page is sufficient evidence).
- [ ] Check parent-domain cookie scoping (`Domain=.example.com`, `HttpOnly` status) to
      assess session/cookie theft impact.
- [ ] Check CSP and CORS configuration on the main application for trust of
      `*.example.com` to assess bypass impact.
- [ ] Determine whether the dangling record is CNAME/ALIAS (single-subdomain) or NS
      (full-zone) for accurate severity rating.
- [ ] Capture before/after evidence (`curl -i` output or screenshots) for the report.

## Stage 3 — General Attack Surface Mapping

- [ ] For each live host not flagged for takeover, identify the technology stack via
      httpx `-tech-detect` output, response headers, cookie names, and error pages.
- [ ] Check `robots.txt` and `sitemap.xml` for disclosed paths.
- [ ] Fetch and review JavaScript bundles for hardcoded API endpoints and routes.
- [ ] Run ffuf or gobuster directory/file discovery using a wordlist matched to the
      identified technology stack where possible.
- [ ] Profile the target's "not found" response behavior before trusting raw status
      codes; apply size/word/regex filtering as needed.
- [ ] Run vhost discovery (ffuf `Host` header fuzzing or `gobuster vhost`) to catch
      virtual hosts without public DNS records.
- [ ] Run parameter discovery against identified API endpoints where input handling is
      a concern.
- [ ] Loop back to Stage 1 with any newly discovered subdomains or hostnames surfaced
      during content discovery.
- [ ] Keep scan rate conservative on live, rate-limit-sensitive, or WAF-protected
      targets; increase only after confirming tolerance.

## Reporting

- [ ] For subdomain takeover findings: include before/after evidence, cookie scope
      analysis, CSP/CORS analysis, and record-type severity justification — not just
      "I claimed the resource."
- [ ] For general attack surface findings: note the discovery method (which tool, which
      wordlist) so the finding is reproducible by the triager.
- [ ] Cross-reference any takeover fingerprint claims against the current
      `can-i-take-over-xyz` status before submission, since provider mitigations change
      over time.
- [ ] Confirm every action taken stayed within the program's documented scope and rules
      before submitting.

## Recurring / Continuous Practice

- [ ] Re-run the full Stage 1–3 pipeline on a schedule (daily or weekly) against active
      bug bounty scope.
- [ ] Diff each run's subdomain list against the previous run to catch newly deployed
      infrastructure quickly — this matters most for subdomain takeover specifically,
      since unclaimed-resource windows are often short-lived.
