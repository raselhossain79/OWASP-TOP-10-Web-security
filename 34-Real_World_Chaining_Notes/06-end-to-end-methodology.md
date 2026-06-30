# 06 — End-to-End Methodology Checklist

A single working reference tying recon through reporting together. Use this as the
running checklist during a live engagement — bug bounty or authorized pentest.

## Stage 1 — Recon (passive, no app-logic traffic)

- [ ] Subdomain enumeration from passive/certificate-transparency sources
- [ ] Technology fingerprinting from job postings, public repos, JS bundles already
      cached by search engines/Wayback Machine
- [ ] Cloud storage bucket discovery using target naming conventions
- [ ] Review program scope/rules of engagement (bug bounty) or signed authorization
      and rules of engagement document (pentest) line by line before any active step

## Stage 2 — Attack surface mapping (see file `03` for full detail)

- [ ] Active content/endpoint/parameter discovery on every in-scope host
- [ ] Authenticated vs. unauthenticated diffing across every available role
- [ ] Build the functional inventory table (input → processing → output) for every
      distinct feature found
- [ ] Identify high-chain-value feature categories first: outbound server-side
      requests, stored-then-rendered content, identity/session boundary features,
      check-then-act two-step actions

## Stage 3 — Low-hanging fruit testing

- [ ] Run standard detection technique for each major vuln class against every
      relevant input, using the mechanism-first detection methods from each
      individual series in this library (boolean/time-based for SQLi, polyglot
      strings for XSS/SSTI, etc.)
- [ ] For anything that doesn't match a known class cleanly, apply the file `04`
      fuzzing/inference methodology instead of skipping it
- [ ] **Log every finding regardless of apparent severity** — this is the step most
      commonly rushed, and it's the one that determines whether chaining is even
      possible later

## Stage 4 — Chaining and escalation

- [ ] Re-read your findings log against the functional inventory table from Stage 2:
      for each finding, what primitive does it grant (input control / read / write /
      trust / timing-state), and which other inventory row consumes that primitive?
- [ ] Cross-reference confirmed findings against the chain pattern catalog in file
      `02` — does this combination resemble any documented pattern?
- [ ] For each candidate chain, explicitly trace and write down (even in scratch
      notes) the exact mechanism connecting each step before attempting full
      exploitation — this prevents wasted effort chasing a connection that only
      *looks* plausible
- [ ] Attempt the full chain in a controlled, minimally-invasive way first — confirm
      the connection works with the least disruptive possible proof before building
      a maximum-impact PoC

## Stage 5 — Defense adaptation (ongoing, not a separate phase)

- [ ] Fingerprint defensive layers (file `05`) as soon as any blocking behavior is
      observed, rather than assuming an endpoint is safe
- [ ] Separate "vulnerability exists" confirmation from "payload evades current
      defenses" — confirm the former first using low-signature-footprint techniques

## Stage 6 — Impact documentation

- [ ] For every individual finding: standard severity, CVSS-style reasoning if your
      program/client expects it, and a one-line note on whether it appears chainable
- [ ] For every confirmed chain: full step-by-step writeup per file `07`'s structure
      *before* submission — don't submit a chain as a list of separate findings
- [ ] Capture evidence at every step of a chain individually (request/response pairs,
      timestamps, screenshots) — a triager or client reviewer needs to verify each
      link, not just trust the narrative

## Stage 7 — Reporting and submission

- [ ] Apply the report-writing structure from file `07` for any chained finding
- [ ] Cross-check scope/rules of engagement one final time before submitting —
      especially for chains that span multiple subdomains/services, confirm every
      component touched is actually in scope
- [ ] For pentest engagements: flag any finding that may require immediate
      out-of-band client notification (active RCE, exposed credentials with live
      access) rather than waiting for the final report

## Recurring discipline notes (apply throughout, not just at specific stages)

- Findings logging is continuous, not a Stage 3-only activity — a finding from Stage
  3 might only become a useful chain component after something discovered in Stage 4
  or even during report-writing in Stage 6.
- Revisit the functional inventory table whenever scope or your understanding of the
  app changes — it's a living document for the duration of the engagement, not a
  one-time artifact.
- This checklist is intentionally sequential in presentation but iterative in
  practice — expect to cycle back from Stage 4 to Stage 3 repeatedly as chain
  candidates reveal gaps in your testing coverage.
