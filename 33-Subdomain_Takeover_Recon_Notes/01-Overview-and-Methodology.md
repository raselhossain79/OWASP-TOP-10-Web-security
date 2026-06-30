# 01 — Overview & Methodology

## What "Attack Surface Mapping" Means

Attack surface mapping is the process of discovering everything an organization exposes
to the internet — every subdomain, every host, every service running on those hosts,
every technology stack in use, and every endpoint or parameter that accepts input. It is
the reconnaissance phase that every other vulnerability class depends on. You cannot
attack what you haven't found.

This differs from classic vulnerability classes like SQL injection or XSS, which assume
you already have a target endpoint in front of you. Attack surface mapping is what gets
you to that endpoint in the first place — and on a large organization, the endpoint that
turns out to be vulnerable is very often one nobody on the security team remembered
existed.

## Why Subdomain Takeover Specifically

Subdomain takeover is one of the highest value-per-effort bug classes in bug bounty
hunting because:

- It requires no authentication bypass, no payload crafting, no complex chaining — just
  finding a DNS record pointing to a resource that no longer exists.
- It is entirely a hygiene failure (decommissioning a cloud resource without removing
  the DNS record pointing to it), which means it recurs constantly across large
  organizations with many teams spinning up and tearing down cloud infrastructure.
- The impact is easy to demonstrate convincingly: full control of a subdomain under the
  target's own domain, usable for phishing, cookie theft (if the parent domain sets
  cookies scoped broadly enough), or hosting malicious content with the implicit trust
  of the target's brand.
- It is almost entirely automatable at the discovery stage, meaning a tooling-heavy
  workflow systematically outperforms manual hunting.

## The Three-Stage Pipeline

This series is structured around the pipeline an attacker (or bug bounty hunter)
actually follows in practice:

**Stage 1 — Subdomain Enumeration (passive + active recon)**
Build the largest possible list of valid subdomains using certificate transparency logs,
DNS aggregator APIs, and brute-forcing. Covered in `02-Recon-Tooling-Amass-Subfinder-httpx.md`.

**Stage 2 — Subdomain Takeover Identification & Exploitation**
Filter the subdomain list down to CNAME records pointing at third-party services, check
whether those services report the resource as unclaimed, and claim it. Covered in
`03-Subdomain-Takeover-Exploitation.md`.

**Stage 3 — General Attack Surface Mapping Beyond Subdomains**
For subdomains that are alive (not takeover candidates), fingerprint the technology
stack and run content discovery to find exposed endpoints, parameters, admin panels,
and forgotten directories. Covered in `04-Content-Discovery-ffuf-gobuster.md`.

These stages are not strictly linear in a live engagement — you'll often loop back to
Stage 1 after Stage 3 reveals new subdomains referenced inside JavaScript files or API
responses — but this is the correct order to learn them in.

## Where This Fits in a Penetration Test or Bug Bounty Engagement

In a formal penetration test, this is the reconnaissance / information gathering phase,
typically the first 10–20% of engagement time but disproportionately important: a
missed subdomain means an entire missed attack surface, not just one missed bug.

In bug bounty hunting, this is usually a continuous background process rather than a
one-time phase. Top bounty hunters run recon pipelines on a schedule (daily or weekly)
against their target programs' scope, diffing the subdomain list against the previous
run to catch newly deployed (and potentially misconfigured) infrastructure the moment
it appears — because subdomain takeover windows are often short-lived (a resource sits
unclaimed for days before someone notices and removes the DNS record, or before another
hunter claims it first).

## PortSwigger Web Security Academy Lab Coverage — Honest Disclosure

This is important to state plainly rather than imply false lab coverage: **PortSwigger
Web Security Academy has no dedicated lab category for subdomain takeover, subdomain
enumeration, or general attack surface mapping.** This is consistent with Academy's
scope — it is built around application-logic vulnerabilities (injection, access control,
deserialization, request smuggling, and so on) that can be modeled inside a self-contained
lab environment. Subdomain takeover is fundamentally an infrastructure and DNS hygiene
issue that depends on real third-party cloud services (S3, Azure, Heroku, GitHub Pages)
being in an actually-unclaimed state — something a static lab environment cannot
replicate, since cloud providers control resource availability outside Academy's control.

This series will **not** pretend otherwise or stretch unrelated labs (e.g., Academy's
DNS rebinding labs under SSRF, which are a different vulnerability class entirely) to
manufacture false coverage.

### Where Real Practice Comes From Instead

- **Live bug bounty programs** (HackerOne, Bugcrowd, Intigriti) — the only environment
  where genuinely unclaimed cloud resources exist to be found and claimed. This is the
  primary practice ground for this category.
- **`EdOverflow/can-i-take-over-xyz`** (GitHub) — a community-maintained reference of
  which cloud services are currently vulnerable to takeover and which have patched the
  issue, used as the canonical fingerprint reference (expanded on in
  `03-Subdomain-Takeover-Exploitation.md`).
- **Self-hosted practice** — intentionally provisioning and then deprovisioning a cheap
  cloud resource (e.g., an S3 bucket or a Heroku app) under a domain you control, then
  practicing the claim process end-to-end without touching anyone else's infrastructure.
- **Writeups from disclosed reports** on HackerOne's public disclosure feed and
  Bugcrowd's disclosed program reports, searching for "subdomain takeover" to see real
  confirmed cases and the exact reasoning used.

## Real-World Industry Framing

Subdomain takeover consistently appears in roundups of the highest-volume bug classes
reported on bug bounty platforms, and major organizations (Microsoft, Uber, Starbucks,
and many others) have paid out bounties for it historically. It is also a recurring
finding in external attack surface management (EASM) vendor reports (e.g., from
Censys, Detectify, and similar vendors that sell continuous attack surface monitoring
as a product) — which itself tells you something: companies pay for commercial tooling
specifically because manual tracking of subdomain inventory at scale consistently fails.
That gap is exactly what this series' tooling-first approach is built to exploit.
