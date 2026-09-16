# 06 — Adjacent / Real-World Checks

These sit at the boundary of pure TLS assessment and broader web app
testing — included because they're commonly missed in TLS-only checklists
but directly affect whether TLS's guarantees actually reach the user.

## 6.1 HTTP → HTTPS Redirect Enforcement

### Why test it
If a server accepts plaintext HTTP and only "prefers" HTTPS via a redirect,
every plaintext request-response pair before that redirect completes is an
interception window — and if the redirect itself is missing, weak, or
skippable, users may stay on plaintext HTTP indefinitely.

### Classification
Medium (redirect present but incomplete coverage), High (no redirect at
all on a service handling sensitive data).

### Detection & interpretation
- `curl -I http://host` — confirm a `301`/`308` redirect to `https://` is
  returned, and that it isn't itself redirecting to another HTTP URL first
  (redirect chains that stay on HTTP longer than necessary).
- Check every path, not just `/` — some configs only redirect the root.

### Remediation
- Redirect all HTTP traffic to HTTPS at the earliest possible point (ideally
  the edge/CDN), then layer HSTS (04.2) so browsers stop trying HTTP first
  on subsequent visits.

---

## 6.2 Mixed Content Detection

### Why test it
An HTTPS page that loads any sub-resource (script, stylesheet, image,
iframe) over plain HTTP undermines the page's integrity guarantee — active
mixed content (scripts) is especially dangerous since a MITM can modify the
script and gain full control of the page's JavaScript context.

### Classification
High (active mixed content: scripts, stylesheets), Low (passive mixed
content: images).

### Detection & interpretation
- Browser DevTools console flags mixed content automatically when browsing
  the live page; for automated scanning, grep rendered HTML/JS for
  `http://` sub-resource URLs.
- Distinguish active vs passive resource types when scoring severity.

### Remediation
- Convert all sub-resource URLs to `https://` or protocol-relative/absolute
  paths; use `Content-Security-Policy: upgrade-insecure-requests` as a
  defense-in-depth backstop.

---

## 6.3 Certificate Pinning Considerations (Mobile/API Context)

### Why test it
Certificate/public-key pinning hard-codes an expected certificate or key
into a mobile app or API client so that even a compromised or mis-issued CA
certificate won't be trusted. Testing here is about assessing whether pinning
is present, correctly implemented, and has a safe rotation plan (unplanned
pin expiry with no update path can brick an entire app's connectivity).

### Classification
Informational-Medium — this is more of an architecture review than a
single pass/fail finding.

### Detection & interpretation
- For mobile apps: intercept traffic via a proxy (e.g., Burp) with a
  trusted CA installed on the test device — if the app still fails to
  connect through the proxy, pinning is present and working; if it connects
  transparently, pinning is absent or bypassable.
- Review whether the pin set includes a backup pin and a realistic rotation
  window ahead of the primary certificate's expiry.

### Remediation
- Implement pinning for high-value mobile/API clients with at least one
  backup pin and a rotation plan tested well before expiry.

---

## 6.4 Load Balancer / CDN TLS Termination Misconfiguration

### Why test it
Many deployments terminate TLS at a CDN or load balancer and then
communicate with the origin over a separate connection (often plain HTTP,
or TLS with weaker settings than the edge). Testing only the public edge
gives a false sense of security if that internal hop is exposed to a wider
network than assumed (shared hosting, cloud VPC misconfig, etc.).

### Classification
Medium-High, context-dependent on how exposed the internal hop actually is.

### Detection & interpretation
- Map the full path: edge TLS config vs origin TLS config, and what
  protocol/cipher the edge-to-origin hop actually uses (often documented in
  CDN provider dashboards, or discoverable via origin IP scanning if
  authorized).
- Check for origin IP exposure that would let an attacker bypass the CDN
  entirely and hit the (possibly weaker) origin TLS directly.

### Remediation
- Encrypt edge-to-origin traffic with TLS as well (not just client-to-edge);
  restrict origin firewall rules to only accept connections from the CDN's
  published IP ranges.

---

## 6.5 MITM via Downgrade — End-to-End Scenario

### Why test it
This ties several individual findings together into the actual attack
narrative a report should tell: e.g., "no TLS_FALLBACK_SCSV (1.3) + SSLv3
still enabled (1.1) + no HSTS (4.2)" combine into a realistic, low-effort
downgrade-then-intercept chain, even though each individual finding might
look moderate in isolation.

### Classification
Chain severity is typically higher than any single contributing finding —
score the chain, not just the parts, in the final report.

### Detection & interpretation
- After completing 01–04, deliberately re-read the findings together and
  ask: "starting from a plaintext HTTP request, what's the shortest path to
  a decrypted or injected session for this specific target?"

### Remediation
- Address the weakest link in the chain first — usually removing the old
  protocol/cipher and adding HSTS closes most practical downgrade paths
  even before every individual hardening item is perfect.
