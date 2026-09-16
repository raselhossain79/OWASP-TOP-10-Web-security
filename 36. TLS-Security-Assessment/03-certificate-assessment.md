# 03 — Certificate Assessment

## 3.1 Certificate Validity

### Why test it
An invalid certificate (wrong purpose, untrusted issuer, malformed chain)
breaks the authentication guarantee TLS is supposed to provide — clients may
either hard-fail (breaking availability) or, worse, users may click through
warnings, training them to ignore future genuine attacks.

### Classification
High if invalid/untrusted; Informational if valid but suboptimal
(self-signed on an internal-only test host, for example).

### Detection & interpretation
- `openssl s_client -connect host:443 -showcerts` then `openssl x509 -noout
  -text` on the leaf cert — check `Issuer`, `Subject`, and verify against a
  trusted root store.
- `testssl.sh` reports `Certificate Validity` and `Trust` sections directly
  with pass/fail per check.

### Remediation
- Issue from a publicly trusted CA for anything internet-facing; use
  internal PKI only for genuinely internal services with client-side trust
  distribution.

---

## 3.2 Certificate Expiration

### Why test it
An expired certificate causes hard connection failures in modern browsers —
an availability issue, but also frequently a sign of poor certificate
lifecycle management, which correlates with other neglected TLS hygiene.

### Classification
Medium approaching Critical as expiry nears (score by days remaining: <7
days = High, <30 = Medium, >30 = Informational/track).

### Detection & interpretation
- `openssl x509 -noout -enddate -in cert.pem` or via `s_client`:
  `echo | openssl s_client -connect host:443 2>/dev/null | openssl x509
  -noout -dates`
- `testssl.sh` prints `Certificate Validity (UTC)` with start/end dates and
  flags near-expiry explicitly.

### Remediation
- Automate renewal (ACME/Let's Encrypt, or enterprise CA automation) rather
  than manual tracking; alert at 30/14/7 day thresholds.

---

## 3.3 Certificate Hostname / SAN Matching

### Why test it
If the certificate's Subject Alternative Names (or legacy CN) don't cover
the hostname actually being connected to, a client either fails the
connection or — if misconfigured to ignore hostname checks — accepts a
certificate that provides no real assurance against MITM.

### Classification
High.

### Detection & interpretation
- `openssl x509 -noout -text` → check the `X509v3 Subject Alternative Name`
  extension against every hostname the service is expected to answer for
  (including all subdomains behind a load balancer/CDN).
- `testssl.sh` explicitly reports hostname match status.

### Remediation
- Ensure SAN list includes every hostname served on that certificate;
  prefer per-service certificates over broad wildcards where practical (see
  3.8).

---

## 3.4 Certificate Chain Validation

### Why test it
A server that only presents the leaf certificate without the required
intermediate(s) forces the client to trust-chase — some browsers cache
intermediates and succeed anyway, silently masking the misconfiguration,
while other clients (mobile apps, custom HTTP clients, IoT) will fail.

### Classification
Medium-High (inconsistent failure across client types makes it easy to miss
in casual browser testing).

### Detection & interpretation
- `openssl s_client -connect host:443 -showcerts` — count certificates
  returned; if only 1 (the leaf) and it's not self-signed by a root already
  in major trust stores, the intermediate is missing.
- SSL Labs' server test flags "Chain issues" explicitly (see 07).

### Remediation
- Configure the web server to serve the full chain (leaf + intermediates,
  excluding the root) — e.g., nginx `ssl_certificate` should point to a
  "fullchain" file, not the leaf alone.

---

## 3.5 Self-Signed Certificate Detection

### Why test it
Self-signed certificates provide encryption but no third-party-verified
identity assurance — acceptable for internal lab/dev use, a genuine finding
for anything public-facing.

### Classification
High for public-facing; Informational for confirmed internal-only lab
targets.

### Detection & interpretation
- `openssl x509 -noout -issuer -subject` on the leaf — if `Issuer` equals
  `Subject`, it's self-signed.
- Cross-check the deployment context before scoring — this is one of the
  few checks where the same technical fact has very different severity
  depending on intended audience.

### Remediation
- Issue from a trusted CA for any public-facing service.

---

## 3.6 Weak Signature Algorithm (MD5/SHA1-signed certs)

### Why test it
A certificate signed with MD5 or SHA1 is vulnerable to collision-based
forgery in principle — an attacker who can produce a colliding certificate
request could get a CA to unknowingly sign a malicious certificate that
validates against the same signature.

### Classification
Critical (MD5), High (SHA1).

### Detection & interpretation
- `openssl x509 -noout -text | grep "Signature Algorithm"` — flag
  `md5WithRSAEncryption` or `sha1WithRSAEncryption`.
- `testssl.sh` reports this directly under certificate signature info.

### Remediation
- Re-issue with SHA-256 or stronger signature algorithm (standard on all
  current CAs by default).

---

## 3.7 Public Key Length Issues

### Why test it
An undersized key (RSA <2048-bit, or a weak elliptic curve) reduces the
computational effort required to break the certificate's key, undermining
every guarantee built on top of it.

### Classification
Critical (RSA <1024), High (RSA 1024–2047), Low (modern EC curves already
compliant).

### Detection & interpretation
- `openssl x509 -noout -text | grep "Public-Key:"` — reports bit length
  directly.
- `testssl.sh` reports key size under certificate info with a strength
  label.

### Remediation
- Minimum RSA-2048, prefer ECDSA P-256 or higher for new issuance.

---

## 3.8 Wildcard Certificate Risks

### Why test it
A single wildcard certificate's private key, if compromised, grants an
attacker impersonation capability across every subdomain it covers — a much
larger blast radius than a per-service certificate, and wildcards are also
sometimes issued more broadly than actually needed.

### Classification
Medium (architectural risk, not an active exploit by itself).

### Detection & interpretation
- Identify wildcard SANs (`*.example.com`) and enumerate how many distinct
  services/servers actually hold a copy of that private key — the more
  copies, the larger the exposure surface.

### Remediation
- Prefer per-subdomain or narrowly-scoped SAN certificates for
  high-value/sensitive subdomains (e.g., auth, payment) even if a wildcard
  is used elsewhere for convenience.

---

## 3.9 CA Trust Validation / EV vs DV

### Why test it
Domain Validated (DV) certificates only assert domain control, not
organizational identity — appropriate for most sites, but a mismatch (e.g., a
banking login page using DV when the organization's own policy requires EV)
can be a compliance or brand-trust finding rather than a pure technical one.

### Classification
Informational/Low — policy-dependent, rarely a standalone security bug.

### Detection & interpretation
- `openssl x509 -noout -text` — check for Organization (O) field presence
  and Certificate Policies OID matching known EV OIDs.

### Remediation
- Align certificate validation level with organizational policy and
  regulatory requirements for the specific service.

---

## 3.10 Certificate Revocation Checking (CRL/OCSP)

### Why test it
If a private key is compromised, revocation is the mechanism that tells
clients to stop trusting that certificate before its natural expiry. If CRL
distribution points or OCSP responders are unreachable/misconfigured, clients
may fail open (accept anyway) — silently negating the entire revocation
mechanism.

### Classification
Medium.

### Detection & interpretation
- `openssl x509 -noout -text | grep -A2 "CRL Distribution\|Authority
  Information Access"` — confirm URLs are present and reachable
  (`curl -I <crl_url>` / `<ocsp_url>`).
- `testssl.sh` reports OCSP responder reachability directly.

### Remediation
- Ensure CRL/OCSP endpoints are reliably reachable; consider OCSP stapling
  (3.11) to reduce dependency on client-side revocation checks.

---

## 3.11 OCSP Stapling Status

### Why test it
Without stapling, the client itself must contact the OCSP responder,
leaking the client's browsing target to that third party and adding latency;
with stapling, the server periodically fetches and "staples" a signed OCSP
response to the handshake.

### Classification
Low-Medium (privacy/performance hardening item).

### Detection & interpretation
- `openssl s_client -connect host:443 -status` — look for `OCSP Response
  Status: successful` in the output; absence means stapling isn't working.
- `testssl.sh` reports `OCSP stapling` pass/fail explicitly.

### Remediation
- nginx: `ssl_stapling on; ssl_stapling_verify on;` with a resolver
  configured; Apache: `SSLUseStapling on`.

---

## 3.12 Certificate Transparency (CT) Log Check

### Why test it
CT logs are public, append-only records of issued certificates — checking
them can reveal unauthorized/mis-issued certificates for your domain issued
by a compromised or careless CA, which is a detection control rather than a
server-config check.

### Classification
Informational (detective control, not a server misconfiguration).

### Detection & interpretation
- Query `crt.sh?q=example.com` or similar CT search interfaces (read-only,
  public data — always permissible to check your own domain).
- Look for certificates you didn't request, unexpected SANs, or issuance
  from unexpected CAs.

### Remediation
- Set up CT monitoring/alerting for the organization's domains; contact the
  issuing CA to revoke any unauthorized certificate found.

---

## 3.13 CAA DNS Record Check

### Why test it
A CAA (Certification Authority Authorization) DNS record restricts which
CAs are permitted to issue certificates for a domain — its absence means any
publicly trusted CA can issue a certificate for that domain if they're
tricked or compromised.

### Classification
Low-Medium (preventive hardening control).

### Detection & interpretation
- `dig CAA example.com` — absence of any record is the finding.

### Remediation
- Add a CAA record restricting issuance to the organization's actual CA(s),
  e.g. `example.com. CAA 0 issue "letsencrypt.org"`.
