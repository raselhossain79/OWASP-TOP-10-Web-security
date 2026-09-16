# 04 — TLS Configuration & Session Handling

## 4.1 General TLS Configuration Review

### Why test it
This is the rollup check: even if every individual item above passes, the
overall configuration file can still have inconsistencies (e.g., strong
ciphers defined but applied to the wrong `server{}` block, or a config that
only covers the default vhost while other vhosts inherit insecure defaults).

### Classification
Varies — treat as a review step, not a single scored finding.

### Detection & interpretation
- Test every distinct hostname/vhost on the server individually — TLS
  scanners report per-connection, not per-server, so a passing scan against
  one vhost says nothing about a second certificate/vhost on the same IP.
- Use SNI explicitly: `openssl s_client -connect host:443 -servername
  other-vhost.example.com`.

### Remediation
- Maintain a single shared, curated TLS config snippet included by every
  vhost, rather than duplicating settings per-site.

---

## 4.2 HSTS (HTTP Strict Transport Security)

### Why test it
Without HSTS, a user's very first request to a domain (or any request after
cache/cookie clearing) can go out over plain HTTP, giving an on-path
attacker a window to intercept or redirect before the HTTPS upgrade happens
(classic SSL-stripping).

### Classification
Medium (missing entirely), Low (present but weak `max-age` or missing
`includeSubDomains`).

### Detection & interpretation
- Check the `Strict-Transport-Security` response header directly: `curl -I
  https://host` and inspect for presence, `max-age` value (recommend
  ≥31536000, i.e. 1 year), `includeSubDomains`, and `preload`.
- `testssl.sh` reports HSTS presence and parameters explicitly.

### Remediation
- Add `Strict-Transport-Security: max-age=31536000; includeSubDomains;
  preload` once every subdomain is confirmed HTTPS-capable (preload is
  effectively permanent via browser preload lists — verify subdomain
  coverage first).

---

## 4.3 Secure vs Insecure Renegotiation

### Why test it
TLS renegotiation lets either party renegotiate handshake parameters
mid-session. The original (insecure) renegotiation design was exploitable via
CVE-2009-3555, allowing an attacker to inject plaintext into the start of a
victim's authenticated session (relevant historically against HTTP request
splicing).

### Classification
High if insecure renegotiation is supported at all.

### Detection & interpretation
- `testssl.sh` explicitly reports `Secure Renegotiation` and `Client-
  initiated Renegotiation` as separate line items.
- Client-initiated renegotiation being allowed (even if "secure") is
  additionally a DoS concern — see 4.7-adjacent note on resource exhaustion.

### Remediation
- Ensure the TLS library is current (secure renegotiation, RFC 5746, is
  standard in all modern stacks); disable client-initiated renegotiation at
  the server level where supported.

---

## 4.4 Session Resumption / Session Ticket Handling

### Why test it
Session resumption (session IDs or session tickets) speeds up reconnects by
skipping a full handshake — but if session ticket encryption keys are
long-lived or shared across a large fleet without rotation, compromising one
key can retroactively decrypt many resumed sessions, undermining PFS gained
elsewhere.

### Classification
Medium.

### Detection & interpretation
- `testssl.sh` reports session ticket/ID support and, where determinable,
  ticket lifetime hints.
- Check server config for ticket key rotation interval — this typically
  isn't visible from the wire and requires config review access.

### Remediation
- Rotate session ticket keys frequently (short-lived, e.g., hourly) and
  avoid syncing the same ticket key across a very large fleet without
  rotation.

---

## 4.5 TLS Compression Status (CRIME)

### Why test it
TLS-level compression enables the CRIME attack — a compression-ratio side
channel that can leak secrets (like session cookies) byte-by-byte, similarly
to how BREACH targets HTTP-level (not TLS-level) compression.

### Classification
High if TLS compression is enabled at all (it should never be, on any
modern stack).

### Detection & interpretation
- `testssl.sh -C` / the CRIME-specific flag reports compression status
  directly as vulnerable/not vulnerable.

### Remediation
- Disable TLS-level compression entirely (default-off on all current
  OpenSSL/BoringSSL builds; only a concern on very old/custom builds).

---

## 4.6 ALPN/NPN Negotiation Check

### Why test it
ALPN (Application-Layer Protocol Negotiation) determines whether HTTP/2 or
HTTP/1.1 is used — not a vulnerability by itself, but misconfigured ALPN can
cause protocol downgrade to HTTP/1.1 unexpectedly, or in rare cases interact
with request-smuggling class issues at protocol boundaries (cross-reference
the HTTP request smuggling file elsewhere in the library for the smuggling
mechanics themselves).

### Classification
Informational, unless combined with a smuggling-relevant protocol mismatch
at a proxy boundary (Medium-High in that combined case).

### Detection & interpretation
- `openssl s_client -connect host:443 -alpn h2,http/1.1` — check the
  negotiated protocol reported.
- Confirm consistency between what the edge (CDN/LB) negotiates and what
  the origin actually speaks.

### Remediation
- Ensure ALPN configuration is consistent across every hop in the request
  path; disable legacy NPN if still enabled (superseded by ALPN).

---

## 4.7 SNI Handling Issues

### Why test it
Server Name Indication tells a multi-tenant server which certificate to
present. Misconfigured SNI handling can leak which other hostnames are
hosted on the same IP (via certificate SAN lists returned for arbitrary SNI
values), or — in rarer misconfigurations — serve the wrong tenant's
certificate/content entirely.

### Classification
Low (information disclosure of co-hosted domains) to Medium (content/cert
mismatch).

### Detection & interpretation
- Query the same IP with several different `-servername` values via
  `openssl s_client` and compare which certificate is returned for each —
  an unexpected match reveals co-hosting, a totally wrong cert for a
  legitimate hostname reveals misrouting.

### Remediation
- Configure a proper default/catch-all vhost that doesn't leak other
  tenants' certificate details; ensure default TLS vhost returns a generic
  or the correct certificate, never another customer's.

---

## 4.8 TLS 1.3 0-RTT Replay Risk

### Why test it
TLS 1.3's 0-RTT (zero round-trip time resumption) lets a client send
application data in its very first flight, before the handshake completes —
convenient for performance, but that early data can be replayed by a network
attacker to the server, since there's no fresh handshake randomness backing
it yet.

### Classification
Medium — depends heavily on what the 0-RTT data is used for; replaying an
idempotent GET is low-impact, replaying a non-idempotent state-changing
request (e.g., a purchase or fund transfer) is high-impact.

### Detection & interpretation
- Confirm TLS 1.3 0-RTT is enabled (`testssl.sh` reports `TLS 1.3 early
  data` support), then review server-side application logic for whether
  early-data requests are treated identically to normal requests.

### Remediation
- Either disable 0-RTT, or ensure the application explicitly rejects/limits
  non-idempotent operations delivered via early data (most modern web
  servers expose an early-data flag your app can check).
