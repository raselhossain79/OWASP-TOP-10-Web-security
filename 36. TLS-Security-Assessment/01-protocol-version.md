# 01 — Protocol & Version Assessment

## 1.1 TLS/SSL Version Detection

### Why test it
A server's supported protocol versions define the entire security ceiling of
the connection — every cipher, every handshake property, every mitigation
downstream depends on which protocol version actually gets negotiated. If a
server still accepts SSLv2, SSLv3, TLS 1.0, or TLS 1.1, an attacker who can
influence the handshake (or simply a passive observer, for the oldest
protocols) can force or witness a connection that has known, publicly
documented cryptographic breaks.

### Classification
| Protocol | Severity if enabled |
|---|---|
| SSLv2 | Critical |
| SSLv3 | Critical (POODLE) |
| TLS 1.0 | High (PCI DSS non-compliant since 2018) |
| TLS 1.1 | Medium-High (deprecated by all major browsers/RFC 8996) |
| TLS 1.2 | Acceptable (baseline) |
| TLS 1.3 | Best practice |

### Detection & interpretation
- `testssl.sh` prints a `Protocols` block; any line showing `SSLv2`, `SSLv3`,
  `TLS 1.0`, or `TLS 1.1` as `offered` (not `not offered`) is a finding.
- `openssl s_client -connect host:443 -ssl3` (or `-tls1`, `-tls1_1`) — if the
  handshake completes instead of erroring out, that protocol is accepted.
- False-positive note: some scanners flag TLS 1.0/1.1 as "offered" when the
  server only supports them for legacy client compatibility behind a WAF that
  actually terminates modern TLS in front — verify at the edge that actually
  faces the internet, not an internal re-encryption hop.

### Remediation
- nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
- Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`
- HAProxy: `ssl-min-ver TLSv1.2` in the bind line.
- Priority: disable SSLv2/SSLv3 immediately (no legitimate client needs them);
  phase out TLS 1.0/1.1 after confirming no legacy client dependency.

---

## 1.2 Weak/Deprecated Protocol Identification

### Why test it
Distinct from raw version detection, this is about confirming *why* an old
version is dangerous in your specific deployment — e.g., a legacy
load-balancer terminating TLS 1.0 for an internal-only service still exposes
that weakness if the service is reachable from a broader network segment than
assumed.

### Classification
High — inherited from whichever protocol is deprecated, but treated
separately here because the fix is often architectural (decommission a
legacy component) rather than a one-line config change.

### Detection & interpretation
- Map every TLS-terminating component in the path (CDN, WAF, load balancer,
  origin) individually — `testssl.sh` against the public IP only tells you
  about the outermost layer.
- Look for mismatches: edge shows TLS 1.3 only, but origin-to-edge or
  origin-to-origin (microservice mesh) still runs TLS 1.0.

### Remediation
- Inventory every TLS endpoint in the request path, not just the
  internet-facing one.
- Retire hardware/software that cannot support TLS 1.2+ rather than
  special-casing it.

---

## 1.3 Downgrade Attack Protection (TLS_FALLBACK_SCSV)

### Why test it
`TLS_FALLBACK_SCSV` is a signaling cipher suite value that tells a server
"this connection is a fallback retry, not the client's real first choice." If
absent, a network attacker can force repeated handshake failures until both
sides fall back to an older, weaker protocol version — this is the mechanism
that made POODLE practically exploitable against SSLv3 even when a server
supported TLS as well.

### Classification
Medium — mitigating control, not a vulnerability by itself, but its absence
converts a "supports one weak protocol" finding into "can be coerced into the
weak protocol even when a strong one is preferred."

### Detection & interpretation
- `testssl.sh` reports `TLS_FALLBACK_SCSV` support explicitly as
  `Downgrade attack prevention`.
- Interpret `not supported` as a finding only in combination with at least one
  weak protocol being enabled — if only TLS 1.2/1.3 are offered, there is
  nothing to downgrade to, so this becomes informational.

### Remediation
- Update TLS library/server software — SCSV support is a software version
  issue, not a config toggle, in most stacks (OpenSSL ≥1.0.1j, current
  nginx/Apache builds already include it).

---

## 1.4 Protocol Downgrade Attacks: POODLE, FREAK, DROWN

### Why test it
These are named, weaponized exploits that rely on protocol-level weaknesses
rather than implementation bugs, meaning they affect any server exposing the
underlying condition regardless of vendor.

| Attack | Mechanism | Impact |
|---|---|---|
| POODLE | SSLv3 CBC padding oracle | Byte-at-a-time plaintext recovery (e.g., session cookies) |
| FREAK | Server accepts export-grade RSA (512-bit) | MITM can factor the key in hours and decrypt traffic |
| DROWN | Same private key reused on a server that still supports SSLv2 | Decrypts modern TLS sessions using the SSLv2 server as an oracle |

### Classification
Critical for all three — each has public tooling and demonstrated real-world
exploitation.

### Detection & interpretation
- `testssl.sh` has dedicated checks: `-U` runs all vulnerability checks
  including POODLE, FREAK, DROWN in one pass; individual flags `-O` (POODLE),
  and cipher-specific export checks cover FREAK.
- DROWN is notable because it can affect a TLS-only server if *any other
  server sharing the same private key/certificate* still runs SSLv2 (e.g., a
  mail server on the same cert). Always check certificate/key reuse across
  services, not just the single host under test.

### Remediation
- POODLE: disable SSLv3 entirely (see 1.1).
- FREAK: disable export cipher suites server-side (see 02).
- DROWN: disable SSLv2 everywhere the private key is used, or issue a
  dedicated certificate for any service that cannot be updated.
