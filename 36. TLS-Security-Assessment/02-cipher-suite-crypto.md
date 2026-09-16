# 02 — Cipher Suite & Cryptography Assessment

## 2.1 Supported Cipher Suite Enumeration

### Why test it
The cipher suite negotiated determines the actual algorithms used for key
exchange, bulk encryption, and integrity for that session. A server can run
TLS 1.2 and still offer a suite that's trivially broken if its cipher list
wasn't curated. Enumeration is the baseline every other check in this section
builds on.

### Classification
Informational by itself (it's a listing); severity is assigned per-cipher in
the following subsections.

### Detection & interpretation
- `nmap --script ssl-enum-ciphers -p 443 target` lists every cipher per
  protocol version with an letter grade (A–F) per Nmap's own scoring.
- `testssl.sh` lists ciphers grouped by protocol and flags each as `offered`
  with a strength label (`WEAK`, `NULL`, `LOW`, `MEDIUM`, `STRONG`).
- Order matters: also record the *server's preferred order*, not just which
  ciphers are offered — a strong cipher offered but not preferred still
  allows negotiation of the weak one (see 2.4).

---

## 2.2 Weak/Deprecated Cryptographic Algorithms

### Why test it
RC4, DES, 3DES, and hash algorithms MD5/SHA1 (when used in the cipher
suite's MAC or the certificate signature) all have practical, published
attacks that reduce effective security far below the advertised key length.

### Classification
| Algorithm | Context | Severity |
|---|---|---|
| RC4 | Any cipher suite | High (biases in keystream, RC4 NOMORE attack) |
| DES / single-DES | Any | Critical (56-bit effective key) |
| 3DES | Bulk cipher | Medium-High (Sweet32 birthday attack, 64-bit block) |
| MD5 | Cert signature or MAC | Critical |
| SHA1 | Cert signature | High (deprecated by all major browsers since 2017) |

### Detection & interpretation
- `testssl.sh` flags each weak cipher/algorithm inline with a colored
  `VULNERABLE` or `WEAK` marker next to the specific cipher name.
- `openssl ciphers -v 'RC4'` (or `'DES'`, `'3DES'`) against the server's
  actual negotiated list confirms whether the weak family is genuinely
  reachable, not just theoretically supported by the library.

### Remediation
- Restrict cipher suites explicitly rather than relying on defaults, e.g.
  nginx: `ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:...';`
  with `ssl_prefer_server_ciphers on;`
- Re-issue any certificate still signed with MD5/SHA1.

---

## 2.3 NULL Cipher, EXPORT Cipher, Anonymous Key Exchange

### Why test it
- **NULL ciphers** provide authentication/integrity with zero encryption —
  traffic is plaintext on the wire.
- **EXPORT ciphers** are artificially weakened (40/56-bit) suites from 1990s
  US export-control law; they exist purely as a downgrade target (FREAK).
- **Anonymous key exchange** (`ADH`/`AECDH`) skips certificate authentication
  entirely, making MITM trivial with no certificate warning shown to the
  client in some implementations.

### Classification
Critical for all three — each collapses a core TLS guarantee (confidentiality
or authentication) entirely, not just weakens it.

### Detection & interpretation
- `testssl.sh -e` (or `--each-cipher`) surfaces NULL/EXPORT/anon ciphers
  explicitly by name (`NULL-SHA`, `EXP-RC4-MD5`, `ADH-AES256-SHA`, etc.).
- Any of these appearing as `offered` — regardless of whether they're
  preferred — is a finding; they should not be present at all.

### Remediation
- Explicitly exclude with `!NULL:!EXPORT:!ADH:!AECDH` in the cipher string,
  in addition to only whitelisting strong suites (belt-and-suspenders).

---

## 2.4 Cipher Ordering / Preference Issues

### Why test it
If the server lets the *client* pick the cipher (`ssl_prefer_server_ciphers
off` or equivalent), a MITM who can manipulate the ClientHello (or a
malicious/outdated client) can force negotiation of the weakest mutually
supported cipher, even if strong ciphers are also present in the list.

### Classification
Medium.

### Detection & interpretation
- `testssl.sh` reports `Server Preference` and `Negotiated cipher per
  protocol` — if preference is "not set" or the negotiated cipher for a
  crafted weak-preference ClientHello is a weak suite, that's the finding.
- Manually: send two `openssl s_client` handshakes with reordered
  `-cipher` lists and confirm the server returns different results depending
  on client order — proves the server isn't enforcing its own order.

### Remediation
- Enable server cipher preference and keep the ordered list curated
  strongest-first, with weak entries removed rather than just deprioritized.

---

## 2.5 Perfect Forward Secrecy (PFS) — DHE/ECDHE

### Why test it
Without PFS, a single compromise of the server's long-term private key lets
an attacker decrypt *every past recorded session* to that server. With
DHE/ECDHE, each session uses an ephemeral key, so past traffic stays safe even
if the long-term key is later compromised.

### Classification
High if PFS ciphers are entirely absent; Medium if present but not
preferred over static RSA key exchange.

### Detection & interpretation
- `testssl.sh` has a dedicated `FS` (Forward Secrecy) section listing which
  ciphers support it and whether the server prefers them.
- Static RSA key exchange ciphers (`TLS_RSA_WITH_...`, no DHE/ECDHE in the
  name) being negotiated by default is the finding.

### Remediation
- Prioritize `ECDHE` suites over plain `RSA` key exchange; drop static RSA
  key exchange entirely where legacy client support allows.

---

## 2.6 DH Parameter Strength (Logjam)

### Why test it
Logjam exploits servers using weak, common, or short (≤1024-bit)
Diffie-Hellman parameters for DHE key exchange — precomputation attacks
against widely-reused parameters make breaking the exchange feasible for a
well-resourced attacker (originally demonstrated against common 512/768-bit
groups).

### Classification
High.

### Detection & interpretation
- `testssl.sh -O` / the Logjam-specific check reports the DH parameter size
  in bits directly (`DH 1024 bits`, etc.) and flags <2048-bit as weak.
- `openssl s_client -connect host:443 -cipher "EDH"` and inspect the
  `Server Temp Key` line in the output for the group size.

### Remediation
- Use 2048-bit or larger custom DH parameters, or prefer ECDHE (elliptic
  curve) over classic DHE entirely, which sidesteps the issue.

---

## 2.7 Elliptic Curve Selection Strength

### Why test it
Not all named curves offer equivalent security; some older curves have
smaller effective security margins or known concerns (e.g., certain NIST
curves have faced scrutiny over parameter generation transparency).

### Classification
Low-Medium — mostly a hardening/best-practice item rather than an active
exploit path today.

### Detection & interpretation
- `testssl.sh` lists negotiated/supported curves under `Elliptic Curves`.
- Flag very small curves (e.g., `secp160`) if offered; modern deployments
  should center on `secp256r1`/`X25519` and above.

### Remediation
- Restrict curve list to `X25519:secp256r1:secp384r1` or the server
  software's equivalent modern default.

---

## 2.8 Key Exchange Algorithm Assessment (RSA vs DHE vs ECDHE)

### Why test it
This is the summary judgment call across 2.5–2.7: which key exchange family
the server actually settles on in practice, since the individual checks above
can each look fine in isolation while the overall negotiated default is still
weak.

### Classification
Depends on findings feeding into it — treat as a rollup, not a separate
scored item.

### Detection & interpretation
- Cross-reference the `testssl.sh` cipher list output: count how many
  reachable suites use RSA-only key exchange vs DHE vs ECDHE, and confirm
  which one wins under default client behavior (most clients prefer ECDHE
  automatically, so this mainly matters for legacy/custom clients).

### Remediation
- ECDHE as the default recommendation for modern deployments; DHE with
  strong parameters only where ECDHE-incapable clients must be supported.
