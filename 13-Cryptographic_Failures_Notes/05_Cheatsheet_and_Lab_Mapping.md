# 05 — Cheatsheet and PortSwigger Lab Mapping

## 1. Quick-Reference Cheatsheet

### Hash fingerprinting

| Observation | Likely algorithm |
|---|---|
| 32 hex chars | MD5 |
| 40 hex chars | SHA1 |
| 64 hex chars | SHA256 |
| Starts `$2a$`/`$2b$`/`$2y$` | bcrypt |
| Starts `$argon2` | Argon2 |
| Same hash repeats across different users | No salt in use |

### JWT triage, in order

1. Decode header + payload (no attack) — check `alg`, check for `exp`
2. Try `alg: none` with empty signature
3. Try known/default secrets against HS256 signature (jwt_tool `-C` / hashcat `-m 16500`)
4. Check for `jwk`, `jku`, `kid` parameters in header — test injection if present
5. If a JWKS endpoint exists, test RS256→HS256 algorithm confusion

### TLS triage, in order

1. Run full default `testssl.sh` scan
2. Confirm no SSLv2/SSLv3/TLS1.0/1.1 support
3. Confirm no NULL/export/RC4/anonymous ciphers
4. Confirm certificate is valid, correctly chained, not self-signed in production, and
   not signed with SHA1
5. Confirm no mixed content on HTTPS pages

### Secrets hunting quick commands

```bash
# Search a cloned repo's full history, not just current files
trufflehog git file:///path/to/repo

# Search client-side JS for likely secret patterns
grep -EnoR "(api[_-]?key|secret|token|bearer)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]" ./js-bundles/
```

### hashcat mode quick-reference (most relevant to this series)

| Mode | Algorithm |
|---|---|
| `0` | Raw MD5 |
| `100` | Raw SHA1 |
| `1400` | Raw SHA256 |
| `3200` | bcrypt |
| `16500` | JWT (HS256/384/512) |

---

## 2. PortSwigger Web Security Academy — Lab Mapping

PortSwigger does not have a single "Cryptography" topic the way it has "SQL injection" or
"Cross-site scripting." The crypto-relevant labs are split across the **Authentication**
topic and the dedicated **JWT** topic. Below, labs are listed **in the exact order they
appear within their respective topic**, which is the Academy's intended difficulty
progression — not grouped by theme.

### Authentication topic → "Other authentication mechanisms" section

| Order | Lab | Difficulty | Technique tested | Maps to |
|---|---|---|---|---|
| 1 | **Brute-forcing a stay-logged-in cookie** | Practitioner | Cookie built from `base64(username:md5(password))` with no salt — poor entropy, crackable via Burp Intruder payload processing or hashcat | File 02 §1, §5 |
| 2 | **Offline password cracking** | Practitioner | XSS used to exfiltrate a victim's stay-logged-in cookie, then the embedded MD5 password hash is cracked offline | File 02 §1, §5 |

### JWT topic

| Order | Lab | Difficulty | Technique tested | Maps to |
|---|---|---|---|---|
| 1 | **JWT authentication bypass via unverified signature** | Apprentice | Server doesn't verify the signature at all | File 03 §2 |
| 2 | **JWT authentication bypass via flawed signature verification** | Apprentice | `alg: none` accepted by flawed verification logic | File 03 §2 |
| 3 | **JWT authentication bypass via weak signing key** | Apprentice | Brute-forceable HMAC secret | File 03 §3 |
| 4 | **JWT authentication bypass via jwk header injection** | Practitioner | Server trusts an attacker-embedded `jwk` public key | File 03 §4.1 |
| 5 | **JWT authentication bypass via jku header injection** | Practitioner | Server fetches verification key from an attacker-controlled `jku` URL | File 03 §4.2 |
| 6 | **JWT authentication bypass via kid header path traversal** | Practitioner | `kid` parameter used unsafely in a filesystem lookup | File 03 §4.3 |
| 7 | **JWT authentication bypass via algorithm confusion** | Expert | RS256→HS256 confusion using an exposed public key | File 03 §5 |
| 8 | **JWT authentication bypass via algorithm confusion with no exposed key** | Expert | Same confusion attack, public key derived mathematically from two observed tokens (`sig2n`) instead of being directly exposed | File 03 §5 |

### Honest coverage gap — no Academy lab exists for these techniques

| Technique | Where it's covered in this series | Why no lab |
|---|---|---|
| Padding oracle attacks | File 02 §4 | Requires a stateful repeated-query oracle loop that doesn't fit the Academy's single-flag lab format; this is a real-world/tooling skill (PadBuster, Burp extensions), not a guided lab exercise |
| Hardcoded secrets discovery | File 02 §2 | Recon/OSINT-style technique (repo history, JS bundles, decompiled binaries) rather than a single exploitable server-side bug — not suited to the Academy's lab structure |
| Weak key generation / weak randomness (general) | File 02 §3 | Partially demonstrated indirectly through the two Authentication labs above (poor cookie entropy), but there is no standalone lab purely about CSPRNG misuse outside that context |
| Missing/weak TLS configuration | File 04 | Entirely a network/config-layer skill tested with external tooling (testssl.sh) against live infrastructure — not something the Academy's lab format (a single web app target) is designed to simulate |

This gap is intentional to call out explicitly: claiming PortSwigger lab coverage for
techniques that don't have a matching lab would misrepresent what hands-on practice is
actually available for them. Where no lab exists, the realistic substitute is running
the relevant real-world tool (hashcat, jwt_tool, testssl.sh, trufflehog) against your own
deliberately-misconfigured test environment, or against intentionally vulnerable
practice targets built for that purpose (e.g., DVWA, a local Docker container with a
known-weak TLS config).

---

## 3. Final Reporting Checklist For This Category

When writing up a Cryptographic Failures finding, confirm the report includes:

- [ ] The specific **algorithm/protocol/mechanism** identified, not just "weak crypto"
- [ ] The **CWE number** (see file 01 §3) for traceability against compliance frameworks
- [ ] Proof of exploitation appropriate to the finding (cracked hash, forged token,
      testssl.sh scan output) — not just "this looks weak"
- [ ] The **downstream impact**, stated in business terms (full auth bypass, account
      takeover, mass credential exposure) rather than only the technical mechanism
- [ ] A **root-cause-level remediation** (e.g., "migrate to bcrypt/Argon2 with proper
      salting," "pin JWT verification to expect only RS256 and reject `alg` values from
      the token header," "disable TLS 1.0/1.1 and RC4 cipher suites server-side") instead
      of only "fix the specific cracked password" or "rotate this one secret" — since the
      underlying design flaw will keep producing new instances of the same finding until
      it's actually changed.
