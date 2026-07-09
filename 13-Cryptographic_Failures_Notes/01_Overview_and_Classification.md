# 01 — Overview and Classification: A02:2021 Cryptographic Failures

## 1. What This Category Actually Is

OWASP A02:2021 — Cryptographic Failures is not one vulnerability. It is a **basket
category** for any failure that breaks the confidentiality or integrity of data through
misuse, absence, or weakness of cryptography. The category moved up to #2 in the OWASP
Top 10 2021 list (from "Sensitive Data Exposure" at #3 in 2017) because the OWASP team
re-framed it around **root cause** (broken crypto) instead of **symptom** (data exposed).
Data exposure is the outcome; cryptographic failure is the cause.

This reframing matters for how you write findings in a real pentest report. "Sensitive
data exposure" tells a client *what* leaked. "Cryptographic failure" tells them *why* it
leaked and *what to fix* — the algorithm, the key handling, or the protocol.

## 2. The Sub-Categories Covered In This Series

| Sub-category | Plain description | File |
|---|---|---|
| Weak/broken hashing algorithms | MD5, SHA1, unsalted hashes used for passwords or integrity | 02 |
| Hardcoded secrets | API keys, encryption keys, JWT secrets committed to source or shipped in binaries/configs | 02 |
| Weak key generation / weak randomness | Predictable keys, `Math.random()` or `rand()` used where a CSPRNG is required | 02 |
| Padding oracle attacks | Exploiting verbose decryption error behavior in CBC-mode block ciphers | 02 |
| Missing/weak TLS configuration | No TLS, expired/self-signed certs, weak cipher suites, protocol downgrade | 04 |
| JWT-specific cryptographic flaws | `alg:none`, weak HMAC secrets, jwk/jku/kid injection, algorithm confusion | 03 |

## 3. CWE Mapping

OWASP A02:2021 maps to a wide CWE set. The ones most relevant to web app pentesting:

- **CWE-259** — Use of Hard-coded Password
- **CWE-321** — Use of Hard-coded Cryptographic Key
- **CWE-326** — Inadequate Encryption Strength
- **CWE-327** — Use of a Broken or Risky Cryptographic Algorithm (MD5, SHA1, DES, RC4)
- **CWE-328** — Use of Weak Hash
- **CWE-330** — Use of Insufficiently Random Values
- **CWE-331** — Insufficient Entropy
- **CWE-347** — Improper Verification of Cryptographic Signature (JWT signature bypass)
- **CWE-757** — Selection of Less-Secure Algorithm During Negotiation ("Algorithm Downgrade")

Knowing these CWE numbers matters for report writing — clients and compliance frameworks
(PCI-DSS, ISO 27001) expect findings to be traceable to a CWE/CVSS basis, not just a
narrative description.

## 4. Why This Category Is Different From the Others In This Series

SQL Injection, XSS, SSTI, XXE, LDAP Injection, and Insecure Deserialization are all
**input-handling failures** — untrusted data reaching a sensitive sink. Cryptographic
Failures is different: it is mostly a **design and configuration failure**. There is
usually no single malicious payload that "triggers" it. Instead you are:

- Identifying *that weak crypto is in use at all* (an algorithm name in a header, a JWT
  structure, a TLS handshake response)
- Then exploiting the *mathematical or implementation weakness* of that specific
  primitive (cracking a hash, forging a signature, decrypting via oracle behavior)

This means the "attack surface" for this category is less about fuzzing parameters and
more about **recognizing weak crypto from its fingerprints** — a 32-character hex string
is almost certainly MD5, a JWT header you can read in cleartext is base64 not encryption,
a TLS handshake that completes on TLS 1.0 is a finding by itself.

## 5. Real-World Industry Framing

Cryptographic failures are consistently among the most damaging findings in real breach
reports, specifically because they tend to compromise *everything downstream at once*
rather than a single record:

- **Adobe (2013)** — encrypted (not hashed) passwords using a weak, unsalted block cipher
  in ECB mode, with password hints stored in plaintext alongside them. The ECB mode
  leakage let researchers spot patterns and recover large numbers of passwords without
  ever breaking the cipher itself — a textbook example of CWE-327.
- **LinkedIn (2012)** — unsalted SHA1 password hashes. Once the hash dump leaked, the
  lack of salting meant rainbow tables and GPU cracking recovered the overwhelming
  majority of passwords within days.
- **Numerous bug bounty reports (HackerOne/Bugcrowd, ongoing)** — JWT `alg:none`
  acceptance and weak HMAC secrets remain a recurring high-severity finding category
  across fintech and SaaS targets, frequently rated Critical because they bypass
  authentication entirely rather than leaking one user's data.

The pattern across all of these: cryptographic failures are rarely "find one bug, fix
one bug." They are usually systemic — one weak design decision (an algorithm choice, a
key reused everywhere, a missing salt) silently affects the entire user base.

## 6. How To Approach This Category On An Engagement

1. **Fingerprint the crypto in use** before attacking it. Look at hash lengths and
   charsets, JWT header contents, TLS handshake responses, response timing on
   decryption errors.
2. **Don't assume "encrypted" means "safe."** Confirm the actual primitive, mode, and key
   management. ECB mode, static IVs, and hardcoded keys are common even when an app
   technically "uses encryption."
3. **Treat configuration as the vulnerability, not just code.** A correct algorithm with
   a weak TLS config in front of it is still a cryptographic failure finding.
4. **Chain findings.** A hardcoded JWT secret found in a JS bundle is far more dangerous
   combined with a privilege-escalation claim than reported alone — always state the
   downstream impact (account takeover, full auth bypass) in the report, not just "weak
   secret detected."

Continue to `02_Hashing_and_Encryption_Weaknesses.md` for the hands-on techniques and the
hashcat deep-dive.
