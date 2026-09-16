# TLS Security Assessment — Reference Library

Part of the Web Security reference series. This directory covers TLS/SSL security
assessment end-to-end: protocol and cipher analysis, certificate assessment,
configuration review, known CVE-class vulnerabilities, tooling (flag-by-flag),
legally authorized practice targets, and remediation guidance.

## Convention

Every topic in this library follows the same four-part cycle so it can be used
standalone, top to bottom, by one person working alone:

1. **Why test it** — what an attacker gains if the weakness is present, in
   plain business/technical impact terms.
2. **Classification** — severity tier (Critical / High / Medium / Low /
   Informational) with the relevant CVSS/OWASP reference so you can prioritize.
3. **Detection & interpretation** — exact tool output, flags, and fields that
   tell you the weakness is present, plus how to avoid false positives.
4. **Remediation** — practical, config-level fixes (nginx/Apache/HAProxy/CDN),
   ordered by priority.

## Files

| # | File | Covers |
|---|------|--------|
| 01 | `01-protocol-version.md` | SSL/TLS version detection, deprecated protocols, downgrade protection |
| 02 | `02-cipher-suite-crypto.md` | Cipher enumeration, weak algorithms, PFS, DH/ECC strength |
| 03 | `03-certificate-assessment.md` | Validity, expiry, hostname/SAN, chain, signature, revocation, CT, CAA |
| 04 | `04-tls-configuration-session.md` | HSTS, renegotiation, session resumption, compression, ALPN/SNI, 0-RTT |
| 05 | `05-known-vulnerabilities.md` | Heartbleed, POODLE, BEAST, CRIME, BREACH, FREAK, Logjam, DROWN, ROBOT, Sweet32, Lucky13 |
| 06 | `06-adjacent-realworld-checks.md` | HTTP→HTTPS enforcement, mixed content, pinning, CDN/LB termination, MITM scenario |
| 07 | `07-tooling-guide.md` | testssl.sh, sslyze, sslscan, nmap ssl scripts, openssl s_client, SSL Labs — flag-by-flag |
| 08 | `08-practice-platforms-legal.md` | Where you can legally/safely practice each check — own-lab vs reference-only |
| 09 | `09-portswigger-lab-mapping.md` | Honest gap disclosure — what PortSwigger covers for TLS and what it doesn't |

## Scope note

This library assumes testing against targets you own, a self-built lab, or a
target you hold written authorization to test. Section 08 is written
specifically to keep that boundary clear per check.
