# Cryptographic Failures — OWASP Top 10 A02:2021

A complete, GitHub-ready technical note series on **Cryptographic Failures**, built to the
same structure and depth as the SQL Injection, XSS, OS Command Injection, NoSQL Injection,
SSTI, XXE, and LDAP Injection series in this account.

This series treats "Cryptographic Failures" the way it is actually treated in industry —
not as a single bug class, but as a **basket category** covering every way that
confidentiality and integrity protections built on cryptography can be broken: weak
algorithms, weak keys, weak randomness, hardcoded secrets, broken transport security, and
implementation-specific flaws like padding oracles and JWT signature bypasses.

---

## File Index

| # | File | Covers |
|---|------|--------|
| 01 | [`01_Overview_and_Classification.md`](01_Overview_and_Classification.md) | What A02:2021 actually is, sub-categories, CWE mapping, real-world breach context, why it replaced "Sensitive Data Exposure" |
| 02 | [`02_Hashing_and_Encryption_Weaknesses.md`](02_Hashing_and_Encryption_Weaknesses.md) | MD5/SHA1 misuse, unsalted/fast password hashing, hardcoded secrets, weak key generation, weak randomness (PRNG vs CSPRNG), padding oracle attacks, **full hashcat usage breakdown** |
| 03 | [`03_JWT_Cryptographic_Attacks.md`](03_JWT_Cryptographic_Attacks.md) | alg:none bypass, weak HMAC secret brute-forcing, jwk/jku/kid header injection, algorithm confusion (RS256→HS256), **full jwt_tool usage breakdown** |
| 04 | [`04_TLS_Transport_Layer_Failures.md`](04_TLS_Transport_Layer_Failures.md) | Missing/weak TLS, weak cipher suites, certificate misconfiguration, protocol downgrade, mixed content, **full testssl.sh usage breakdown** |
| 05 | [`05_Cheatsheet_and_Lab_Mapping.md`](05_Cheatsheet_and_Lab_Mapping.md) | Quick-reference cheatsheet for engagements + PortSwigger Web Security Academy lab mapping in correct difficulty progression order |

---

## How This Series Is Structured

Every file follows the same internal format used across the rest of the note library:

- **What it is** — plain definition, no jargon-first explanations
- **Why it happens** — root cause in code/config, not just "developer made a mistake"
- **Real-world framing** — how this shows up in actual breaches, bug bounty reports, or
  pentest findings, not just CTF-style lab theory
- **Piece-by-piece command breakdown** — every flag of every tool command is explained;
  no command is ever shown as "just run this"
- **PortSwigger lab mapping** — labs are referenced in the order they actually appear in
  the Academy's difficulty progression (Apprentice → Practitioner → Expert), not grouped
  arbitrarily by theme
- **Real-world notes** — a dedicated section in every file connecting the lab-level
  technique to how it plays out against production targets

## Tools Covered In Depth

- **hashcat** — offline hash cracking (file 02)
- **jwt_tool** — JWT structural and cryptographic attacks (file 03)
- **testssl.sh** — TLS/SSL configuration auditing (file 04)

## Scope Note

PortSwigger Web Security Academy does not currently have a single dedicated "Cryptography"
lab category the way it does for SQL injection or XSS. The crypto-relevant labs are spread
across the **Authentication** topic (weak hashing, poor cookie entropy) and the **JWT**
topic (signature and algorithm attacks). TLS misconfiguration, padding oracle attacks, and
hardcoded-secret discovery are **not lab-based on the Academy** — they are real-world /
external-tooling skills. File 05 is explicit about which techniques have a matching lab and
which are covered as professional methodology instead, so nothing here pretends a lab
exists when it doesn't.

## Language Policy

All files in this series are written in full English only. No Bangla or Banglish text
appears anywhere in this repository.
