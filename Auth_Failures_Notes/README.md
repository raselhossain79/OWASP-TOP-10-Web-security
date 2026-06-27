# OWASP A07:2021 — Identification and Authentication Failures

Comprehensive offensive security note series covering authentication and session
management failures, mapped to real-world attack patterns and PortSwigger Web
Security Academy labs in their official Academy progression order.

This series follows the same structural conventions as the SQL Injection,
Insecure Deserialization, and other A0x series in this repository: flag-by-flag
command breakdowns, honest lab mapping (no fabricated mappings where no lab
exists), real-world industry framing, and full English output.

## File Index

| File | Topic |
|---|---|
| [01_Overview_and_Classification.md](01_Overview_and_Classification.md) | What A07 covers, CWE mapping, failure taxonomy, testing methodology |
| [02_Brute_Force_and_Credential_Attacks.md](02_Brute_Force_and_Credential_Attacks.md) | Credential stuffing, brute force, weak password policy, full Hydra reference, Burp Intruder |
| [03_Rate_Limit_and_Lockout_Bypass.md](03_Rate_Limit_and_Lockout_Bypass.md) | IP rotation, X-Forwarded-For spoofing, lockout/rate-limit detection and evasion |
| [04_Session_Management_Flaws.md](04_Session_Management_Flaws.md) | Session fixation, token predictability/entropy, Burp Sequencer |
| [05_Password_Reset_Vulnerabilities.md](05_Password_Reset_Vulnerabilities.md) | Reset token flaws, host header poisoning, middleware poisoning |
| [06_MFA_Bypass.md](06_MFA_Bypass.md) | 2FA logic flaws, OTP brute force, response manipulation |
| [07_Cheatsheet_and_Lab_Mapping.md](07_Cheatsheet_and_Lab_Mapping.md) | Master checklist + full 14-lab PortSwigger Academy mapping |

## How This Series Is Structured

- Every command shown is broken down flag by flag — what it does and why,
  never "just run this."
- PortSwigger lab references are listed in the **exact order they appear in
  the Authentication topic of the Web Security Academy** (Apprentice →
  Practitioner → Expert), not grouped by theme.
- Where no PortSwigger lab exists for a real-world technique (e.g., classic
  session fixation, raw token-entropy analysis), this is stated explicitly
  rather than forcing a mapping that doesn't exist.
- Real-world notes are included in every file to connect lab-based learning
  to how these failures actually appear in production systems and bug bounty
  programs.

## Scope Reference: OWASP A07:2021

A07:2021 — Identification and Authentication Failures (formerly A2:2017 —
Broken Authentication) covers failures that let an attacker assume the
identity of another user, temporarily or permanently, including credential
attacks, session handling flaws, and multi-factor authentication weaknesses.

## Companion Series

This series is part of a larger OWASP Top 10 note collection in this
repository, including A01 (Broken Access Control), A02 (Cryptographic
Failures), A03 (Injection — SQLi, XSS, SSTI, XXE, LDAP, NoSQL, OS Command,
CRLF), A04 (Insecure Design), A05 (Security Misconfiguration), A06
(Vulnerable and Outdated Components), and A08 (Insecure Deserialization).
