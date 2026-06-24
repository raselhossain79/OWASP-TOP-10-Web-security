# LDAP Injection — Note Series

Part of an OWASP Top 10 (A03:2021 — Injection) note series. Companion series in this repository: SQL Injection, XSS, NoSQL Injection, OS Command Injection, SSTI, XXE Injection.

## Scope

This series covers LDAP Injection (CWE-90) across three technique families, written for real-world web application and Active Directory-adjacent penetration testing:

- Authentication bypass via LDAP filter manipulation
- Blind LDAP injection (boolean-based and error-based extraction)
- Data extraction via LDAP search filters (scope/wildcard abuse, attribute and group-membership enumeration)

Every payload in this series is broken down piece by piece — no payload is presented without an explanation of what each operator, wildcard, or parenthesis placement does and why it works against the LDAP filter grammar (RFC 4515).

## Important Note on Lab Coverage

**PortSwigger Web Security Academy has no dedicated LDAP Injection topic or lab category**, unlike SQL Injection, XSS, NoSQL Injection, OS Command Injection, SSTI, and XXE — each of which has a structured Apprentice → Practitioner → Expert lab progression on the Academy. This is explained in full in file 01, section 6, with recommended alternatives (OWASP WebGoat's LDAP Injection lesson, and a self-hosted OpenLDAP practice lab with setup instructions in file 06).

## Important Note on Tooling

**There is no widely-adopted, sqlmap-equivalent automation tool for LDAP injection.** This is primarily a manual, Burp Suite-driven technique (Repeater for crafting, Intruder for blind boolean extraction), supplemented by short custom Python scripts for bulk extraction. Full detail and a reusable script template in file 06.

## File Index

| # | File | Description |
|---|---|---|
| 01 | `01_Overview_and_Classification.md` | OWASP/CWE classification, what LDAP is, real-world injection points, the three technique families, tooling reality check, PortSwigger lab coverage gap, real-world severity context |
| 02 | `02_LDAP_Filter_Syntax_Reference.md` | RFC 4515 filter grammar, prefix-notation explained, why there's no SQLi-style `OR 1=1` bypass, escaping rules — read before any payload file |
| 03 | `03_Authentication_Bypass.md` | Single-filter bind vs. search-then-bind patterns, full payload breakdowns for login bypass, NOT-based negation abuse |
| 04 | `04_Blind_LDAP_Injection.md` | Establishing a true/false oracle, boolean-based character extraction, error-based blind, why time-based blind is rare for LDAP |
| 05 | `05_Data_Extraction_Search_Filters.md` | Scope/wildcard escape, attribute enumeration, `memberOf`/AD group pivoting through reflected search features |
| 06 | `06_Manual_Exploitation_and_Tooling.md` | Step-by-step manual methodology, Burp Intruder configuration for blind extraction, reusable Python extraction script, self-hosted OpenLDAP lab setup |
| 07 | `07_Cheatsheet.md` | Condensed quick-reference for all of the above, plus a decision tree and defensive notes for reporting |

## Recommended Reading Order

01 → 02 → 03 → 04 → 05 → 06 → 07. File 02 is foundational and is assumed knowledge in every file after it.

## Language

All content is written in English only.
