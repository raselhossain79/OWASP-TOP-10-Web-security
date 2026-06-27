# OWASP A06:2021 — Vulnerable and Outdated Components

A GitHub-ready, engagement-focused note series on identifying and verifying
vulnerable or outdated software components during a web application
penetration test. Built in the same structure and depth as the SQL Injection,
XSS, SSTI, XXE, and LDAP Injection series in this repo.

## Why this category is different from the others

A06 is not an injection class with its own payload syntax. It is a
**recon and software-composition-analysis (SCA) problem**. There is no
"exploit string" for A06 itself — the actual exploitation happens through
whatever vulnerability the outdated component contains (which might be SQLi,
RCE, deserialization, XXE, etc., covered in their own series). This series
focuses on the part that is unique to A06: **finding out what software and
what version is running, and proving it is exploitable before you act on it.**

## File Index

| # | File | Purpose |
|---|------|---------|
| 1 | [`01_Overview_and_Methodology.md`](01_Overview_and_Methodology.md) | What A06 is, real breach case studies, end-to-end methodology |
| 2 | [`02_Fingerprinting_Techniques.md`](02_Fingerprinting_Techniques.md) | Manual + tool-based version fingerprinting — WhatWeb, Wappalyzer, Nmap version detection, full flag breakdowns |
| 3 | [`03_Automation_Tools_RetireJS_DependencyCheck.md`](03_Automation_Tools_RetireJS_DependencyCheck.md) | Retire.js and OWASP Dependency-Check — the closest automated equivalents to a "scanner" for this category |
| 4 | [`04_CVE_Research_Workflow.md`](04_CVE_Research_Workflow.md) | NVD and Exploit-DB research workflow, CVSS reading, supply chain risk basics, responsible verification before exploitation |
| 5 | [`05_PortSwigger_Lab_Mapping.md`](05_PortSwigger_Lab_Mapping.md) | Honest lab-coverage mapping for this category on PortSwigger Academy |
| 6 | [`06_Checklist.md`](06_Checklist.md) | Final field checklist for engagements and reports |

## How to use this series

1. Read `01` for the mental model and methodology before touching tools.
2. Use `02` and `03` side by side during recon — `02` is for manual/semi-automated
   fingerprinting, `03` is for dependency-level automated scanning.
3. Use `04` every time a version number turns up — it is the bridge between
   "I found a version" and "I can prove this is exploitable."
4. Use `05` to know what limited hands-on practice PortSwigger Academy offers
   for this category, and where to go instead.
5. Use `06` as a pre-report / pre-engagement gate check.

## Scope note

This series assumes a black-box or grey-box web application penetration test
context. It does not cover internal supply-chain/SBOM tooling for software
vendors (e.g., building your own SBOM pipeline) in depth — that is a separate,
larger DevSecOps topic. The supply chain material here is scoped to what a
pentester needs to reason about during an engagement.
