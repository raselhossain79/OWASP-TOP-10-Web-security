# 05 — PortSwigger Web Security Academy Lab Mapping

## Honest coverage note (read this first)

Unlike SQL Injection, XSS, SSTI, XXE, and LDAP Injection, **PortSwigger Web
Security Academy does not have a dedicated "Vulnerable and Outdated
Components" topic.** This is expected — A06 is a recon/inventory-and-CVE-research
discipline rather than an injection technique with its own exploit syntax, and
PortSwigger's Academy is structured around exploitable vulnerability classes
with crafted payloads (which is also why your other note series in this
collection map so cleanly to dedicated topics there).

That means this file is structurally different from the lab-mapping sections
in your other series: there is no multi-lab apprentice → practitioner →
expert progression to walk through for A06 specifically. There is exactly
**one lab on the entire Academy that is a direct, practical match** for this
category's core skill (find a version → check it against a known-vulnerability
source → confirm exploitability), and it lives inside the **Information
Disclosure** topic, not under any "components" heading.

## The one direct match

### Lab: Information disclosure in error messages
- **Topic on Academy:** Information Disclosure
- **Difficulty tier:** Apprentice
- **URL:** `portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages`

**Why this lab is the real A06 analog despite living under a different topic
name:** the lab's entire solve path is the A06 workflow in miniature. You
submit unexpected input (a non-integer value) to a parameter, the application
throws an unhandled exception, and the resulting stack trace discloses the
exact backend framework and version (Apache Struts 2, version 2.3.31). To
solve the lab, you take that version string and check it against a known-vulnerability
source (Exploit-DB, in most public walkthroughs) to confirm it corresponds to
a real, exploitable RCE — then submit the version string as the lab's answer.
This is exactly the File 02 → File 04 pipeline in this note series, compressed
into one lab.

What it does **not** cover, because no PortSwigger lab does: actually running
a tool like WhatWeb/Wappalyzer/Nmap against the target (the version is handed
to you via the error message, not fingerprinted with a scanner), running
Retire.js/OWASP Dependency-Check, or any dependency-tree-level analysis. Those
are real-world/tooling skills this series teaches that simply have no lab
equivalent on the Academy.

## Where to practice the parts PortSwigger doesn't cover

Since the Academy's coverage stops at "read a version out of an error
message," round out your practice elsewhere for the tooling-heavy parts of
this category:

- **WhatWeb / Wappalyzer / Nmap version detection** — practice against
  intentionally vulnerable VM sets designed for full-stack recon, such as
  OWASP's own **VWA** (vulnerable VM projects), **HackTheBox** machines
  tagged for outdated-software/CVE-exploitation paths, or a self-hosted
  deliberately old version of a real CMS/framework (e.g. an old WordPress or
  Apache Struts release) in an isolated lab VM.
- **Retire.js / OWASP Dependency-Check** — practice against **OWASP
  Juice Shop** or **OWASP WebGoat**, both of which intentionally ship
  outdated/vulnerable JS dependencies and are explicitly designed as SCA
  practice targets, or against any open-source project's older Git tag where
  you know a since-patched CVE exists.
- **NVD / Exploit-DB research workflow** — this doesn't need a lab at all;
  practice it directly by picking any well-known historical CVE (Log4Shell,
  the Equifax Struts CVE, a recent CVE from this month's NVD feed) and
  walking the full File 04 workflow end-to-end as a dry run, without needing
  a live vulnerable target.

## Suggested practice order

Since there's no Academy difficulty ladder to follow here, a sensible
self-built progression is:

1. Solve the **Information disclosure in error messages** lab itself, since
   it's the one genuine touchpoint — and read at least two of the public
   write-ups solving it differently (some use Exploit-DB/searchsploit, some
   use a plain Google search) to see both research paths in practice.
2. Stand up Juice Shop or WebGoat locally and run Retire.js / OWASP
   Dependency-Check against them, comparing your tool output to their known
   documented vulnerabilities.
3. Pick 2–3 historical CVEs (Struts/Equifax, Log4Shell, a recent CMS plugin
   CVE) and do a full NVD + Exploit-DB research workflow dry run on paper for
   each, to build research speed before you need it live on an engagement.
