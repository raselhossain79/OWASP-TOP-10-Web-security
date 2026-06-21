# Web Application Security — Complete Reference Notes

A structured, from-scratch reference library covering web application security
vulnerability classes, built for hands-on penetration testing practice and aligned with
real-world engagement methodology — not just lab theory.

This repo follows the OWASP Top 10 (2021) as its backbone, with each major vulnerability
class broken into its own directory of detailed, self-contained notes.

---

## Why This Repo Exists

Most public SQLi/XSS/SSRF cheatsheets are either too shallow (just a payload list with
no explanation) or too scattered across blog posts to use as a single reference during
active practice. This repo is built to be the opposite: every technique is explained
mechanically (what the payload/command actually does and why it works), organized by
vulnerability type, and cross-referenced to PortSwigger Web Security Academy labs since
that's the primary practice environment used while building these notes.

Each topic directory follows the same internal structure for consistency:
- An overview/classification file (start here for that topic)
- One file per major sub-type/technique
- A dedicated automation-tool file, where a well-known tool exists for that vuln class
  (e.g. sqlmap for SQL injection, commix for command injection)
- A filter/WAF bypass file, where relevant
- A final cheatsheet + lab-mapping file
- A `README.md` indexing that specific topic's files

---

## Repository Structure

```
.
├── README.md                          ← you are here (repo-wide index)
├── SQLi_Notes/                        ← SQL Injection (complete)
├── XSS_Notes/                         ← Cross-Site Scripting (complete, if added as its own folder)
├── Command_Injection_Notes/
├── NoSQL_Injection_Notes/
├── SSTI_Notes/
├── XXE_Notes/
├── LDAP_Injection_Notes/
├── CRLF_Injection_Notes/
├── Insecure_Deserialization_Notes/
├── Broken_Access_Control_Notes/
├── Cryptographic_Failures_Notes/
├── Insecure_Design_Notes/
├── Security_Misconfiguration_Notes/
├── Vulnerable_Components_Notes/
├── Auth_Failures_Notes/
├── Integrity_Failures_Notes/
├── Logging_Monitoring_Failures_Notes/
└── SSRF_Notes/
```

> Folder names above are suggested — use whatever naming convention you actually create
> each directory with; just keep the table below updated to match.

---

## Topic Index & Status

| Folder | OWASP Mapping | Status |
|---|---|---|
| `SQLi_Notes/` | A03:2021 – Injection | ✅ Complete |
| `XSS_Notes/` | A03:2021 – Injection | ✅ Complete |
| `Command_Injection_Notes/` | A03:2021 – Injection | ⬜ Planned |
| `NoSQL_Injection_Notes/` | A03:2021 – Injection | ⬜ Planned |
| `SSTI_Notes/` | A03:2021 – Injection | ⬜ Planned |
| `XXE_Notes/` | A05:2021 – Security Misconfiguration | ⬜ Planned |
| `LDAP_Injection_Notes/` | A03:2021 – Injection | ⬜ Planned |
| `CRLF_Injection_Notes/` | A03:2021 – Injection | ⬜ Planned |
| `Insecure_Deserialization_Notes/` | A08:2021 – Software and Data Integrity Failures | ⬜ Planned |
| `Broken_Access_Control_Notes/` | A01:2021 | ⬜ Planned |
| `Cryptographic_Failures_Notes/` | A02:2021 | ⬜ Planned |
| `Insecure_Design_Notes/` | A04:2021 | ⬜ Planned |
| `Security_Misconfiguration_Notes/` | A05:2021 | ⬜ Planned |
| `Vulnerable_Components_Notes/` | A06:2021 | ⬜ Planned |
| `Auth_Failures_Notes/` | A07:2021 | ⬜ Planned |
| `Integrity_Failures_Notes/` | A08:2021 | ⬜ Planned |
| `Logging_Monitoring_Failures_Notes/` | A09:2021 | ⬜ Planned |
| `SSRF_Notes/` | A10:2021 | ⬜ Planned |

Update the status column as each topic directory gets built out.

---

## How To Use This Repo

**If you're me, continuing this later:**
1. Check the status table above for what's left.
2. Each unbuilt topic has a ready-to-paste prompt saved separately
   (`Remaining_Topics_Prompts.md`) — copy it into a new chat to build that folder.
3. Once a topic folder is complete, update its status here and commit.

**If you're reviewing for study/revision:**
1. Pick a topic folder.
2. Open that folder's own `README.md` first — it explains that topic's specific file
   breakdown and recommended reading order.
3. Use the final cheatsheet file in each folder as quick reference during active lab
   practice; use the detailed files when you need to understand *why* something works.

**If you're someone else browsing this repo:**
These notes assume familiarity with HTTP fundamentals and basic web app structure. They
go deep on mechanism (what each payload/command does, not just that it works) because
that's the standard this repo is held to throughout — every file explains the "why,"
not just the "what."

---

## Conventions Used Throughout This Repo

- All notes are written in English only.
- Every command or payload is broken down piece by piece (flags, parameters, syntax
  explained) — nothing is presented as a "just run this" black box.
- Each topic's exploitation techniques are mapped to PortSwigger Web Security Academy
  labs wherever a matching lab exists, since that's the primary hands-on practice
  environment.
- Every topic folder includes real-world engagement notes — common mistakes, what shows
  up in actual client environments vs. clean lab environments, and report-writing
  considerations — not just theoretical exploitation steps.
- Where an established automation tool exists for a vulnerability class (sqlmap, commix,
  ysoserial, etc.), that tool gets its own dedicated file at the same depth as the
  manual techniques — understand the manual mechanism first, then the tool.

---

## Disclaimer

These notes are for authorized security testing and educational purposes only — use
only against systems you own or have explicit written permission to test (PortSwigger
Web Security Academy labs, your own lab environments, or authorized client engagements
within defined scope).
