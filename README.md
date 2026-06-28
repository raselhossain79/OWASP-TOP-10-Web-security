# Web Application Security — Complete Reference Notes

A structured, from-scratch reference library covering web application security
vulnerability classes, built for hands-on penetration testing practice and aligned with
real-world engagement methodology — not just lab theory.

This repo follows the OWASP Top 10 (2021) as its backbone, expanded with additional
topics cross-checked against the OWASP Web Security Testing Guide (WSTG) — the full
penetration testing methodology — since the Top 10 alone misses several common
real-world/bug-bounty categories.

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

## ⭐ Learning Sequence — Read This Before Picking a Topic

This is the order to actually go through the repo, not just an alphabetical folder
list. The order is based on: (1) what you need to understand first for later topics to
make sense, and (2) real-world/bug-bounty frequency — common, learnable-early topics
come before rare, advanced ones.

**Legend for the Focus column:**
- 🔴 **High** — spend real time here; high frequency in real engagements/bug bounty,
  or foundational for later topics
- 🟡 **Medium** — important, but can move faster once the pattern clicks
- ⚪ **Low** — useful to know exists, don't over-invest early; revisit later if a target
  specifically calls for it

| # | Topic | Folder | Status | Focus | Why |
|---|---|---|---|---|---|
| 0 | **Web Fundamentals (prerequisite)** | `Web_Fundamentals_Notes/` | ✅ Complete | 🔴 High | Non-negotiable — every other topic assumes this is already understood |
| 1 | SQL Injection | `SQLi_Notes/` | ✅ Complete | 🔴 High | Most-documented injection class, builds core "find→confirm→exploit" methodology used everywhere else |
| 2 | Cross-Site Scripting | `XSS_Notes/` | ✅ Complete | 🔴 High | Extremely common in real targets; foundation for several later chains (CSRF token theft, session hijacking) |
| 3 | Server-Side Template Injection | `SSTI_Notes/` | ✅ Complete | 🟡 Medium | Direct RCE potential, but rarer to find than SQLi/XSS |
| 4 | XML External Entity Injection | `XXE_Notes/` | ✅ Complete | 🟡 Medium | High impact when found, but increasingly rare due to modern library hardening |
| 5 | LDAP Injection | `LDAP_Injection_Notes/` | ✅ Complete | ⚪ Low | Rare in bug bounty; mainly relevant for internal/enterprise app engagements |
| 6 | OS Command Injection | `Command_Injection_Notes/` | ⬜ Planned | 🔴 High | Direct RCE, common in apps that shell out to system commands |
| 7 | NoSQL Injection | `NoSQL_Injection_Notes/` | ⬜ Planned | 🟡 Medium | Important specifically when the stack is MongoDB/Node.js-based |
| 8 | XPath Injection | `XPath_Injection_Notes/` | ⬜ Planned | ⚪ Low | Niche — only relevant against XML-backed query systems |
| 9 | CRLF / HTTP Header Injection | `CRLF_Injection_Notes/` | ⬜ Planned | 🟡 Medium | Often a stepping stone into cache poisoning/header-based chains |
| 10 | Broken Access Control | `Broken_Access_Control_Notes/` | ⬜ Planned | 🔴 High | **The single most common bug bounty finding category** — IDOR, privilege escalation |
| 11 | Cross-Site Request Forgery | `CSRF_Notes/` | ⬜ Planned | 🟡 Medium | Less common than pre-2020 due to SameSite defaults, but still found and chains well with XSS |
| 12 | Identification & Auth Failures | `Auth_Failures_Notes/` | ⬜ Planned | 🔴 High | Brute force, session flaws, MFA bypass — consistently found in real assessments |
| 13 | Cryptographic Failures | `Cryptographic_Failures_Notes/` | ⬜ Planned | 🟡 Medium | JWT misconfiguration specifically is increasingly common and high-value |
| 14 | Server-Side Request Forgery | `SSRF_Notes/` | ⬜ Planned | 🔴 High | High payout, very common on cloud-hosted modern apps (metadata endpoint abuse) |
| 15 | Host Header Injection / Reset Poisoning | `Host_Header_Injection_Notes/` | ⬜ Planned | 🟡 Medium | Specific but high-impact chain (account takeover via reset link) |
| 16 | HTTP Request Smuggling | `HTTP_Request_Smuggling_Notes/` | ⬜ Planned | 🟡 Medium | High payout when found, but requires the auth/HTTP fundamentals to be solid first |
| 17 | Web Cache Poisoning | `Web_Cache_Poisoning_Notes/` | ⬜ Planned | 🟡 Medium | Pairs naturally with #16; same underlying "unkeyed input" mindset |
| 18 | HTTP Parameter Pollution | `HTTP_Parameter_Pollution_Notes/` | ⬜ Planned | ⚪ Low | Useful technique, rarely a standalone critical finding |
| 19 | File Upload Vulnerabilities | `File_Upload_Vulnerabilities_Notes/` | ⬜ Planned | 🔴 High | Common, direct path to RCE, high real-world frequency |
| 20 | LFI / RFI | `LFI_RFI_Notes/` | ⬜ Planned | 🟡 Medium | Less common than file upload alone, but a strong RCE chain partner |
| 21 | Insecure Deserialization | `Insecure_Deserialization_Notes/` | ⬜ Planned | ⚪ Low | Rare to find, but very high payout (RCE) when it exists — know the concept, don't over-drill |
| 22 | CORS Misconfiguration | `CORS_Misconfiguration_Notes/` | ⬜ Planned | 🟡 Medium | Common finding, moderate severity unless chained with something else |
| 23 | Clickjacking | `Clickjacking_Notes/` | ⬜ Planned | ⚪ Low | Easy to test, but low standalone severity in most programs now |
| 24 | Open Redirect | `Open_Redirect_Notes/` | ⬜ Planned | 🟡 Medium | Low severity alone, but a frequent and valuable chain ingredient (OAuth, phishing) |
| 25 | Client-Side JS Vulnerabilities | `Client_Side_JS_Vulnerabilities_Notes/` | ⬜ Planned | 🟡 Medium | Prototype Pollution/postMessage issues are increasingly common on modern JS-heavy apps |
| 26 | Race Conditions | `Race_Conditions_Notes/` | ⬜ Planned | 🔴 High | High payout, currently trending heavily in bug bounty, fintech/e-commerce especially |
| 27 | Mass Assignment | `Mass_Assignment_Notes/` | ⬜ Planned | 🟡 Medium | Common on API-backed apps specifically |
| 28 | Insecure Design | `Insecure_Design_Notes/` | ⬜ Planned | ⚪ Low | Conceptual/methodology category — useful mindset, not a checklist item |
| 29 | Security Misconfiguration | `Security_Misconfiguration_Notes/` | ⬜ Planned | 🟡 Medium | Quick recon-based wins (exposed configs, default creds) — good for fast, easy bounties |
| 30 | Vulnerable & Outdated Components | `Vulnerable_Components_Notes/` | ⬜ Planned | 🟡 Medium | Easy wins via CVE matching, low technical depth required |
| 31 | Software/Data Integrity Failures | `Integrity_Failures_Notes/` | ⬜ Planned | ⚪ Low | Mostly supply-chain/CI-CD focused — rare in typical bug bounty scope |
| 32 | Security Logging & Monitoring Failures | `Logging_Monitoring_Failures_Notes/` | ⬜ Planned | ⚪ Low | Not directly exploitable — mainly relevant for formal pentest report completeness |
| 33 | Subdomain Takeover & Recon Methodology | `Subdomain_Takeover_Recon_Notes/` | ⬜ Planned | 🔴 High | Recon quality determines everything else you'll find — and takeovers are an easy, high-value win on their own |
| 34 | **Real-World Exploitation & Chaining (capstone)** | `Real_World_Chaining_Notes/` | ⬜ Planned | 🔴 High | Build LAST — this is what turns "I solved labs" into "I can hunt live targets" |
| — | API Security | `API_Security_Notes/` | ⬜ Not yet scoped | — | Planned as a separate effort later — GraphQL, BOLA, API-specific rate limiting, etc. Not part of this sequence yet. |

---

## How To Read the Priority Column in Practice

- **Don't skip a 🔴 to get to a later topic faster** — these are either extremely
  common in real bug bounty/pentest work, or load-bearing for understanding something
  later (Web Fundamentals, SQLi, Access Control, Auth Failures, SSRF, File Upload, Race
  Conditions, Subdomain Takeover/Recon, and the capstone are all 🔴 for a reason).
- **🟡 topics are worth full notes but don't need the same repetition/drilling** — read
  once thoroughly, do a handful of labs, move on. You'll come back to these naturally
  when a real target calls for the specific technique.
- **⚪ topics are "know it exists, recognize the pattern" level** — build the notes for
  completeness (so the reference exists when you need it), but don't block progress on
  mastering these early. Several of these (LDAP, XPath, Insecure Deserialization) are
  genuinely rare to encounter; spending equal time here as on SQLi/Access Control would
  be a poor use of limited study time.

---

## Repository Structure

```
.
├── README.md                                  ← you are here (repo-wide index)
├── Web_Fundamentals_Notes/                    ← START HERE — prerequisite, read first
├── SQLi_Notes/
├── XSS_Notes/
├── SSTI_Notes/
├── XXE_Notes/
├── LDAP_Injection_Notes/
├── Command_Injection_Notes/
├── NoSQL_Injection_Notes/
├── XPath_Injection_Notes/
├── CRLF_Injection_Notes/
├── Broken_Access_Control_Notes/
├── CSRF_Notes/
├── Auth_Failures_Notes/
├── Cryptographic_Failures_Notes/
├── SSRF_Notes/
├── Host_Header_Injection_Notes/
├── HTTP_Request_Smuggling_Notes/
├── Web_Cache_Poisoning_Notes/
├── HTTP_Parameter_Pollution_Notes/
├── File_Upload_Vulnerabilities_Notes/
├── LFI_RFI_Notes/
├── Insecure_Deserialization_Notes/
├── CORS_Misconfiguration_Notes/
├── Clickjacking_Notes/
├── Open_Redirect_Notes/
├── Client_Side_JS_Vulnerabilities_Notes/
├── Race_Conditions_Notes/
├── Mass_Assignment_Notes/
├── Insecure_Design_Notes/
├── Security_Misconfiguration_Notes/
├── Vulnerable_Components_Notes/
├── Integrity_Failures_Notes/
├── Logging_Monitoring_Failures_Notes/
├── Subdomain_Takeover_Recon_Notes/
├── API_Security_Notes/                        ← planned separately, not yet scoped
└── Real_World_Chaining_Notes/                  ← capstone, build LAST
```

> Folder names above are suggested — use whatever naming convention you actually create
> each directory with; just keep the sequence table above updated to match.

---

## Prompt Reference Files

Three reference files contain ready-to-paste prompts for building each remaining topic
in a new chat — keep these saved alongside the repo (not necessarily committed to it):

| File | Covers |
|---|---|
| `Remaining_Topics_Prompts.md` | The 17 OWASP-Top-10-aligned topics (#6–#18 above, plus CSRF and Deserialization) |
| `Additional_WebApp_Pentest_Topics_Prompts.md` | The 14 additional topics found via WSTG cross-check (#19–#33 above) |
| `Updated_Capstone_Prompt.md` | Topic #34 — build LAST, after everything else is done |

`Web_Fundamentals_Notes/` (topic #0) was already built directly as notes rather than a
prompt — it's the only topic in this repo built this way.

---

## How To Use This Repo

**If you're me, continuing this later:**
1. Check the sequence table above for what's next in order (not just what's unchecked
   — the order matters more than the OWASP-numbering used in the prompt files).
2. Each unbuilt topic has a ready-to-paste prompt in one of the three prompt files
   above — copy it into a new chat to build that folder.
3. Once a topic folder is complete, update its status here and commit.

**If you're reviewing for study/revision:**
1. Start with `Web_Fundamentals_Notes/` if it's been a while — even a quick skim
   refreshes the header/cookie/SOP vocabulary used everywhere else.
2. Pick a topic folder, open that folder's own `README.md` first.
3. Use the final cheatsheet file in each folder as quick reference during active lab
   practice; use the detailed files when you need to understand *why* something works.

**If you're someone else browsing this repo:**
Start with `Web_Fundamentals_Notes/` regardless of your background — every later folder
assumes that vocabulary. These notes go deep on mechanism (what each payload/command
does, not just that it works) because that's the standard this repo is held to
throughout — every file explains the "why," not just the "what."

---

## Conventions Used Throughout This Repo

- All notes are written in English only.
- Every command or payload is broken down piece by piece (flags, parameters, syntax
  explained) — nothing is presented as a "just run this" black box.
- Scope for this repo was cross-checked against the OWASP Web Security Testing Guide
  (WSTG) — the full penetration testing methodology — not just the OWASP Top 10 risk
  list, since the Top 10 alone misses several common real-world/bug-bounty categories
  (file upload, request smuggling, race conditions, CORS, recon methodology, etc).
- Each topic's exploitation techniques are mapped to PortSwigger Web Security Academy
  labs wherever a matching lab exists, in the correct difficulty progression sequence
  as they appear on the Academy — not grouped arbitrarily by theme.
- Every topic folder includes real-world engagement notes — common mistakes, what shows
  up in actual client environments vs. clean lab environments, and report-writing
  considerations — not just theoretical exploitation steps.
- Where an established automation tool exists for a vulnerability class (sqlmap, commix,
  ysoserial, etc.), that tool gets its own dedicated file at the same depth as the
  manual techniques — understand the manual mechanism first, then the tool.
- Where a vulnerability class commonly faces WAF/filter-based defenses in the real
  world, a dedicated bypass file or section is included rather than assumed unnecessary.

---

## Disclaimer

These notes are for authorized security testing and educational purposes only — use
only against systems you own or have explicit written permission to test (PortSwigger
Web Security Academy labs, your own lab environments, or authorized client engagements
within defined scope).
