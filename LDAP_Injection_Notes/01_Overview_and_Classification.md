# LDAP Injection — Overview & Classification

## 1. Where This Sits in OWASP Top 10 (2021)

LDAP Injection falls under **A03:2021 — Injection**, the same parent category as SQL Injection, NoSQL Injection, OS Command Injection, SSTI, and XXE. The shared root cause across all of these is identical: **untrusted input is concatenated into a query/command language without proper escaping or parameterization**, and the interpreter (in this case, an LDAP directory server) cannot distinguish attacker-supplied control characters from legitimate query structure.

- **CWE-90**: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
- **Classification context**: LDAP Injection is structurally closer to XPath Injection than to SQL Injection, because LDAP filters use **prefix (Polish) notation** with parentheses, not infix notation with quotes. This single fact changes almost every exploitation primitive you're used to from SQLi — there is no `OR 1=1`-style universal bypass, and that distinction is covered in detail in file 04.

## 2. What LDAP Actually Is (Minimum You Need to Pentest It)

LDAP (Lightweight Directory Access Protocol) is a protocol for reading and writing data in a **directory service** — a hierarchical database optimized for lookups, not transactional writes. Real-world directory services that speak LDAP:

- **Microsoft Active Directory** — by far the most common target in corporate engagements. Almost every internal AD pentest engagement touches LDAP somewhere (user search portals, self-service password reset, helpdesk lookup tools, SSO backends).
- **OpenLDAP** — common in Linux-centric environments, VPN auth backends, and legacy intranet portals.
- **389 Directory Server, ApacheDS, Novell eDirectory, IBM Tivoli Directory Server** — less common but still seen in enterprise/government environments.

A directory stores **entries**, each identified by a **Distinguished Name (DN)**, e.g.:

```
cn=John Smith,ou=Marketing,dc=corp,dc=example,dc=com
```

Each entry has **attributes** (`cn`, `sn`, `uid`, `mail`, `memberOf`, `userPassword`, `objectClass`, etc.). Applications query the directory using **LDAP search filters** — this is the injection point.

## 3. The Injection Point — Where Web Apps Touch LDAP

In a typical engagement, you'll find LDAP injection candidates in:

| Feature | Why it's LDAP-backed |
|---|---|
| Corporate login pages / SSO portals | Authenticate against AD/LDAP instead of a local SQL `users` table |
| Employee/staff directory search ("find a colleague") | Searches `cn`, `mail`, `department` attributes directly |
| Self-service password reset | Looks up the account by username/email before triggering reset |
| Helpdesk / IT admin internal tools | Search by username, employee ID, OU |
| VPN and remote access portals | Many corporate VPN appliances bind to AD over LDAP for auth |
| Address book / contact lookup features in groupware | Same pattern as staff directory search |

The common thread: **any feature that says "look up a user/object by some attribute" is a candidate**, exactly the way any feature that says "fetch a row by some column" is a SQLi candidate.

## 4. The Four Technique Families (and how this series is split)

This series mirrors how real assessments actually unfold — you typically progress through these in order:

1. **Filter Sanitization Bypass & Evasion** (file 03) — before any technique below can be attempted against a defended input, you often need to get past filtering that blocks or strips `* ( ) \` and NUL. Covers identifying the defense type in use and the realistic evasion (or honest non-evasion) for each.
2. **Authentication Bypass via LDAP Filter Manipulation** (file 04) — manipulating the filter used during a bind/search-then-bind login flow to authenticate without valid credentials, or to authenticate as an arbitrary user.
3. **Blind LDAP Injection** (file 05) — when the application doesn't reflect query results directly (no error messages, no visible search output), you infer attribute values one character/bit at a time using true/false response differences — directly analogous to blind SQLi, but using LDAP's prefix-notation boolean operators instead of `AND`/`OR` infix logic.
4. **Data Extraction via LDAP Search Filters** (file 06) — when results ARE reflected (e.g., a staff directory search), abusing wildcards and filter logic to enumerate attributes and dump directory contents beyond what the feature was designed to expose.

A fifth file (07) covers **manual exploitation methodology and tooling** — because, unlike SQL injection, this vulnerability class has no dominant automated exploitation tool, and that fact changes your entire workflow.

## 5. Tooling Reality Check — There Is No sqlmap-Equivalent

This is an explicit, important note for anyone coming from the SQL Injection series: **there is no widely-adopted, actively maintained, sqlmap-equivalent automation framework for LDAP injection.**

What exists instead:

- **`ldapsearch`** (OpenLDAP client utility) — useful for *legitimate* LDAP querying once you have valid creds/anonymous bind, but it does not perform injection/fuzzing on a web app's HTTP parameters. It's a directory query client, not a web exploitation tool.
- **Burp Suite Intruder / Repeater** — this is the actual primary exploitation tool for LDAP injection in real engagements. Filter-manipulation payloads are short, the response differences are binary (true/false), and Intruder's payload-position + grep-match workflow is sufficient to automate blind extraction character-by-character. This is covered in depth in file 07.
- **Custom Python scripts** — for blind boolean-based extraction loops (iterating the alphabet against a true/false oracle), most working pentesters write a short, purpose-built script rather than reach for a general framework. A reusable template is provided in file 07.
- A handful of abandoned/proof-of-concept GitHub repos exist (search "LDAP injection fuzzer") but none has the community adoption, reliability, or breadth of sqlmap, NoSQLMap, tplmap, or commix. **Do not put one of these on your resume or claim tool proficiency you can't defend in an interview** — for LDAP injection, the defensible, industry-recognized skill is *manual filter manipulation via Burp*, not tool operation.

**Bottom line for your methodology**: treat LDAP injection as a **manual, logic-driven technique**, the way blind SQLi was before sqlmap matured. Your value as a tester here is understanding the filter grammar (file 02) well enough to hand-craft and adapt payloads against whatever filter structure the backend is using — which you usually can't see.

## 6. PortSwigger Web Security Academy — Lab Coverage Note (Read This Before Starting File 04)

Unlike SQL Injection, XSS, NoSQL Injection, OS Command Injection, SSTI, and XXE — each of which has a dedicated Academy topic page with a structured Apprentice → Practitioner → Expert lab progression — **PortSwigger Web Security Academy currently has no dedicated "LDAP Injection" topic or lab category.**

What PortSwigger does have:
- An **"LDAP injection" Scanner issue definition** under their knowledge base (`portswigger.net/kb/issues/00100500_ldap-injection`), which documents CWE-90 and Burp Scanner's detection logic for this issue class — useful as a reference for how Burp Scanner flags it, but it is **not an interactive lab**.
- A 2008 research blog post ("Null byte attacks are alive and well") that discusses LDAP injection conceptually alongside XPath injection — good background reading, not a lab.

**This means there are no PortSwigger Academy labs to map techniques to in this series.** Where the SQLi, XXE, SSTI, and NoSQLi series in your GitHub repo map every technique to a specific Apprentice/Practitioner/Expert lab URL, the LDAP injection files in this series will instead note **"No PortSwigger Academy lab — practice via:"** and point to the closest real alternative for that specific technique. Recommended alternative practice sources (cross-referenced per technique in files 04–06):

- **OWASP WebGoat** — includes a dedicated "LDAP Injection" lesson with a vulnerable directory search lab, closest hands-on equivalent to a PortSwigger-style lab for this class.
- **TryHackMe / HackTheBox** — search for rooms/boxes explicitly tagged LDAP injection; coverage rotates over time, so check current room catalogs rather than relying on a fixed name here.
- **Self-hosted OpenLDAP + a deliberately vulnerable PHP/Python frontend** — because labs are scarce, many testers (including in real OSCP/CTF prep) build a 20-line vulnerable search script against a local OpenLDAP instance to safely practice filter manipulation. A minimal vulnerable app skeleton is included in file 07 for exactly this purpose.

This gap is itself worth remembering for interviews: if asked "have you done LDAP injection on PortSwigger," the accurate, defensible answer is that the Academy doesn't currently offer a dedicated lab track for it, and your hands-on practice came from WebGoat / a self-hosted lab / real engagement exposure — say that plainly rather than implying lab coverage that doesn't exist.

## 7. Real-World Severity & Notable Context

- LDAP injection is frequently rated **High to Critical** when it leads to authentication bypass on a corporate SSO/VPN portal, because the blast radius is "log in as any AD user" — often a direct path to internal network access.
- PortSwigger's own research has documented real LDAP injection vulnerabilities in commercial identity products (e.g., a historical LDAP injection issue in ForgeRock's OpenAM via an unauthenticated OpenID `webfinger` endpoint) — a reminder that this bug class shows up in **identity and access management software itself**, not just bespoke web apps.
- Because LDAP-backed login forms often sit at the network edge (VPN portals, extranet SSO), a successful authentication bypass here can be a pre-auth foothold into an internal AD environment — directly relevant to your AD pentesting track and 4xpl0it Security engagement scope.

## 8. What's Next

Read file `02_LDAP_Filter_Syntax_Reference.md` before touching any payload file — every operator and wildcard used in files 04–06 is explained there first, and those files assume you understand the grammar rather than re-deriving it each time. If your target filters or blocks special characters, read file `03_Filter_Bypass_and_Evasion.md` next, before files 04–06; otherwise proceed straight to file 04.
