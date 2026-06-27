# Remaining Security Topics — Checklist & Ready-to-Paste Prompts

SQLi and XSS are already done. This file covers everything left, grouped into 3 simple
buckets. For each topic there's a ready-to-paste prompt — just copy the whole block into
a new chat, no editing needed.

**Important fix added to every prompt below:** every command in these notes must be
broken down piece by piece (what each flag/parameter does, why it's used) — never just
listed as a raw command to run blindly. This was missing in some of the SQLi notes;
all prompts below now explicitly require it.

---

## GROUP 1 — Injection Family (6 topics)

### [✅] 1. OS Command Injection

```
I'm building a comprehensive, GitHub-ready note series on OS Command Injection — part of 
the OWASP Top 10 Injection category (A03:2021). I already have a similar complete note 
series for SQL Injection and want this one built the same way and depth.

Requirements:
- Cover ALL sub-types: in-band (output visible directly), blind command injection 
  (no output shown), and out-of-band command injection (exfiltration via DNS/HTTP)
- Cover injection via shell metacharacters (;, |, &&, ||, backticks, $()) across both 
  Linux and Windows targets
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, blind techniques, 
  OOB techniques, a filter/WAF bypass file, a dedicated file covering "commix" 
  (the sqlmap-equivalent automation tool for command injection — full usage, flags, 
  and its own WAF/filter bypass options), and a final cheatsheet + lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file (how this shows up in actual engagements, 
  common mistakes, report-writing considerations)
- CRITICAL: every command shown must be broken down line by line — explain exactly 
  what each flag/argument/operator does and why it's there. Never give a command as 
  just "run this" without explaining what it actually does. I need to understand the 
  mechanism, not just copy-paste blindly.

Please plan the file breakdown first, then build each file.
```

### [✅] 2. NoSQL Injection

```
I'm building a comprehensive, GitHub-ready note series on NoSQL Injection (primarily 
MongoDB-style, since that's most common) — part of the OWASP Top 10 Injection category 
(A03:2021). I already have a similar complete note series for SQL Injection and want 
this one built the same way and depth.

Requirements:
- Cover authentication bypass via operator injection ($ne, $gt, $regex, etc), 
  blind NoSQL injection, and JavaScript injection (where()/mapReduce abuse in MongoDB)
- Explain how NoSQL injection differs fundamentally from SQLi (no SQL syntax involved, 
  JSON-based operator manipulation instead) clearly upfront
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy, if matching labs exist
- Break into multiple separate files: overview/classification, exploitation techniques, 
  a filter bypass file, a dedicated file covering "NoSQLMap" (the sqlmap-equivalent 
  automation tool for NoSQL injection — full usage, flags, and limitations compared to 
  sqlmap), and a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command/payload shown must be broken down piece by piece — explain 
  exactly what each operator/parameter does and why. Never give a payload as just 
  "use this" without explaining the mechanism behind it.

Please plan the file breakdown first, then build each file.
```

### [✅] 3. Server-Side Template Injection (SSTI)

```
I'm building a comprehensive, GitHub-ready note series on Server-Side Template Injection 
(SSTI) — part of the OWASP Top 10 Injection category (A03:2021). I already have a similar 
complete note series for SQL Injection and want this one built the same way and depth.

Requirements:
- Cover detection (polyglot payloads like ${{<%[%'"}}%\), identifying the template 
  engine in use (Jinja2, Twig, FreeMarker, Velocity, Smarty, etc), and exploitation 
  paths from basic expression evaluation up to remote code execution per engine
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/detection, engine-by-engine exploitation 
  (at least Jinja2 and Twig in detail since they're most common), a 
  detection-to-RCE escalation file, a dedicated file covering "tplmap" (the 
  sqlmap-equivalent automation tool for SSTI — full usage, flags, and how to interpret 
  its output), and a final cheatsheet + lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every payload/command shown must be broken down piece by piece — explain 
  exactly what each part of the template syntax does and why it triggers code execution. 
  Never give a payload as just "use this" without explaining the mechanism.

Please plan the file breakdown first, then build each file.
```

### [✅] 4. XML External Entity (XXE) Injection

```
I'm building a comprehensive, GitHub-ready note series on XML External Entity (XXE) 
Injection — mapped under OWASP Top 10 Security Misconfiguration (A05:2021) but distinct 
enough to deserve its own note set. I already have a similar complete note series for 
SQL Injection and want this one built the same way and depth.

Requirements:
- Cover classic XXE (file read via external entities), blind XXE (out-of-band 
  exfiltration via DNS/HTTP), XXE via SSRF, and error-based XXE (data leaked through 
  malformed XML error messages)
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, classic/in-band XXE, 
  blind/OOB XXE, a file showing XXE-to-SSRF chaining, a dedicated file covering 
  "XXEinjector" (the closest automation tool equivalent for XXE — full usage, flags, 
  and what it can/can't automate compared to manual XXE), and a final cheatsheet + 
  lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every XML payload shown must be broken down piece by piece — explain what 
  the DOCTYPE declaration, entity definition, and each part of the payload actually does. 
  Never give a payload as just "use this" without explaining the mechanism.

Please plan the file breakdown first, then build each file.
```

### [✅] 5. LDAP Injection

```
I'm building a comprehensive, GitHub-ready note series on LDAP Injection — part of the 
OWASP Top 10 Injection category (A03:2021). I already have a similar complete note 
series for SQL Injection and want this one built the same way and depth.

Requirements:
- Cover authentication bypass via LDAP filter manipulation, blind LDAP injection, 
  and data extraction via LDAP search filters
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy, if matching labs exist (note if this vuln class has limited lab coverage there)
- Break into multiple separate files: overview/classification, exploitation techniques, 
  and a final cheatsheet file
- Note: there is no widely-used sqlmap-equivalent automation tool for LDAP injection — 
  if you find one worth covering, include it, otherwise explicitly note in the overview 
  file that this is primarily a manual/Burp Intruder-driven technique
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every payload shown must be broken down piece by piece — explain exactly 
  what each LDAP filter operator/wildcard does and why. Never give a payload as just 
  "use this" without explaining the mechanism.

Please plan the file breakdown first, then build each file.
```

### [✅] 6. CRLF / HTTP Header Injection

```
I'm building a comprehensive, GitHub-ready note series on CRLF Injection / HTTP Header 
Injection — part of the OWASP Top 10 Injection category (A03:2021). I already have a 
similar complete note series for SQL Injection and want this one built the same way 
and depth.

Requirements:
- Cover HTTP response splitting, header injection leading to cache poisoning, 
  session fixation via injected headers, and log injection
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, exploitation techniques 
  (response splitting, cache poisoning chains), a section/file mentioning "crlfuzz" (a 
  basic CRLF-detection fuzzing tool — lighter than sqlmap-tier but worth knowing), and 
  a final cheatsheet file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every payload shown must be broken down piece by piece — explain exactly 
  what the %0d%0a (CRLF) sequence does in context and why it breaks the parser. 
  Never give a payload as just "use this" without explaining the mechanism.

Please plan the file breakdown first, then build each file.
```

---

## GROUP 2 — Deserialization (1 topic)

### [✅] 7. Insecure Deserialization

```
I'm building a comprehensive, GitHub-ready note series on Insecure Deserialization — 
mapped under OWASP Top 10 Software and Data Integrity Failures (A08:2021) but distinct 
enough to deserve its own note set. I already have a similar complete note series for 
SQL Injection and want this one built the same way and depth.

Requirements:
- Cover deserialization vulnerabilities across PHP (object injection), Java 
  (gadget chains, ysoserial), Python (pickle), and .NET, at a level appropriate for a 
  pentester (not just theory)
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, language-by-language 
  exploitation (PHP, Java, Python, .NET as separate sections or files), a gadget chain 
  concept file, and a final cheatsheet + lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command/payload/tool usage shown must be broken down piece by piece — 
  explain exactly what each part does and why, including any tool flags (e.g. ysoserial 
  usage). Never give a command as just "run this" without explaining what it actually 
  does. I need to understand the mechanism, not just copy-paste blindly.

Please plan the file breakdown first, then build each file.
```

---

## GROUP 3 — Other OWASP Top 10 Categories (9 topics)

### [✅] 8. Broken Access Control (A01:2021)

```
I'm building a comprehensive, GitHub-ready note series on Broken Access Control — 
OWASP Top 10 A01:2021. I already have a similar complete note series for SQL Injection 
and want this one built the same way and depth.

Requirements:
- Cover IDOR (Insecure Direct Object Reference), horizontal and vertical privilege 
  escalation, missing function-level access control, path traversal as an access 
  control issue, and forced browsing
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, IDOR techniques, 
  privilege escalation techniques, a path traversal file, a section/file covering 
  "Autorize" and "AuthMatrix" (Burp extensions that automate access control testing by 
  replaying requests under different user sessions — the closest tool-equivalent for 
  this category), and a final cheatsheet + lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command/request example shown must be broken down piece by piece — 
  explain exactly what's being changed/manipulated and why it bypasses the control. 
  Never give an example as just "try this" without explaining the mechanism.

Please plan the file breakdown first, then build each file.
```

### [✅] 9. Cryptographic Failures (A02:2021)

```
I'm building a comprehensive, GitHub-ready note series on Cryptographic Failures — 
OWASP Top 10 A02:2021. I already have a similar complete note series for SQL Injection 
and want this one built the same way and depth.

Requirements:
- Cover weak/broken algorithms (MD5/SHA1 misuse), hardcoded secrets, weak key 
  generation/randomness, missing/weak TLS configuration, padding oracle attacks, 
  and JWT-specific cryptographic flaws (alg:none, weak secret brute-forcing)
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, hashing/encryption 
  weaknesses (with a dedicated "hashcat" usage section — full flags breakdown, not just 
  commands), JWT attacks specifically (with a dedicated "jwt_tool" usage section), a 
  TLS/transport-layer file (with a dedicated "testssl.sh" usage section), and a final 
  cheatsheet + lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command/tool usage shown (e.g. hashcat, jwt_tool) must be broken down 
  piece by piece — explain exactly what each flag does and why. Never give a command as 
  just "run this" without explaining what it actually does.

Please plan the file breakdown first, then build each file.
```

### [✅] 10. Insecure Design (A04:2021)

```
I'm building a comprehensive, GitHub-ready note series on Insecure Design — 
OWASP Top 10 A04:2021. I already have a similar complete note series for SQL Injection 
and want this one built the same way and depth.

Requirements:
- Cover this as a conceptual/methodology category (unlike SQLi, this isn't a single 
  payload-based attack) — explain business logic flaws, missing rate limiting by design, 
  trust boundary violations, and how to identify design-level flaws during an engagement
- Include real-world example scenarios (e.g. flawed password reset logic, race 
  conditions from design flaws, workflow bypass)
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each concept, 
  in the correct difficulty progression sequence as they appear on the Academy 
  (business logic vulnerabilities labs are most relevant here)
- Break into multiple separate files: overview/concept, business logic flaw categories, 
  a case-study file with real example scenarios, and a final checklist file for 
  identifying insecure design during an engagement
- Note: there is no sqlmap-equivalent automation tool for this category since it's 
  conceptual/manual by nature — no need to force-fit a tool here
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: wherever a request sequence or manipulation example is shown, break it down 
  step by step — explain exactly what's being exploited in the workflow and why it works.

Please plan the file breakdown first, then build each file.
```

### [✅] 11. Security Misconfiguration (A05:2021)

```
I'm building a comprehensive, GitHub-ready note series on Security Misconfiguration — 
OWASP Top 10 A05:2021. I already have a similar complete note series for SQL Injection 
and want this one built the same way and depth. (Note: I'm covering XXE as its own 
separate note series, so this one should focus on the OTHER misconfiguration issues, 
not XXE.)

Requirements:
- Cover default credentials, unnecessary features/services enabled, verbose error 
  messages/stack traces, missing security headers, directory listing exposure, 
  cloud storage misconfiguration (S3 buckets etc), and CORS misconfiguration
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, a security headers file, 
  a CORS misconfiguration file, a cloud/infrastructure misconfiguration file (including 
  a section on "S3Scanner" for cloud storage misconfig), a section/file covering "Nikto" 
  (general misconfiguration scanning — full flags breakdown), and a final cheatsheet + 
  lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command/tool usage shown must be broken down piece by piece — explain 
  exactly what each flag/check does and why. Never give a command as just "run this" 
  without explaining what it actually does.

Please plan the file breakdown first, then build each file.
```

### [✅] 12. Vulnerable and Outdated Components (A06:2021)

```
I'm building a comprehensive, GitHub-ready note series on Vulnerable and Outdated 
Components — OWASP Top 10 A06:2021. I already have a similar complete note series for 
SQL Injection and want this one built the same way and depth.

Requirements:
- Cover identifying outdated software/libraries (version fingerprinting techniques), 
  using CVE databases effectively (NVD, Exploit-DB), supply chain risk basics, and 
  how to responsibly verify a suspected known-vulnerable component during an engagement
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs if any exist, in the correct difficulty progression sequence 
  as they appear on the Academy (note if this category has limited lab coverage 
  there, since it's more recon/methodology-focused)
- Break into multiple separate files: overview/methodology, a fingerprinting techniques 
  file (whatweb, Wappalyzer — full flags breakdown), a dedicated file covering 
  "Retire.js" and "OWASP Dependency-Check" (the closest automation tool equivalents for 
  finding vulnerable components), a CVE-research workflow file, and a final checklist 
  file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command/tool usage shown (e.g. whatweb, wappalyzer, nmap version 
  detection) must be broken down piece by piece — explain exactly what each flag does 
  and why. Never give a command as just "run this" without explaining what it does.

Please plan the file breakdown first, then build each file.
```

### [✅] 13. Identification and Authentication Failures (A07:2021)

```
I'm building a comprehensive, GitHub-ready note series on Identification and 
Authentication Failures — OWASP Top 10 A07:2021. I already have a similar complete 
note series for SQL Injection and want this one built the same way and depth.

Requirements:
- Cover credential stuffing/brute force, weak password policy exploitation, session 
  fixation, session token predictability/weak entropy, multi-factor authentication 
  bypass techniques, and password reset flow vulnerabilities
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, brute force/credential 
  attacks (with a dedicated "Hydra" full usage section — same depth as the sqlmap file 
  in my SQLi series — plus Burp Intruder technique), session management flaws, an MFA 
  bypass file, and a final cheatsheet + lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command/tool usage shown must be broken down piece by piece — explain 
  exactly what each flag/parameter does and why. Never give a command as just "run this" 
  without explaining what it actually does.

Please plan the file breakdown first, then build each file.
```

### [ ] 14. Software and Data Integrity Failures (A08:2021)

```
I'm building a comprehensive, GitHub-ready note series on Software and Data Integrity 
Failures — OWASP Top 10 A08:2021. I already have a similar complete note series for 
SQL Injection and want this one built the same way and depth. (Note: I'm covering 
Insecure Deserialization as its own separate note series, so this one should focus on 
the OTHER integrity issues, not deserialization.)

Requirements:
- Cover insecure CI/CD pipeline risks, unsigned/unverified software updates, 
  dependency confusion attacks, and client-side integrity issues (e.g. unverified 
  CDN-hosted scripts, missing Subresource Integrity)
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs if any exist, in the correct difficulty progression sequence 
  as they appear on the Academy (note if coverage is limited there)
- Break into multiple separate files: overview/classification, supply chain/dependency 
  attack techniques, a CI/CD risk file, and a final checklist file
- Note: there is no single sqlmap-equivalent automation tool for this category — if 
  dependency-confusion-specific tooling is worth mentioning, include it, otherwise keep 
  this manual/methodology-focused
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every command/example shown must be broken down piece by piece — explain 
  exactly what's happening and why it's exploitable. Never give an example as just 
  "do this" without explaining the mechanism.

Please plan the file breakdown first, then build each file.
```

### [ ] 15. Security Logging and Monitoring Failures (A09:2021)

```
I'm building a comprehensive, GitHub-ready note series on Security Logging and 
Monitoring Failures — OWASP Top 10 A09:2021. I already have a similar complete note 
series for SQL Injection and want this one built the same way and depth.

Requirements:
- Cover this from a pentester's perspective: how to identify logging/monitoring gaps 
  during an engagement, log injection techniques, and how this category typically gets 
  evidenced in a pentest report (since it's rarely "exploitable" directly, more of a 
  gap-identification category)
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs if any exist, in the correct difficulty progression sequence 
  as they appear on the Academy (note if coverage is minimal/none, since this 
  category is hard to lab-test directly)
- Break into multiple separate files: overview/concept, a log injection techniques file, 
  and a final checklist file for identifying this gap during an engagement
- Note: there is no automation/exploitation tool equivalent for this category since 
  it's a detection-gap category rather than a directly exploitable one — no need to 
  force-fit a tool here
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: any payload/example shown must be broken down piece by piece — explain 
  exactly what it does and why.

Please plan the file breakdown first, then build each file.
```

### [ ] 16. Server-Side Request Forgery — SSRF (A10:2021)

```
I'm building a comprehensive, GitHub-ready note series on Server-Side Request Forgery 
(SSRF) — OWASP Top 10 A10:2021. I already have a similar complete note series for 
SQL Injection and want this one built the same way and depth.

Requirements:
- Cover basic SSRF (direct), blind SSRF (no response shown), SSRF via URL parsing 
  bypass tricks (IP encoding, redirects, DNS rebinding), and cloud metadata endpoint 
  exploitation (AWS/GCP/Azure metadata services)
- Cover SSRF filter bypass techniques specifically (since SSRF protections are commonly 
  filter-based)
- Real-world industry-standard framing throughout, not just lab theory
- I practice on PortSwigger Web Security Academy — map relevant labs to each technique, in the correct difficulty progression 
  sequence as they appear on the Academy (not just grouped by theme)
- Break into multiple separate files: overview/classification, basic/blind SSRF, 
  a filter bypass techniques file, a cloud metadata exploitation file, a dedicated file 
  covering "SSRFmap" (the sqlmap-equivalent automation tool for SSRF — full usage, 
  modules, and flags) and "Gopherus" (payload generator for SSRF-to-internal-service 
  attacks), and a final cheatsheet + lab mapping file
- Include a README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- Include real-world notes in each file
- CRITICAL: every payload/command shown must be broken down piece by piece — explain 
  exactly what each part of the URL/payload does and why it triggers the bypass. Never 
  give a payload as just "use this" without explaining the mechanism.

Please plan the file breakdown first, then build each file.
```

---

## How to Use This File

1. Pick the next unchecked `[ ]` topic.
2. Open a new chat.
3. Copy the entire code block under that topic and paste it as your first message.
4. After the note series is done in that chat, come back here and check the box.
5. Move to the next topic.

No need to remember anything or write prompts from scratch — every prompt already
includes the command-breakdown requirement so this won't be missed again.


```
I'm building a final, capstone note series called "Real-World Exploitation & Vulnerability 
Chaining" — meant to be read AFTER completing individual vulnerability-type note series 
(SQLi, XSS, SSRF, IDOR, SSTI, etc). This is not about any single vulnerability type — it's 
about the methodology and skills that bridge "I can solve a known PortSwigger lab pattern" 
to "I can adapt to messy, unpredictable real-world targets and bug bounty programs."

Requirements:
- Cover vulnerability CHAINING specifically — combining multiple individually-low-impact 
  bugs into one critical finding. Include real documented chain patterns such as:
  - IDOR + Broken Access Control → full account takeover
  - SSRF + Cloud Metadata + exposed credentials → cloud account compromise
  - Stored XSS + CSRF token theft → full account takeover
  - SQLi + file write → RCE
  - SSTI → RCE
  - Open redirect + OAuth misconfig → account takeover
  - Subdomain takeover + cookie scoping → session hijacking
- Cover how to THINK about chaining: mapping an app's full attack surface first, 
  tracking "low severity" findings instead of discarding them, and looking for where 
  one bug's output becomes another bug's input
- Cover adapting known techniques to unknown/custom situations: how to approach a target 
  with no known CVE or lab-matching pattern, systematic fuzzing methodology, and how to 
  read application behavior to infer what's happening server-side without source code
- Cover a practical end-to-end methodology for live targets: recon → attack surface 
  mapping → low-hanging fruit testing → chaining/escalation → impact documentation, 
  written as something usable on both bug bounty targets and authorized pentest 
  engagements
- Cover common WAF/defense adaptation in real environments (since real-world WAFs behave 
  differently from lab environments — what's actually different and how to test for it)
- Cover report-writing for chained findings specifically (how to document a multi-step 
  chain clearly for a client/program so impact isn't underestimated)
- Real-world industry-standard framing throughout — this file series should read like 
  something written by an experienced bug bounty hunter/pentester, not a lab walkthrough
- Break into multiple separate files:
  1. Overview — what chaining is, why low-severity bugs matter, mindset shift from 
     lab-solving to real-world hunting
  2. Documented real-world chain patterns (the list above, each broken down step by step)
  3. Attack surface mapping methodology for an unfamiliar target
  4. Adapting known techniques to unknown/custom scenarios (fuzzing methodology, 
     behavioral inference without source code)
  5. Real-world WAF/defense behavior and adaptation (how it differs from lab conditions)
  6. End-to-end methodology checklist (recon → mapping → testing → chaining → reporting)
  7. Report-writing guide specifically for chained/multi-step findings
  8. A README.md indexing all files
- Write everything in full English only — no Bangla/Banglish anywhere
- CRITICAL: every example/payload/request sequence shown must be broken down step by 
  step — explain exactly what's happening at each stage of a chain and why it works. 
  Never give a chain example as just "this leads to that" without explaining the 
  mechanism connecting each step.

Please plan the file breakdown first, then build each file.
```
