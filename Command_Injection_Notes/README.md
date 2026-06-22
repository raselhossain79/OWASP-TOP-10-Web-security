# OS Command Injection — Complete Note Series

Part of the OWASP Top 10, **A03:2021 – Injection** category. Companion series to the SQL Injection notes, built to the same depth and standard: every command is broken down flag-by-flag, every technique is mapped to its real PortSwigger Web Security Academy lab in correct progression order, and every file includes real-world engagement notes, common mistakes, and report-writing guidance.

## File Index

| File | Description |
|---|---|
| [`01_Overview_and_Classification.md`](01_Overview_and_Classification.md) | Root cause of command injection, shell-mediated vs. direct execution, full Linux/Windows/PowerShell metacharacter reference, the three sub-types (in-band, blind, OOB). |
| [`02_InBand_Command_Injection.md`](02_InBand_Command_Injection.md) | Output-visible injection. Linux (`;`, `\|`, backticks, `$()`) and Windows (`&`) payload construction, step by step. Maps to **PortSwigger Lab 1**. |
| [`03_Blind_Command_Injection.md`](03_Blind_Command_Injection.md) | Time-based detection (`sleep`, `timeout`), conditional/boolean detection, file-write/read detection. Maps to **PortSwigger Labs 2–3**. |
| [`04_OutOfBand_Command_Injection.md`](04_OutOfBand_Command_Injection.md) | DNS and HTTP exfiltration via Burp Collaborator, data smuggling through DNS subdomains and HTTP paths. Maps to **PortSwigger Labs 4–5**. |
| [`05_Filter_WAF_Bypass.md`](05_Filter_WAF_Bypass.md) | Character/keyword blacklist bypass, space filtering bypass (`${IFS}`, tabs, brace expansion), Windows caret-escape bypass, WAF pattern-matching evasion. |
| [`06_Commix_Automation.md`](06_Commix_Automation.md) | Full commix usage: installation, targeting, OS/technique selection, `--os-shell`, `--reverse-tcp`, tamper scripts for automated WAF bypass. |
| [`07_Cheatsheet_and_Lab_Mapping.md`](07_Cheatsheet_and_Lab_Mapping.md) | Consolidated payload quick-reference (Linux + Windows + PowerShell), a decision flowchart for technique selection, and the complete PortSwigger lab progression table. |

## Recommended Reading / Practice Order

1. Read `01` for the conceptual foundation — don't skip this even if eager to start injecting; the shell-mediated vs. direct-execution distinction underpins everything that follows.
2. Work through `02` → `03` → `04` in order, solving the corresponding PortSwigger lab after each file, since the labs are specifically designed to remove one detection signal at a time (output → timing → OOB).
3. Read `05` once comfortable with the core mechanics, and practice bypasses against DVWA's "High" security command injection module or similar deliberately-filtered targets.
4. Read `06` last — commix is most useful once you already understand what it's automating; using it first without that foundation will make its output much harder to interpret correctly.
5. Use `07` as a standing reference during real engagements and CTFs.

## Conventions Used Throughout This Series

- All commands are broken down argument-by-argument — no "just run this" instructions.
- Every payload section states explicitly whether it targets Linux (`sh`/`bash`), Windows `cmd.exe`, or PowerShell, since operator syntax differs meaningfully between them.
- PortSwigger lab references use the Academy's actual lab names and progression order, not topic groupings.
- Every file ends with real-world engagement notes, common mistakes, and report-writing considerations.
- Written entirely in English.
