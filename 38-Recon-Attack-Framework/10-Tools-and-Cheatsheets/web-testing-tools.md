# Web Testing Tools — Quick Reference

Covers tools used in `06-Vulnerability-Testing/` and `07-WAF-and-Filter-Analysis/`.

| Tool | Used For | Module |
|---|---|---|
| Burp Suite / Caido (proxy) | Capturing/replaying requests, manual testing, Intruder-style fuzzing | input-surface-analysis.md, xss.md, business-logic.md |
| `sqlmap` | Automated SQLi detection/exploitation, tamper scripts for evasion | sqli.md, authorized-bypass-testing.md |
| `curl` | Manual request crafting and scripted testing | used throughout |
| Browser DevTools | DOM-based XSS inspection, JS debugging | xss.md, javascript-analysis.md |
| A listener you control (Burp Collaborator / `requestbin` / `nc`) | SSRF/blind interaction detection | ssrf.md |

## `sqlmap` — Common Safe Defaults
```bash
sqlmap -u "https://target.com/item?id=1" --batch --risk=1 --level=1 --delay=1
```
- `--risk=1`: lowest risk tier of test payloads (avoids riskier, potentially
  destructive techniques used at higher risk levels).
- `--level=1`: tests only the most common injection points/techniques; increase
  only if a lower level found nothing and the program's scope/rate limits allow
  more thorough (slower, noisier) testing.
- `--delay=1`: 1 second between requests — adjust to match program rate-limit
  guidance.

## `ffuf` — Common Safe Defaults
```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -t 20 -p 0.1
```
See `04-Attack-Surface-Mapping/endpoint-discovery.md` for the full flag breakdown.

## Notes
- Always confirm current tool syntax against `--help` or official documentation —
  flags and defaults change between versions.
- None of these tools substitute for manual verification of a finding — see
  `08-Validation-and-Evidence/validation-and-evidence.md`.
