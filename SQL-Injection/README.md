# SQL Injection — Complete Reference Notes

A from-scratch, real-world-aligned SQL injection note series, built around the
PortSwigger Web Security Academy lab structure but written for use beyond the labs —
on real engagements, OSCP-style boxes, and bug bounty work.

This README is the index. Read it first, then follow the files in order the first time
through. After that, use it as a lookup table when you need a specific technique fast.

---

## How This Series Is Organized

The notes follow the same flow you'd actually use on a target: confirm injection →
identify type → exploit → escalate → automate → bypass defenses. Files are numbered so
they can be read in sequence, but each one is also self-contained enough to jump straight
to if you just need one technique.

---

## File Index

| # | File | What's Inside |
|---|---|---|
| 00 | `00_SQLi_Overview_and_Classification.md` | Start here. Industry-standard SQLi classification (in-band / blind / OOB / second-order), the methodology you should follow on every engagement, and a DB engine fingerprinting table (MySQL/MSSQL/Oracle/Postgres syntax differences). |
| 01 | `01_InBand_SQLi_Union_Error.md` | **UNION-based** (column count, fingerprinting, schema enumeration, data extraction) and **Error-based** (XPath errors, type-conversion errors) techniques, with real-world notes on when each applies. |
| 02 | `02_Blind_SQLi_Boolean_Time.md` | **Boolean-based blind** (conditional response differences, ASCII binary search) and **Time-based blind** (SLEEP/WAITFOR/pg_sleep payloads) when there's no visible data in the response. |
| 03 | `03_OutOfBand_SQLi.md` | **OOB SQLi** via DNS/HTTP exfiltration (MSSQL `xp_dirtree`, Oracle `UTL_HTTP`), Burp Collaborator / interactsh setup, for when even time-based extraction is too slow or unreliable. |
| 04 | `04_Second_Order_SQLi.md` | **Stored/second-order injection** — payload saved at one point, triggered unsafely at a completely different feature later. Includes the classic username-truncation account-takeover example. |
| 05 | `05_WAF_Bypass_and_Filter_Evasion.md` | Manual WAF/filter evasion: case manipulation, inline comments, encoding tricks, operator substitution, double-encoding, HTTP parameter pollution. |
| 06 | `06_PortSwigger_Labs_Mapping_Cheatsheet.md` | Full PortSwigger Academy lab checklist mapped to technique, plus a fast copy-paste payload reference organized by goal (confirm injection, get column count, dump data, etc). |
| 07 | `07_SQLMap_Complete_Guide.md` | Full **sqlmap** usage: detection flags, DB/table/column enumeration, session/auth handling, `--os-shell`/file read-write, and the complete `--tamper` script reference for automated WAF bypass. |
| 08 | `08_Advanced_Topics_Stacked_RCE_AuthBypass.md` | The pieces most note sets skip: **stacked queries**, **file read/write** (LOAD_FILE, xp_cmdshell, COPY), **SQLi → RCE chains**, **auth bypass cheatsheet**, injection in ORDER BY/INSERT/HTTP headers, and a flag for NoSQL injection as a separate vuln class to cover later. |

---

## Recommended Reading Order (First Pass)

```
00 → 01 → 02 → 03 → 04 → 05 → 06 → 07 → 08
```

Each file ends with a "Continue to →" pointer to the next one, so you can also just
open file 00 and follow the trail.

## Recommended Use During Active Practice

When actually doing PortSwigger labs:
1. Open `06_PortSwigger_Labs_Mapping_Cheatsheet.md` for the lab checklist and quick
   payloads.
2. Reference the matching theory file (01–04) when a payload doesn't work and you need
   to understand *why*.
3. Use `07_SQLMap_Complete_Guide.md` only after manually confirming injection yourself —
   automating before understanding defeats the purpose of the practice.
4. Use `05` and the WAF-bypass section of `07` only when a lab/target is explicitly
   filtering your input.

---

## Coverage Status

- [x] In-band (UNION, Error-based)
- [x] Blind (Boolean, Time-based)
- [x] Out-of-band
- [x] Second-order/stored
- [x] Manual WAF/filter bypass
- [x] sqlmap (full usage + automated WAF bypass)
- [x] Stacked queries
- [x] File read/write
- [x] SQLi → RCE chains
- [x] Auth bypass cheatsheet
- [x] Context variations (ORDER BY, INSERT/UPDATE, HTTP headers)
- [ ] NoSQL injection — different vulnerability class, not relational SQLi; build as a
  separate note set if/when a MongoDB-backed target comes up.

This series is considered **complete** for classic relational-database SQL injection,
both for PortSwigger Academy practice and for real-world pentest engagements.

---

## Notes on Maintenance

- If PortSwigger renames or adds labs, update the checklist in file `06` — academy lab
  names/order can change over time.
- If you discover a new real-world technique or WAF bypass during actual client work,
  add it to the relevant file rather than starting a new one — keep this as the single
  source of truth rather than letting notes fragment across multiple versions.
- Written entirely in English per standing documentation policy — no Bangla/Banglish in
  any file, including this README.
