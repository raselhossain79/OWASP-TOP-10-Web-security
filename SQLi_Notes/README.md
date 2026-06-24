# SQL Injection — Complete Note Series

> OWASP Top 10 — A03:2021 Injection Category

A comprehensive, engagement-ready reference covering SQL Injection end to end: all injection
types, manual exploitation mechanics, WAF/filter bypass, full sqlmap automation, advanced
exploitation chains, and PortSwigger Web Security Academy lab mapping.

Every command and payload in every file is broken down piece by piece — no "just run this"
instructions. The goal is mechanism-level understanding, not copy-paste usage.

## File Index

| # | File | Covers |
|---|---|---|
| 01 | [`01-overview-classification.md`](./01-overview-classification.md) | Root-cause mechanism, DBMS fingerprinting, full SQLi type classification |
| 02 | [`02-in-band-sqli.md`](./02-in-band-sqli.md) | UNION-based & Error-based SQLi, schema enumeration |
| 03 | [`03-blind-sqli.md`](./03-blind-sqli.md) | Boolean-based & Time-based blind SQLi |
| 04 | [`04-oob-sqli.md`](./04-oob-sqli.md) | Out-of-band SQLi via DNS/HTTP (Oracle, MSSQL, MySQL, PostgreSQL) |
| 05 | [`05-second-order-sqli.md`](./05-second-order-sqli.md) | Second-order/stored SQLi chains |
| 06 | [`06-manual-waf-bypass.md`](./06-manual-waf-bypass.md) | Manual WAF/filter evasion: encoding, case, comments, HPP |
| 07 | [`07-sqlmap-complete.md`](./07-sqlmap-complete.md) | Full sqlmap reference + dedicated WAF bypass/tamper section |
| 08 | [`08-advanced-topics.md`](./08-advanced-topics.md) | Stacked queries, file read/write, SQLi-to-RCE, auth bypass, injection contexts |
| 09 | [`09-cheatsheet-lab-mapping.md`](./09-cheatsheet-lab-mapping.md) | Consolidated cheatsheet + full PortSwigger lab progression map |

## Recommended Reading Order

Read sequentially 01 → 09. Each file builds on mechanisms introduced earlier (DBMS syntax
table in file 01, comment/whitespace mechanics in file 02, conditional patterns in file 03 are
reused throughout files 04–08).

## Scope Covered

- **In-band:** UNION-based, Error-based (MySQL, MSSQL, PostgreSQL, Oracle)
- **Blind:** Boolean-based, Time-based
- **Out-of-band:** DNS exfiltration (Oracle `UTL_INADDR`, MSSQL `xp_dirtree`), HTTP exfiltration (Oracle `UTL_HTTP`, PostgreSQL `dblink`)
- **Second-order/stored:** Cross-feature payload detonation
- **Advanced:** Stacked queries, `LOAD_FILE`/`INTO OUTFILE`, `xp_cmdshell`, `COPY ... TO PROGRAM`, SQLi-to-RCE, auth bypass cheatsheet, `ORDER BY`/`INSERT`/`UPDATE`/header injection contexts
- **WAF bypass:** Manual (encoding, case, comments, double-encoding, HPP) + automated (sqlmap `--tamper` full reference table, `--identify-waf`, custom tamper script authoring, rate-limit evasion)
- **Tooling:** Full sqlmap flag reference — detection, enumeration, session/auth handling, `--os-shell`, file read/write

## Engagement Framing

Every file includes a **Real-World Notes** section addressing how the technique shows up in
actual assessments, common mistakes during testing, and report-writing considerations —
written for direct application on client engagements, not just lab exercises.

## Language

All content is written in full English only.
