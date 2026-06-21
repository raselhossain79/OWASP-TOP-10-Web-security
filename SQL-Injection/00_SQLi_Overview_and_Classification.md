# SQL Injection — Master Overview & Classification

> This is the index file for the full SQLi note set. Read this first, then go into each
> type-specific file. All labs referenced here map to PortSwigger Web Security Academy,
> since that is the primary practice environment for this track.

## 1. What SQL Injection Actually Is

SQL Injection (SQLi) happens when user-controlled input is concatenated into a SQL query
without proper parameterization, allowing an attacker to alter the logic of that query.
It is not "one technique" — it's a category, and the real skill is recognizing *which*
sub-type applies based on how the application responds.

## 2. File Map (this note series)

| File | Covers |
|---|---|
| `01_InBand_SQLi_Union_Error.md` | UNION-based, Error-based |
| `02_Blind_SQLi_Boolean_Time.md` | Boolean-based blind, Time-based blind |
| `03_OutOfBand_SQLi.md` | OOB via DNS/HTTP exfiltration |
| `04_Second_Order_SQLi.md` | Stored/second-order injection |
| `05_WAF_Bypass_and_Filter_Evasion.md` | Encoding, obfuscation, WAF bypass |
| `06_PortSwigger_Labs_Mapping_Cheatsheet.md` | Lab-by-lab mapping + quick payload reference |
| `07_SQLMap_Complete_Guide.md` | Full sqlmap usage, enumeration, OS access, WAF bypass via tamper scripts |
| `08_Advanced_Topics_Stacked_RCE_AuthBypass.md` | Stacked queries, file read/write, SQLi→RCE, auth bypass cheatsheet, context variations |

## 3. Industry-Standard Classification

Real-world pentest reports (and OWASP) classify SQLi by **how you extract data**, not by
the database engine:

1. **In-band SQLi** — data comes back in the same HTTP response.
   - UNION-based
   - Error-based
2. **Blind SQLi** — no data in the response; you infer answers indirectly.
   - Boolean-based (content changes True/False)
   - Time-based (response delay True/False)
3. **Out-of-band (OOB) SQLi** — data exfiltrated via a different channel (DNS, HTTP).
4. **Second-order (stored) SQLi** — payload stored now, triggered later in a different
   query/context.

There's a secondary axis — **injection context** — which matters for real engagements:
- In a `WHERE` clause (most common, most labs)
- In an `ORDER BY` clause (can't always use UNION the same way)
- In an `INSERT`/`UPDATE` statement (blind techniques only, usually)
- In a stored procedure / batch query (stacked queries, if supported)
- In HTTP headers (User-Agent, X-Forwarded-For, Cookie) — common in real assessments,
  rarely covered in basic labs

## 4. The Methodology You Should Always Follow (real-world + exam)

1. **Identify the injection point** — every parameter, header, cookie is a candidate.
2. **Confirm injection** — break the query with `'`, `"`, `)`, or a logic test
   (`' AND '1'='1` vs `' AND '1'='2`).
3. **Identify the DB engine** — error messages, version functions, comment syntax
   differences (`--`, `#`, `/* */`).
4. **Determine the injection context** — string, numeric, inside a function, etc.
5. **Pick the right technique** based on what the app gives you back (see classification
   above).
6. **Enumerate the schema** before dumping data — DB name, table names, column names.
7. **Extract data** — credentials, PII, whatever the engagement scope allows.
8. **Escalate if possible** — read files, write files, stacked queries, OS command
   execution depending on DB engine and privileges.

This sequence is what separates "lab-passing" from "real engagement" thinking — on a real
test you won't be told the DB engine or that a parameter is injectable. You find that out
yourself, every time.

## 5. Database Engine Fingerprinting Cheatsheet

| Test | MySQL | MSSQL | Oracle | PostgreSQL |
|---|---|---|---|---|
| Comment | `-- ` or `#` | `--` | `--` | `--` |
| String concat | `CONCAT(a,b)` | `a + b` | `a \|\| b` | `a \|\| b` |
| Version | `SELECT @@version` | `SELECT @@version` | `SELECT banner FROM v$version` | `SELECT version()` |
| Substring | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` | `SUBSTRING(s,1,1)` |
| Time delay | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | needs `DBMS_LOCK.SLEEP` (often blocked) | `pg_sleep(5)` |
| Stacked queries | rare (depends on driver) | yes, common | no (single statement) | yes |
| Current DB | `SELECT database()` | `SELECT db_name()` | `SELECT global_name FROM global_name` | `SELECT current_database()` |

You'll fingerprint this within the first few requests on any real engagement — don't skip
this step even when a lab tells you the engine up front.

## 6. Why This Note Set Exists

You're rebuilding this from scratch after covering almost everything before, so this set
is meant to be the **single source of truth** for AD-prep-style review later. Each
type-specific file is self-contained: theory, detection method, exploitation walkthrough,
PortSwigger lab name, and a real-world note on how this shows up outside of labs (WAFs,
ORMs, prepared statements bypasses, etc).

Continue to → `01_InBand_SQLi_Union_Error.md`
