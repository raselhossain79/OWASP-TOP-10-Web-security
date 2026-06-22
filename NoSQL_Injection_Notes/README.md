# NoSQL Injection — Note Series (OWASP A03:2021)

A comprehensive, mechanism-first note series on NoSQL injection, focused on MongoDB (the most widely deployed NoSQL database in production web applications). Built to the same depth and standard as the SQL Injection series in this repository: every payload is broken down piece by piece, every technique is mapped to a real PortSwigger Web Security Academy lab where one exists, and every section includes real-world framing beyond lab theory.

## Files

| File | Contents |
|---|---|
| [`01_Overview_and_Classification.md`](01_Overview_and_Classification.md) | What NoSQL injection is, how it **fundamentally differs from SQLi** (type/structure confusion vs. syntax breaking), MongoDB's data model, the two formal categories (syntax injection vs. operator injection), injection-point surfaces, impact categories, and the full Academy lab map |
| [`02_Exploitation_Techniques.md`](02_Exploitation_Techniques.md) | Detection methodology, operator-injection authentication bypass (`$ne`, `$gt`, `$in`), blind/boolean syntax-injection data extraction, `$where`/`Object.keys()` blind field enumeration, `$regex` JS-free extraction, timing-based blind injection, and `mapReduce()` as a second JS-injection surface |
| [`03_Filter_and_WAF_Bypass.md`](03_Filter_and_WAF_Bypass.md) | Bypassing key-stripping sanitizers, type enforcement gaps, regex/WAF blocklists, operator allowlisting, and null-byte truncation — organized by *which defensive layer* you're up against |
| [`04_NoSQLMap_Automation_Tool.md`](04_NoSQLMap_Automation_Tool.md) | Full usage of NoSQLMap (the sqlmap-equivalent for NoSQL): installation, menu-driven and flag-driven usage, every flag explained, and an honest, specific comparison of its limitations against sqlmap |
| [`05_Cheatsheet.md`](05_Cheatsheet.md) | Compressed quick-reference: decision tree, payload tables, operator reference, filter-bypass lookup, and lab order — for use during live engagements, not for first-time learning |

## How to Use This Series

1. Read File 01 first, in full. The SQLi-vs-NoSQLi distinction in §1 is the single most important conceptual reset — skipping it leads to misdiagnosing operator injection as "not a real vulnerability" because no SQL error ever appears.
2. Work through File 02 alongside the PortSwigger labs, in this exact order:
   1. Detecting NoSQL injection (Apprentice)
   2. Exploiting NoSQL operator injection to bypass authentication (Apprentice)
   3. Exploiting NoSQL injection to extract data (Practitioner)
   4. Exploiting NoSQL operator injection to extract unknown fields (Practitioner)
3. Keep File 03 in mind from the start, not just when you get stuck — real targets are filtered far more often than lab targets.
4. Read File 04 once you're comfortable with manual exploitation, not before — understanding the manual mechanism first means you'll know when to trust (and when to distrust) the tool's output.
5. Use File 05 as your in-engagement memory aid once you've internalized everything above.

## Scope Note

This series focuses on MongoDB, consistent with both real-world prevalence and the PortSwigger Web Security Academy's own scope. Other document-store databases (CouchDB) and other NoSQL data models entirely (key-value, wide-column, graph) use different query languages and are only referenced where directly relevant (e.g., NoSQLMap's CouchDB support in File 04).
