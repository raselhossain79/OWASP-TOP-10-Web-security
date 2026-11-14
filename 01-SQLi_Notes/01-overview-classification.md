# SQL Injection — Overview & Classification

> Part of the OWASP Top 10 Injection Category (A03:2021 — Injection)

## 1. What SQL Injection Actually Is

SQL Injection (SQLi) happens when user-controlled input is concatenated directly into a SQL query string instead of being passed as a parameterized value. The database cannot tell the difference between "data" and "code" — it just sees a string of SQL syntax and executes it.

Example of the root cause (PHP/MySQL, vulnerable pattern):

```php
$query = "SELECT * FROM users WHERE username = '" . $_GET['username'] . "'";
```

Breakdown of why this is broken:
- `$_GET['username']` — raw, attacker-controlled input pulled straight from the URL query string. Nothing validates or escapes it before use.
- `" . ... . "` — PHP string concatenation. The input is glued directly into the SQL text, meaning any quote characters or SQL keywords inside the input become part of the query itself, not data.
- The surrounding single quotes (`'...'`) are meant to delimit a string literal, but if the input itself contains a `'`, that quote closes the literal early and anything after it is interpreted as SQL syntax by the parser.

If an attacker sends `' OR '1'='1`, the resulting query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1'
```

Breakdown:
- `''` — closes the original string literal early using the injected leading quote.
- `OR '1'='1'` — adds a tautology (always-true condition) joined with `OR`, so the `WHERE` clause evaluates to true for every row regardless of the original `username` filter.
- Net effect: the query returns all rows in the `users` table instead of just one.

This is the seed mechanism behind every SQLi variant covered in this series — only the *delivery method* and *feedback channel* change between types.

## 2. Why This Matters On Real Engagements

On a real assessment, SQLi is rarely "found and forgotten." It's usually the pivot point:
- Auth bypass → access to an admin panel
- Data extraction → PII/credential dumps for the report's impact section
- File read (`LOAD_FILE`, `xp_cmdshell`, etc.) → source code disclosure or code execution
- It may chain into full RCE on the underlying host, depending on DBMS capabilities, privileges, configuration, and operating-system restrictions (see file 08).

Report-writing note: clients care less about "I bypassed login" and more about *business impact* — "an unauthenticated attacker could extract the customer database, including hashed passwords and PII." Only claim host-level code execution when it has actually been demonstrated. Always frame findings around verified business impact, not just technical curiosity.

## 3. Classification of SQLi Types

SQLi techniques can be classified by how the attacker receives information, as well as by when the vulnerable query executes.

### 3.1 In-Band SQLi

The attack and the result travel over the *same channel* — you send the payload, you see the result in the HTTP response.

- **UNION-based** — append a `UNION SELECT` to pull extra columns of data directly into the page output.
- **Error-based** — force the database to throw an error that leaks data inside the error message itself (e.g., database-specific conversion or XML-related errors).

### 3.2 Blind SQLi

No useful query result is directly reflected in the response. You infer information indirectly.

- **Boolean-based** — inject a condition; the page behaves differently (different content, HTTP status, response length) depending on whether the condition is true or false.
- **Time-based** — inject a conditional delay; if the response takes longer, the condition may have been true. Used when there is no reliable visible difference in output.

### 3.3 Out-of-Band (OOB) SQLi

The database is made to generate an interaction over a *different* channel — typically DNS or HTTP — rather than returning the result in the normal HTTP response.

This can be useful when:
- Database errors are hidden.
- The application does not reflect query results.
- Boolean responses are indistinguishable.
- Timing-based tests are unreliable or blocked.

OOB requires suitable DBMS functionality, permissions, configuration, and network egress. Not every database supports the same OOB techniques.

### 3.4 Second-Order (Stored) SQLi

The payload is stored in the database from one input point (e.g., a "display name" field), and the injection only *triggers* later, when a different part of the application reads and uses that stored value unsafely in a separate query.

Important distinction: Second-order SQLi describes *when the injection is triggered*, not how the result is returned. A second-order vulnerability may produce an error, a visible result, or a blind response.

## 4. Database Fingerprinting — Complete Reference

Database fingerprinting means identifying the Database Management System (DBMS) and, when possible, its version.

This is important because SQL syntax, built-in functions, comments, error behavior, and delay mechanisms differ between DBMS products.

**Important:** Fingerprinting is not always the literal first step. First identify a potentially injectable input and understand its query context. Then fingerprint the backend using the available feedback channel.

### 4.1 Common DBMS Used in Web Applications

The following relational databases are particularly relevant to SQL injection testing:

| DBMS | Common environment | Example |
|---|---|---|
| MySQL | Web applications, PHP-based systems | MySQL 8.x |
| MariaDB | Web applications, Linux environments | MariaDB 10.x |
| PostgreSQL | Modern web applications, enterprise systems | PostgreSQL 16 |
| Microsoft SQL Server (MSSQL) | Microsoft enterprise environments | SQL Server 2022 |
| Oracle Database | Enterprise applications | Oracle Database 19c |
| SQLite | Lightweight applications, embedded systems | SQLite 3.x |

Note: Redis and MongoDB are examples of NoSQL databases. They do not use SQL in the same way as the relational DBMS products above, so traditional SQLi fingerprinting payloads do not apply directly.

### 4.2 DBMS Identification Cheat Sheet

| DBMS | Version query | String concatenation | Comment syntax |
|---|---|---|---|
| MySQL | `SELECT @@version` | `CONCAT(a,b)` | `-- `, `#`, `/* */` |
| MariaDB | `SELECT @@version` | `CONCAT(a,b)` | `-- `, `#`, `/* */` |
| PostgreSQL | `SELECT version()` | `a || b` | `--`, `/* */` |
| MSSQL | `SELECT @@version` | `a + b` | `--`, `/* */` |
| Oracle | `SELECT banner FROM v$version` | `a || b` | `--`, `/* */` |
| SQLite | `SELECT sqlite_version()` | `a || b` | `--`, `/* */` |

These are SQL-level queries, not ready-to-use HTTP injection payloads. Their placement depends on the vulnerable query structure.

### 4.3 DBMS-Specific Fingerprinting Reference

#### A. MySQL / MariaDB

**Version identification:**

```sql
SELECT @@version;
SELECT VERSION();
```

**String concatenation:**

```sql
SELECT CONCAT('My', 'SQL');
```

Expected output:

```text
MySQL
```

**Useful characteristics:**
- `@@version` returns the database version.
- `CONCAT()` joins multiple strings.
- `#` is a MySQL-style single-line comment.
- `-- ` requires whitespace after the two hyphens.
- `SLEEP(seconds)` can introduce a delay.
- `IF(condition, true_value, false_value)` provides conditional logic.

**Example Boolean condition:**

```sql
SELECT IF(SUBSTRING(@@version,1,1)='8',1,0);
```

**Example time-based condition:**

```sql
SELECT IF(SUBSTRING(@@version,1,1)='8',SLEEP(5),0);
```

A delay of approximately five seconds indicates that the condition selected the sleep branch, subject to network and application behavior.

**Error-based notes:**
- MySQL has historically exposed information through certain XML and conversion-related errors.
- `EXTRACTVALUE()` and `UPDATEXML()` were commonly used in older error-based examples.
- These XML functions are deprecated in MySQL 5.7 and removed in MySQL 8.0. Do not assume they will work on modern installations.
- Error messages and function availability depend on the version and application error handling.

#### B. PostgreSQL

**Version identification:**

```sql
SELECT version();
SELECT current_setting('server_version');
```

**String concatenation:**

```sql
SELECT 'Post' || 'greSQL';
```

Expected output:

```text
PostgreSQL
```

**Useful characteristics:**
- `version()` returns detailed PostgreSQL version information.
- `current_setting('server_version')` returns the server version setting.
- `||` joins strings.
- `--` and `/* */` are comment syntax.
- `pg_sleep(seconds)` introduces a delay.
- `SUBSTRING()` can extract part of a string.

**Example Boolean condition:**

```sql
SELECT CASE
    WHEN current_setting('server_version') LIKE '16.%'
    THEN 1
    ELSE 0
END;
```

**Example time-based condition:**

```sql
SELECT CASE
    WHEN current_setting('server_version') LIKE '16.%'
    THEN pg_sleep(5)
    ELSE pg_sleep(0)
END;
```

This is a standalone query example. In an injection, its placement must be adapted to the surrounding SQL expression.

**Error-based example:**

```sql
SELECT CAST('not-a-number' AS INTEGER);
```

PostgreSQL produces an invalid integer input error.

PostgreSQL also supports the shorthand cast syntax:

```sql
SELECT 'not-a-number'::INTEGER;
```

These examples demonstrate PostgreSQL-style error behavior. They do not automatically leak the server version.

#### C. Microsoft SQL Server (MSSQL)

**Version identification:**

```sql
SELECT @@version;
```

Additional information:

```sql
SELECT SERVERPROPERTY('ProductVersion');
SELECT SERVERPROPERTY('ProductLevel');
SELECT DB_NAME();
```

**String concatenation:**

```sql
SELECT 'Microsoft ' + 'SQL Server';
```

Expected output:

```text
Microsoft SQL Server
```

**Useful characteristics:**
- `@@version` returns detailed server version information.
- `SERVERPROPERTY()` returns server properties.
- `+` joins strings.
- `--` and `/* */` are comment syntax.
- `WAITFOR DELAY` can introduce a delay.
- `SUBSTRING()` extracts part of a string.

**Example Boolean condition:**

```sql
SELECT CASE
    WHEN SUBSTRING(@@version,1,9) = 'Microsoft'
    THEN 1
    ELSE 0
END;
```

**Example time-based condition:**

```sql
IF SUBSTRING(@@version,1,9) = 'Microsoft'
    WAITFOR DELAY '00:00:05';
```

Note: `WAITFOR DELAY` is a statement, not an ordinary scalar function. It generally requires a context that permits statement execution or stacked queries.

**Error-based example:**

```sql
SELECT CONVERT(INT, 'not-a-number');
```

MSSQL returns a conversion error.

A dynamic conversion involving `@@version` can sometimes expose version text in an error message:

```sql
SELECT CONVERT(INT, @@version);
```

Whether the useful text appears depends on the error and the application response.

#### D. Oracle Database

**Version identification:**

```sql
SELECT banner FROM v$version;
```

Alternative:

```sql
SELECT version FROM v$instance;
```

These system views may require appropriate permissions.

**String concatenation:**

```sql
SELECT 'Ora' || 'cle' FROM dual;
```

Expected output:

```text
Oracle
```

**Useful characteristics:**
- Oracle uses `||` for string concatenation.
- `DUAL` is a special one-row table commonly used for expressions.
- `SUBSTR()` extracts part of a string.
- `DBMS_PIPE.RECEIVE_MESSAGE()` can introduce a delay when the necessary permissions are available.
- `--` and `/* */` are comment syntax.
- `ROWNUM` can be used to limit returned rows.

**Example Boolean condition:**

```sql
SELECT CASE
    WHEN SUBSTR(
        (SELECT banner FROM v$version WHERE ROWNUM = 1),
        1, 6
    ) = 'Oracle'
    THEN 1
    ELSE 0
END
FROM dual;
```

**Example time-based query:**

```sql
SELECT CASE
    WHEN 1=1
    THEN DBMS_PIPE.RECEIVE_MESSAGE('test',5)
    ELSE 0
END
FROM dual;
```

This example depends on the availability and permissions of `DBMS_PIPE`. Its return value and execution context must also be considered when adapting it to an injection.

**Error-based example:**

```sql
SELECT TO_NUMBER('not-a-number') FROM dual;
```

Oracle produces an invalid number error (commonly ORA-01722).

This demonstrates Oracle-specific error behavior, but does not by itself reveal the database version.

#### E. SQLite

**Version identification:**

```sql
SELECT sqlite_version();
```

Additional information:

```sql
SELECT sqlite_source_id();
```

**String concatenation:**

```sql
SELECT 'SQL' || 'ite';
```

Expected output:

```text
SQLite
```

**Useful characteristics:**
- `sqlite_version()` returns the SQLite library version.
- `sqlite_source_id()` returns source/build identification information.
- `||` joins strings.
- `--` and `/* */` are comment syntax.
- SQLite does not provide a built-in SQL `SLEEP()` function.
- Its function availability can depend on how the application compiled or extended SQLite.

**Example Boolean condition:**

```sql
SELECT CASE
    WHEN SUBSTR(sqlite_version(),1,1) = '3'
    THEN 1
    ELSE 0
END;
```

**Error-based example:**

```sql
SELECT ABS(-9223372036854775808);
```

SQLite can return an integer overflow error for this expression.

This is a SQLite-specific behavioral clue, not a version disclosure technique.

**Time-based limitation:**

SQLite has no standard built-in SQL sleep function comparable to MySQL's `SLEEP()` or PostgreSQL's `pg_sleep()`.

A time-based approach may be unavailable unless the application exposes a suitable custom function or another delay-producing operation.

### 4.4 Fingerprinting Through Different SQLi Techniques

The same DBMS can be fingerprinted through different feedback channels. The following examples demonstrate the approaches.

Important assumptions:
- You are testing an authorized target.
- The vulnerable parameter and its SQL context are already understood.
- The examples are SQL expressions or query fragments, not universally valid HTTP payloads.
- UNION examples assume two compatible output columns and that the second column is reflected in the response.

#### A. Error-Based Fingerprinting

The objective is to trigger DBMS-specific errors and inspect the resulting response.

| DBMS | Example |
|---|---|
| MySQL | `EXTRACTVALUE(1,CONCAT(0x7e,@@version))` — legacy versions where the function exists |
| PostgreSQL | `CAST('invalid' AS INTEGER)` |
| MSSQL | `CONVERT(INT,@@version)` |
| Oracle | `TO_NUMBER('invalid')` |
| SQLite | `ABS(-9223372036854775808)` |

**What to observe:**
- Error format and error codes.
- Function names mentioned in the error.
- Data type conversion behavior.
- Whether the error contains any dynamic input.
- Whether the application exposes the database error or hides it.

Do not assume every error will reveal the version. Some errors only reveal DBMS-specific behavior.

#### B. UNION-Based Fingerprinting

The objective is to retrieve the database version directly into a reflected output column.

**MySQL / MariaDB:**

```sql
' UNION SELECT NULL,@@version-- -
```

**PostgreSQL:**

```sql
' UNION SELECT NULL,version()-- -
```

**MSSQL:**

```sql
' UNION SELECT NULL,@@version-- -
```

**Oracle:**

```sql
' UNION SELECT NULL,banner FROM v$version WHERE ROWNUM=1-- -
```

**SQLite:**

```sql
' UNION SELECT NULL,sqlite_version()-- -
```

Important considerations:
- The number of columns must match the original query.
- Data types must be compatible.
- At least one selected column must be displayed in the application response.
- Oracle requires a valid `FROM` source, such as `v$version` or `dual`.
- Permissions can prevent access to certain Oracle system views.

A failed UNION attempt does not prove that SQLi is absent.

#### C. Boolean-Based Blind Fingerprinting

The objective is to infer database information by observing whether a condition is true or false.

Example DBMS-specific conditions:

| DBMS | Example condition |
|---|---|
| MySQL | `SUBSTRING(@@version,1,1)='8'` |
| PostgreSQL | `current_setting('server_version') LIKE '16.%'` |
| MSSQL | `SUBSTRING(@@version,1,9)='Microsoft'` |
| Oracle | `SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,6)='Oracle'` |
| SQLite | `SUBSTR(sqlite_version(),1,1)='3'` |

For example, in MySQL:

```sql
' AND SUBSTRING(@@version,1,1)='8'-- -
```

If the condition is true, the application may return the normal response. If false, the response may change.

**What to observe:**
- Page content.
- Response length.
- HTTP status code.
- Consistent differences between true and false conditions.

Always establish a reliable true/false baseline first. Dynamic page content and caching can produce misleading differences.

#### D. Time-Based Blind Fingerprinting

The objective is to trigger a delay only when a particular condition is true.

| DBMS | Delay mechanism |
|---|---|
| MySQL | `SLEEP(5)` |
| PostgreSQL | `pg_sleep(5)` |
| MSSQL | `WAITFOR DELAY '00:00:05'` |
| Oracle | `DBMS_PIPE.RECEIVE_MESSAGE('test',5)` |
| SQLite | No standard built-in sleep function |

Example MySQL query:

```sql
SELECT IF(
    SUBSTRING(@@version,1,1)='8',
    SLEEP(5),
    0
);
```

Example PostgreSQL query:

```sql
SELECT CASE
    WHEN current_setting('server_version') LIKE '16.%'
    THEN pg_sleep(5)
    ELSE pg_sleep(0)
END;
```

**What to observe:**
- Compare normal response time with the conditional delay.
- Repeat the test to reduce false positives.
- Consider network latency and server load.
- Do not interpret one slow response as proof of SQLi.

For MSSQL, `WAITFOR DELAY` is a statement and usually needs a compatible execution context. Oracle's delay mechanism depends on permissions. SQLite generally lacks a native equivalent.

#### E. Out-of-Band (OOB) Fingerprinting

OOB testing relies on an interaction outside the normal HTTP response, usually DNS or HTTP.

Unlike UNION or error-based fingerprinting, OOB does not necessarily return the version directly.

Examples of DBMS-specific capabilities:

| DBMS | Potential OOB-related functionality | Important limitation |
|---|---|---|
| MySQL | `LOAD_FILE()` and file-related operations | Requires suitable privileges, file access and environment configuration |
| PostgreSQL | Extensions and server-side program/file functionality | Depends heavily on installed extensions and permissions |
| MSSQL | `xp_dirtree`, `xp_fileexist` and other extended procedures | Availability and execution permissions vary |
| Oracle | `UTL_HTTP`, `UTL_INADDR` | Network ACLs and permissions may restrict access |
| SQLite | No standard built-in network request function | Usually requires application-provided extensions or functions |

**General OOB validation workflow:**

1. Set up an authorized DNS or HTTP interaction listener.
2. Use a DBMS-specific, non-sensitive callback test where the environment permits it.
3. Observe whether the database environment generates an external interaction.
4. Correlate the interaction with the test request.
5. Record the DBMS capability and relevant restrictions.

Important:
- A DNS/HTTP callback does not automatically reveal the DBMS version.
- An unsuccessful callback does not prove the absence of SQLi.
- Network egress restrictions, DNS resolution, permissions and DBMS configuration can prevent callbacks.
- Do not assume that every DBMS supports the same OOB functionality.

### 4.5 Quick Comparison — Which Fingerprinting Method Should You Try?

| Situation | Recommended approach |
|---|---|
| Database errors are visible | Error-based fingerprinting |
| Query results appear in the page | UNION-based fingerprinting |
| Page changes based on conditions | Boolean-based fingerprinting |
| No useful visible difference | Time-based testing |
| In-band and timing channels are unusable | Consider OOB testing |
| Payload is stored and executed later | Investigate second-order SQLi |

This is a practical decision guide, not a mandatory sequence. Multiple techniques can be tested where appropriate.

### 4.6 What If the DBMS Cannot Be Identified?

Sometimes fingerprinting is difficult because:
- The application hides database errors.
- UNION results are not reflected.
- The injection context restricts available SQL syntax.
- WAF rules interfere with testing.
- The database user lacks permission to access version information.
- The application uses an ORM or database abstraction layer.
- The backend database is configured to restrict certain functions.

In these situations:

1. Preserve the evidence that SQLi exists.
2. Record which tests worked and which failed.
3. Test DBMS-specific behavior using safe, minimal probes.
4. Avoid assuming that the application language identifies the DBMS.
5. Consider multiple DBMS possibilities until sufficient evidence is available.

**Important distinction:**

A database version query failing does not mean the database is unidentified forever, and a DBMS-specific function working is stronger evidence than guessing from the application's technology stack.

### 4.7 Common Fingerprinting Mistakes

**Mistake 1: Assuming the application language determines the DBMS**

PHP does not automatically mean MySQL. PHP applications can use PostgreSQL, SQLite, MSSQL and other databases.

**Mistake 2: Assuming all DBMS products support the same functions**

`SLEEP()` is not a universal SQL function. `pg_sleep()` and `WAITFOR DELAY` belong to different DBMS products.

**Mistake 3: Treating one failed payload as proof**

A payload can fail because of the injection context, syntax, privileges, filters or application behavior.

**Mistake 4: Confusing an error with version disclosure**

A DBMS-specific error may identify the database family without revealing its exact version.

**Mistake 5: Assuming OOB is universally available**

OOB requires specific capabilities and network conditions. It is not a guaranteed fallback for every blind SQLi.

**Mistake 6: Ignoring the original SQL query context**

A payload designed for a string parameter may not work in a numeric parameter or inside a different SQL expression.

## 5. Real-World Notes (Apply Throughout the Series)

- **Common mistake #1:** Testing only with `'` and giving up if it doesn't error. Many modern frameworks (ORMs, prepared statement wrappers) prevent certain injection patterns, but other unsafe query construction may still exist. Test different input contexts where authorized.
- **Common mistake #2:** Assuming WAF presence means "not exploitable." A WAF blocks known patterns, not necessarily the underlying logic flaw — see file 06 for manual bypass.
- **Common mistake #3:** Assuming error-based SQLi is the only way to identify an injection. Blind and OOB techniques can provide evidence without visible SQL errors.
- **Common mistake #4:** Assuming DBMS fingerprinting must succeed before any other SQLi testing. Sometimes the injection context must be understood first.
- **Report-writing tip:** Always state the exact parameter, HTTP method, and a single reproducible proof-of-concept request/response pair. Reviewers and developers fixing the bug need the minimum viable reproduction, not the entire enumeration history.
- **Evidence tip:** Record the DBMS identification method, observed version (if available), and confidence level. Distinguish confirmed identification from an educated guess.

## 6. Practical SQLi Testing Workflow

Use this as a general workflow during authorized engagements:

### Phase 1 — Initial Discovery

1. Identify user-controlled input points (URL parameters, POST fields, headers, cookies, JSON values).
2. Establish a normal baseline request.
3. Test whether input changes query behavior.
4. Investigate SQL syntax errors and other anomalies.
5. Determine whether the input is likely part of a string, numeric, or other SQL context.

### Phase 2 — Injection Validation

1. Check whether the input can alter SQL logic.
2. Compare true and false conditions.
3. Investigate visible database errors.
4. Determine whether UNION-based output is possible.
5. Consider blind testing when direct output is unavailable.

### Phase 3 — Database Fingerprinting

1. Identify possible DBMS-specific behavior.
2. Try suitable version-identification queries in the established injection context.
3. Use error-based or UNION-based feedback when available.
4. Use Boolean or time-based approaches when direct output is unavailable.
5. Consider OOB only when appropriate capabilities and network conditions exist.

### Phase 4 — Controlled Impact Validation

1. Determine what data or operations are accessible.
2. Validate impact using the minimum necessary evidence.
3. Avoid unnecessary extraction of sensitive information.
4. Check whether database privileges create additional security impact.
5. Document all verified findings.

### Phase 5 — Reporting

Include:
- Vulnerable endpoint and parameter.
- HTTP method and authentication requirements.
- DBMS and version, if confirmed.
- SQLi classification.
- Reproducible proof of concept.
- Actual demonstrated impact.
- Remediation recommendations.

## 7. PortSwigger Academy Mapping (Topic Overview)

This series follows the Academy's own difficulty progression. Full lab-by-lab mapping lives in file `09-cheatsheet-lab-mapping.md`, but by category:

- **SQL injection** topic (Apprentice → Practitioner → Expert) → covered across files 02–05, 08.
- **SQL injection (Blind)** is technically the same Academy topic, but focuses on extracting information when query results are not directly returned.
- Error-based, UNION-based, Boolean-based, Time-based and OOB approaches are studied through their respective feedback mechanisms.

## Next File

→ `02-in-band-sqli.md` — UNION-based and Error-based techniques, full payload breakdowns.
