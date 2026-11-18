# SQL Injection — Detection & DBMS Fingerprinting

> For authorized security testing only. Payloads are examples, not universal strings. Adapt them to the input context, DBMS, driver, and application query.

## 1. Quick Testing Workflow

1. Save a normal request and response as a baseline.
2. Test one input at a time: URL parameter, form field, JSON/XML value, cookie, or header.
3. Compare status, response body, length, redirects, and timing.
4. Identify the SQL context: string, number, `LIKE`, sort/order, or another expression.
5. Confirm with a controlled true/false pair or another repeatable signal.
6. Fingerprint the DBMS using more than one clue.
7. Record exact requests, responses, and limitations.

## 2. Identify the Input Context

| Context | Example query | Initial tests |
|---|---|---|
| String | `WHERE name = '<input>'` | `'`, `''`, `')` |
| Numeric | `WHERE id = <input>` | `1`, `1+1`, `1 AND 1=1` |
| LIKE | `WHERE name LIKE '%<input>%'` | `'`, `%`, wildcard changes |
| Sort/order | `ORDER BY <input>` | Valid column names or indexes |
| JSON/XML | Value is extracted from structured input | Keep the JSON/XML valid while changing one value |

A quote-triggered error is a clue, not proof. Confirm that the change is repeatable and related to SQL processing.

## 3. Basic Detection Techniques

### 3.1 Quote and delimiter testing

```sql
'
"
')
")
```

- **Purpose:** Check whether input is placed inside a quoted SQL expression.
- **Signal:** Repeatable SQL-related error or response change.
- **WAF tests:** URL-encode delimiters; try a different delimiter only if the context supports it.
- **Limitations:** Generic HTTP errors may have unrelated causes.

### 3.2 Arithmetic testing

```sql
1
1+1
1-1
```

- **Purpose:** Check whether input is evaluated as a numeric SQL expression.
- **Signal:** A result or response change matching the expression.
- **WAF tests:** URL-encode operators; try parentheses or valid whitespace alternatives if needed.
- **Limitations:** Application-side validation may reject expressions before SQL receives them.

### 3.3 Boolean-based testing

String context:
```sql
' AND '1'='1'--
' AND '1'='2'--
```

Numeric context:
```sql
1 AND 1=1
1 AND 1=2
```

- **Purpose:** Compare a condition expected to be true with one expected to be false.
- **Signal:** Stable difference in content, status, row count, or another observable feature.
- **WAF tests:** URL encoding, valid whitespace alternatives, comments, and equivalent condition syntax.
- **Limitations:** Caching, dynamic content, and personalization can create false positives.

### 3.4 SQL comments

```sql
-- 
#
/* comment */
```

- `--` is widely supported; some DBMSs require whitespace or a control character after it.
- `#` is commonly used by MySQL/MariaDB.
- `/* ... */` is supported by several DBMSs, but exact behaviour varies.
- **WAF tests:** Comment insertion or comment-based token splitting may affect simple filters.
- **Limitations:** A proxy or WAF may remove or normalize comments before SQL parsing.

## 4. Error-Based Detection

Send a harmless syntax test and check whether a database error is exposed.

```sql
'
''
')
```

| DBMS | Common error clues |
|---|---|
| MySQL / MariaDB | `You have an error in your SQL syntax` |
| PostgreSQL | `syntax error at or near` |
| Microsoft SQL Server | `Unclosed quotation mark` |
| Oracle | `ORA-` error codes |
| SQLite | `near "...": syntax error` |

- **Purpose:** Detect SQL parsing errors and gather DBMS clues.
- **WAF tests:** Compare raw and URL-encoded input; test valid comment/whitespace variants.
- **Limitations:** Applications often hide database errors. A generic error does not identify the DBMS.

## 5. UNION-Based Detection

### 5.1 Find the number of columns

Try increasing `ORDER BY` positions:
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

Or increase the number of `NULL` values:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

- **Purpose:** Find a column count accepted by the original query.
- **WAF tests:** URL-encode reserved characters; test valid comments, whitespace, or case variants.
- **Limitations:** `UNION` may be blocked even when another SQLi technique works.

### 5.2 Find a visible column

After finding the count, replace one `NULL` at a time with a harmless marker:
```sql
' UNION SELECT 'marker',NULL--
```

Adjust the number of expressions and data types to match the original query.

- **Signal:** The marker appears in the response.
- **WAF tests:** Test encoding or DBMS-valid comment/whitespace variants if a simple signature filter is suspected.
- **Limitations:** The application may not display the selected column.

## 6. Blind SQLi Detection

### 6.1 Boolean-based blind

```sql
' AND 1=1--
' AND 1=2--
```

- **Purpose:** Detect SQL evaluation when no error or query result is shown.
- **Signal:** A repeatable difference between true and false responses.
- **WAF tests:** URL encoding, accepted whitespace alternatives, comments, and equivalent conditions.
- **Limitations:** Requires a reliable observable difference.

### 6.2 Conditional error-based blind

General idea: make one condition produce a valid result and the other a controlled error. Syntax is DBMS-specific.

PostgreSQL example:
```sql
' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1--
```

- **Purpose:** Turn a hidden condition into an error/no-error signal.
- **WAF tests:** Encode delimiters and use only syntax accepted by the identified DBMS.
- **Limitations:** Error handling, type conversion, and query optimization may affect behaviour.

### 6.3 Time-based blind

| DBMS | Delay function |
|---|---|
| MySQL / MariaDB | `SLEEP(5)` |
| PostgreSQL | `pg_sleep(5)` |
| SQL Server | `WAITFOR DELAY '0:0:5'` |
| Oracle | `DBMS_PIPE.RECEIVE_MESSAGE('x',5)` (permissions/context dependent) |
| SQLite | No built-in portable sleep function |

Examples:
```sql
' AND SLEEP(5)--
' AND pg_sleep(5)--
```

SQL Server statement example:
```sql
'; WAITFOR DELAY '0:0:5'--
```

- **Purpose:** Check whether a condition can cause a measurable delay.
- **WAF tests:** Encode punctuation; use the delay syntax for the confirmed DBMS.
- **Limitations:** Use short delays, repeat tests, and compare with normal latency. SQLite generally needs an application-defined function or another channel.

## 7. Stacked Queries

A semicolon may allow a second statement, depending on the DBMS, driver, and connection settings.

- **Purpose:** Determine whether the execution path accepts multiple statements.
- **WAF tests:** Semicolon encoding or comment variations may affect simple filters.
- **Limitations:** Many drivers disable multi-statements. A semicolon in input does not prove a second statement executed.

## 8. Second-Order SQLi

- **What it is:** Input is stored first and used unsafely in a later SQL query.
- **How to test:** Submit a unique harmless marker, then trigger the workflow that reads or processes the stored value.
- **WAF tests:** Check transformations at both storage time and later use; the value may be decoded before the second query.
- **Limitations:** A successful save is not proof of SQL execution. Identify the later execution point.

## 9. Out-of-Band (OOB) SQLi

- **What it is:** A database causes a DNS/HTTP interaction that can be observed outside the normal response.
- **Requirements:** DBMS feature support, permissions, outbound network access, and a controlled listener.
- **WAF tests:** Input encoding may affect request filtering, but database egress controls are a separate layer.
- **Limitations:** No callback does not rule out SQLi. Use a harmless unique token, not real data.

## 10. DBMS Fingerprinting

Use multiple clues: error wording, syntax, version functions, and behaviour.

| DBMS | Version expression | Notes |
|---|---|---|
| MySQL | `SELECT VERSION()` | `@@version` is also common |
| MariaDB | `SELECT VERSION()` | Version text often includes `MariaDB` |
| PostgreSQL | `SELECT version()` | Returns build/platform details |
| SQL Server | `SELECT @@VERSION` | `SERVERPROPERTY('ProductVersion')` is another clue |
| Oracle | `SELECT * FROM v$version` | Access may be restricted; `DUAL` is a common one-row source |
| SQLite | `SELECT sqlite_version()` | Embedded database; no normal server account model |

Concatenation clues:

| DBMS | Common concatenation |
|---|---|
| MySQL / MariaDB | `CONCAT(a,b)` |
| PostgreSQL | `a || b` |
| SQL Server | `a + b` |
| Oracle | `a || b` |
| SQLite | `a || b` |

Other syntax clues:
- MySQL/MariaDB: `#` comments, `LIMIT`, executable comments such as `/*!50000 ... */`.
- PostgreSQL: `LIMIT`, `pg_sleep()`, `version()`.
- SQL Server: `TOP`, `WAITFOR DELAY`, `@@VERSION`.
- Oracle: `DUAL`, `ROWNUM`, `ORA-` errors.
- SQLite: `sqlite_master`, `PRAGMA`, `sqlite_version()`.

## 11. WAF / Filter Bypass Reference

> Bypass results depend on where filtering and decoding occur. A bypass is not guaranteed, and syntax must still be valid for the target DBMS.

| Technique | Example / idea | Limitation |
|---|---|---|
| URL encoding | `'` → `%27`; space → `%20` | May be decoded before WAF inspection |
| Double URL encoding | `%2527` | Only relevant if another decoding stage exists |
| Case variation | `UNION` → `uNiOn` | Ineffective against case-insensitive normalization |
| Inline comments | `UN/**/ION` | DBMS- and token-position-dependent |
| Whitespace alternatives | `%09`, `%0a`, `%0d`, `%0b`, `%0c` | Parsers and filters may normalize them |
| Parentheses | `AND (1=1)` | Changes grammar; not a universal space replacement |
| Function alternatives | `SUBSTRING()` vs `MID()` | Availability differs by DBMS |
| XML character references | `U` → `&#x55;` | Only useful when XML parsing decodes the value |
| HTTP Parameter Pollution | Duplicate parameter names | Framework may use first, last, or combined values |
| JSON/XML representation | Encode a value while keeping valid structure | Parser must decode it before SQL use |
| MySQL executable comments | `/*!50000 SELECT 1 */` | MySQL/MariaDB-specific and version-dependent |
| Hex/character construction | DBMS-specific string construction | Type conversion and normalization differ |

### Encoding reminders

- URL encoding is not SQL escaping.
- XML character references are decoded by an XML parser; they are not universal SQL encoding.
- Raw hex text such as `554E494F4E` is not the same as XML hex entities such as `&#x55;&#x4E;`.
- A bypass matters only if the transformed input reaches the SQL parser in the intended form.

## 12. Evidence Checklist

- [ ] Baseline request saved.
- [ ] Only one input changed per test.
- [ ] True/false pair repeated.
- [ ] Timing compared with baseline and repeated.
- [ ] Injection context identified.
- [ ] DBMS fingerprint supported by multiple clues.
- [ ] WAF behaviour separated from application/database behaviour.
- [ ] No destructive query or unnecessary data access used.
- [ ] Exact request, response, and impact recorded.
