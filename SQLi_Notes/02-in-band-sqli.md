# In-Band SQL Injection — UNION-Based & Error-Based

## 1. UNION-Based SQLi

### 1.1 Core Mechanism
`UNION` combines results from two `SELECT` statements into one result set. If you can append
a second `SELECT` to a vulnerable query, you can pull arbitrary data from arbitrary tables
straight into the application's existing output.

Two hard requirements for `UNION` to work:
1. The injected `SELECT` must return the **same number of columns** as the original query.
2. Corresponding columns must be of **compatible data types**.

### 1.2 Step 1 — Determine Column Count

**Method A: `ORDER BY` increment**

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

Breakdown:
- `'` — closes the original string literal (same mechanism as file 01).
- `ORDER BY N` — sorts results by the Nth column. If N exceeds the actual column count, the
  database throws an "unknown column" / "out of range" error.
- `--` — comments out the remainder of the original query (e.g., a trailing quote or extra
  clause) so the modified query stays syntactically valid.
- Method: increment N until the query errors. The last N that *succeeded* is the column count.

**Method B: `UNION SELECT NULL` increment**

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

Breakdown:
- `UNION SELECT NULL,...` — attempts to union a row of `NULL` values. `NULL` is used because
  it's compatible with virtually every data type (string, int, date), so a "column count
  mismatch" error (if any) is purely about *count*, not *type*.
- Each additional `NULL` represents one more column being guessed.
- A response that loads normally (no DB error) confirms the column count matches.

### 1.3 Step 2 — Identify Reflected (Visible) Columns

```sql
' UNION SELECT 'a','b','c'--
```

Breakdown:
- Replace each `NULL` with a distinct marker string (`'a'`, `'b'`, `'c'`). Whichever marker(s)
  appear in the rendered page tell you exactly which column positions get displayed back to
  the user — those are the positions you'll use to exfiltrate real data.

### 1.4 Step 3 — Extract Data

Example against MySQL, assuming columns 2 and 3 are reflected:

```sql
' UNION SELECT NULL,username,password FROM users--
```

Breakdown:
- `NULL` — placeholder for column 1, which we already established is not reflected (no point
  injecting real data into a column you can't see).
- `username,password` — actual column names pulled from a table guessed/enumerated via
  `information_schema` (see below). Positioned in columns 2 and 3 because those are the
  reflected positions identified in step 2.
- `FROM users` — the target table.

### 1.5 Enumerating Schema (when table/column names are unknown)

```sql
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
```

Breakdown:
- `information_schema.tables` — a built-in metadata view present in MySQL, MSSQL, and
  PostgreSQL that lists every table the current DB user can see, across all accessible
  databases by default.
- `table_name` — the column inside that metadata view holding each table's name.
- This is DBMS-agnostic-ish: Oracle uses `all_tables` with column `table_name` instead.

```sql
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

Breakdown:
- `information_schema.columns` — metadata view listing every column across every table.
- `WHERE table_name='users'` — filters that list down to only the table you've already
  identified as interesting, so you get its column names specifically.

### 1.6 Multi-Row Extraction (single-row reflection workaround)

If the page only displays one row at a time, concatenate multiple rows into one string:

```sql
' UNION SELECT NULL,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),NULL FROM users--
```

Breakdown:
- `GROUP_CONCAT(...)` — MySQL aggregate function that merges multiple rows into a single
  string value, which is essential when the app's template only renders the first row of a
  result set.
- `username,0x3a,password` — concatenates each username and password together, separated by
  `0x3a` (hex for `:`), so each pair stays readable and distinguishable.
- `SEPARATOR 0x0a` — uses `0x0a` (hex for newline) to separate each *row* of concatenated
  username:password pairs, so the dump prints one credential pair per line.
- Hex literals (`0x3a`, `0x0a`) are used instead of literal `:`/`\n` characters specifically to
  avoid any quote-character filtering the app might apply on raw string literals.

PortSwigger lab mapping (Apprentice): **"SQL injection attack, querying the database type and
version"**, **"SQL injection UNION attack, determining the number of columns returned by the
query"**, **"SQL injection UNION attack, finding a column containing text"**, **"SQL
injection UNION attack, retrieving data from other tables"**, **"SQL injection UNION attack,
retrieving multiple values in a single column"**.

## 2. Error-Based SQLi

Used when UNION isn't viable (e.g., column count mismatch can't be resolved, or output isn't
directly reflected) but the application *does* display raw database error messages.

### 2.1 MySQL — `extractvalue()` / `updatexml()`

```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
```

Breakdown:
- `extractvalue(1, ...)` — first argument `1` is just a dummy XML document; the function's
  real purpose here is abused — we only care about its second argument being evaluated and
  then thrown back in an error because it's invalid XPath.
- `concat(0x7e, (SELECT version()))` — builds the string we want leaked: a `~` delimiter
  followed by the actual subquery result (`SELECT version()`).
- Because this string isn't valid XPath syntax, MySQL raises an `XPATH syntax error` that
  includes the offending string (our concatenated payload) directly in the error message —
  that's the exfiltration channel.

```sql
' AND updatexml(1,concat(0x7e,(SELECT password FROM users LIMIT 1)),1)--
```

Breakdown:
- `updatexml(target_xml, xpath_expr, new_value)` — same abuse pattern as `extractvalue`, but
  `updatexml` takes three args; we only manipulate the second (the XPath expression) since
  that's the one evaluated and leaked on error.
- `(SELECT password FROM users LIMIT 1)` — subquery nested directly inside the payload,
  letting you extract one row at a time without needing UNION's column-matching constraints.
- `LIMIT 1` — restricts the subquery to a single row, since `updatexml`/`extractvalue` can
  only leak one scalar value per call — without this, a multi-row subquery would itself throw
  a "subquery returns more than 1 row" error instead of leaking data.

### 2.2 MSSQL — Type Conversion Errors

```sql
' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--
```

Breakdown:
- `CONVERT(int, ...)` — explicitly casts the subquery's result (a text password value) into
  an integer. Since passwords aren't numeric, this cast always fails.
- The failure message in MSSQL includes the *actual string value* it failed to convert,
  meaning the password is disclosed verbatim in the error text.
- `TOP 1` — MSSQL's row-limiting syntax (equivalent to MySQL's `LIMIT 1`), needed for the same
  reason: the conversion only accepts a single scalar value.

### 2.3 PostgreSQL — Cast Errors

```sql
' AND 1=CAST((SELECT current_user) AS int)--
```

Breakdown:
- `CAST(value AS int)` — PostgreSQL's standard-SQL casting syntax (equivalent role to
  MSSQL's `CONVERT`).
- `(SELECT current_user)` — returns the DB user the connection is running as, a key
  privilege-enumeration data point that gets disclosed in the resulting cast-failure error.

### 2.4 Oracle — `XMLType` Errors

```sql
' AND 1=(SELECT UPPER(XMLType(CHR(60)||(SELECT banner FROM v$version WHERE rownum=1)||CHR(62))) FROM dual)--
```

Breakdown:
- `CHR(60)` / `CHR(62)` — hex-free way to produce `<` and `>` characters, wrapping the leaked
  value as a fake XML tag, since `XMLType()` expects well-formed-looking XML input to attempt
  parsing.
- `XMLType(...)` — attempting to parse a malformed XML string containing the version banner
  triggers a parse error that includes the offending content (the version banner) in the
  message.
- `WHERE rownum=1` — Oracle's pre-12c row-limiting idiom, equivalent purpose to `LIMIT 1`/
  `TOP 1` above.
- `FROM dual` — Oracle requires a `FROM` clause even for constant/scalar selects; `dual` is a
  built-in one-row dummy table used purely to satisfy that syntax requirement.

PortSwigger lab mapping (Apprentice): **"SQL injection attack, querying the database type and
version"** (MSSQL/Oracle variant), and error-based extraction is exercised directly within
**"SQL injection vulnerability allowing login bypass"** when error verbosity permits.

## 3. Real-World Notes

- **Common mistake:** Forgetting to verify column *type* compatibility before assuming a
  UNION column-count match worked — a query that "doesn't error" but also doesn't reflect
  data may mean a type mismatch silently nulled the row in some DBMS configurations.
- **Engagement reality:** Production apps increasingly suppress raw DB errors (generic "500
  Internal Server Error" pages). When that's the case, pivot straight to blind techniques
  (file 03) rather than burning time hunting for error-based feedback that isn't there.
- **Report-writing tip:** For UNION-based findings, include the exact column-count and
  reflected-column discovery steps in an appendix — this demonstrates rigor and helps the dev
  team understand exactly how much of the schema was exposed, not just the final payload.

## Next File
→ `03-blind-sqli.md` — Boolean-based and Time-based blind techniques.
