# SQL Injection — Overview & Classification

> Part of the OWASP Top 10 Injection Category (A03:2021 — Injection)

## 1. What SQL Injection Actually Is

SQL Injection (SQLi) happens when user-controlled input is concatenated directly into a SQL
query string instead of being passed as a parameterized value. The database cannot tell the
difference between "data" and "code" — it just sees a string of SQL syntax and executes it.

Example of the root cause (PHP/MySQL, vulnerable pattern):

```php
$query = "SELECT * FROM users WHERE username = '" . $_GET['username'] . "'";
```

Breakdown of why this is broken:
- `$_GET['username']` — raw, attacker-controlled input pulled straight from the URL query
  string. Nothing validates or escapes it before use.
- `" . ... . "` — PHP string concatenation. The input is glued directly into the SQL text,
  meaning any quote characters or SQL keywords inside the input become part of the query
  itself, not data.
- The surrounding single quotes (`'...'`) are meant to delimit a string literal, but if the
  input itself contains a `'`, that quote closes the literal early and anything after it is
  interpreted as SQL syntax by the parser.

If an attacker sends `' OR '1'='1`, the resulting query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1'
```

Breakdown:
- `''` — closes the original string literal early using the injected leading quote.
- `OR '1'='1'` — adds a tautology (always-true condition) joined with `OR`, so the `WHERE`
  clause evaluates to true for every row regardless of the original `username` filter.
- Net effect: the query returns all rows in the `users` table instead of just one.

This is the seed mechanism behind every SQLi variant covered in this series — only the
*delivery method* and *feedback channel* change between types.

## 2. Why This Matters On Real Engagements

On a real assessment, SQLi is rarely "found and forgotten." It's usually the pivot point:
- Auth bypass → access to an admin panel
- Data extraction → PII/credential dumps for the report's impact section
- File read (`LOAD_FILE`, `xp_cmdshell`, etc.) → source code disclosure or code execution
- It frequently chains into full RCE on the underlying host (see file 08)

Report-writing note: clients care less about "I bypassed login" and more about *business
impact* — "an unauthenticated attacker could extract the full customer database including
hashed passwords and PII, and had a path to host-level code execution." Always frame findings
this way, not just as a technical curiosity.

## 3. Classification of SQLi Types

### 3.1 In-Band SQLi
The attack and the result travel over the *same channel* — you send the payload, you see the
result in the HTTP response.
- **UNION-based** — append a `UNION SELECT` to pull extra columns of data directly into the
  page output.
- **Error-based** — force the database to throw an error that leaks data inside the error
  message itself (e.g., MySQL `extractvalue()`, MSSQL conversion errors).

### 3.2 Blind SQLi
No data is reflected in the response. You infer truth/falsehood indirectly.
- **Boolean-based** — inject a condition; the page behaves differently (different content,
  HTTP status, response length) depending on whether the condition is true or false.
- **Time-based** — inject a conditional delay (e.g., `SLEEP(5)`); if the response takes
  longer, the condition was true. Used when there's zero visible difference in output.

### 3.3 Out-of-Band (OOB) SQLi
The database is made to exfiltrate data over a *different* protocol entirely — typically DNS
or HTTP — because the in-band/blind channels are unusable (no error display, no timing signal
due to query timeouts, etc.).

### 3.4 Second-Order (Stored) SQLi
The payload is stored in the database from one input point (e.g., a "display name" field) and
the injection only *triggers* later, when a different part of the application reads and uses
that stored value unsafely in a separate query.

## 4. Database Fingerprinting (First Step On Any Engagement)

Before choosing a technique, identify the backend DBMS — syntax differs significantly.

| DBMS | Version string syntax | Comment syntax | String concat |
|---|---|---|---|
| MySQL/MariaDB | `SELECT @@version` | `-- `, `#`, `/*...*/` | `CONCAT(a,b)` |
| PostgreSQL | `SELECT version()` | `--`, `/*...*/` | `a || b` |
| MSSQL | `SELECT @@version` | `--`, `/*...*/` | `a + b` |
| Oracle | `SELECT banner FROM v$version` | `--`, `/*...*/` | `a \|\| b` |

Quick fingerprint payload (universal starting point):

```sql
' AND 1=CONVERT(int,@@version)--
```

Breakdown:
- `'` — closes the string literal context, same mechanism as section 1.
- `AND 1=CONVERT(int,@@version)` — forces an explicit type cast of the DBMS version string
  (text) into an integer. This cast is intentionally invalid.
- `CONVERT(int, ...)` is **MSSQL-specific** syntax — if the error message returned mentions
  "CONVERT" or shows the actual version text inside a conversion error, you've confirmed
  MSSQL. If the function is unrecognized, try the MySQL/Postgres equivalents below.
- `--` — MSSQL/MySQL line comment, used to neutralize whatever SQL the application appends
  after your injected value (commonly a trailing `'` or `LIMIT` clause), so the query remains
  syntactically valid.

MySQL equivalent fingerprint:

```sql
' AND extractvalue(1,concat(0x7e,@@version))--
```

Breakdown:
- `extractvalue(1, concat(0x7e, @@version))` — `extractvalue()` is a MySQL XML function
  that expects a valid XPath in its second argument. `@@version` is not valid XPath syntax,
  so MySQL throws an XPATH syntax error and, as a side effect, includes the value of
  `concat(0x7e, @@version)` in the error text.
- `0x7e` — hex for `~` (tilde), used purely as a visual delimiter in the error output so the
  version string is easy to spot among other error text.
- `concat()` — MySQL string concatenation function, joins the delimiter and the version
  string into one value passed to `extractvalue()`.

## 5. Real-World Notes (apply throughout the series)

- **Common mistake #1:** Testing only with `'` and giving up if it doesn't error. Many modern
  frameworks (ORMs, prepared statement wrappers) block quotes but still pass numeric, JSON, or
  header-based input unsafely — always test multiple injection contexts (see file 08).
- **Common mistake #2:** Assuming WAF presence means "not exploitable." A WAF blocks known
  patterns, not the underlying logic flaw — see file 06 for manual bypass.
- **Report-writing tip:** Always state the exact parameter, HTTP method, and a *single*
  reproducible proof-of-concept request/response pair. Reviewers and devs fixing the bug need
  the minimum viable repro, not the entire enumeration history.

## 6. PortSwigger Academy Mapping (Topic Overview)

This series follows the Academy's own difficulty progression. Full lab-by-lab mapping lives
in file `09-cheatsheet-lab-mapping.md`, but by category:

- **SQL injection** topic (Apprentice → Practitioner → Expert) → covered across files 02–05, 08
- **SQL injection (Blind)** is technically the same Academy topic, just deeper labs

## Next File
→ `02-in-band-sqli.md` — UNION-based and Error-based techniques, full payload breakdowns.
