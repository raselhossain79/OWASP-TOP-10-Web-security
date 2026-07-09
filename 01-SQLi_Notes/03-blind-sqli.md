# Blind SQL Injection — Boolean-Based & Time-Based

## 1. Why "Blind"

No data is reflected in the HTTP response and no DB error is shown. The only signal you get
is an indirect one: a difference in page content/length, HTTP status code, or response timing.
This is the most common real-world scenario against hardened production apps — generic error
pages are standard practice, so assume blind first on any modern target.

## 2. Boolean-Based Blind SQLi

### 2.1 Core Mechanism
Inject a condition that is provably true or false, and observe whether the application's
behavior changes (e.g., "Welcome back" vs. nothing, 200 vs. 302, a longer vs. shorter page).

### 2.2 Confirming the Injection Point

```sql
' AND 1=1--
' AND 1=2--
```

Breakdown:
- `AND 1=1` — a condition that is always true; appended to the original `WHERE` clause it
  should not change the original result set's truth value, so the page should render
  identically to a baseline request with no payload.
- `AND 1=2` — always false; if this consistently produces a *different* response (different
  page, empty result, redirect) than the `1=1` case, you've confirmed the input is reaching
  a live, executable `WHERE` clause — i.e., the injection point is real and exploitable.
- `--` — comments out any trailing original SQL so the modified query remains valid.

### 2.3 Extracting Data One Bit/Character At A Time

**Step 1 — confirm table/column exists:**

```sql
' AND (SELECT 'a' FROM users LIMIT 1)='a'--
```

Breakdown:
- `(SELECT 'a' FROM users LIMIT 1)` — a subquery that only succeeds (returns a row) if the
  `users` table exists and contains at least one row; `LIMIT 1` keeps it to a single
  comparable value as required by the `=` operator.
- `='a'` — compares the subquery's literal output against the same literal; this isn't really
  testing data, it's testing whether the subquery *executes without error*, confirming the
  table exists and is non-empty.

**Step 2 — extract data character by character using `SUBSTRING`:**

```sql
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
```

Breakdown:
- `SUBSTRING(string, start, length)` — extracts a portion of the password value: starting at
  position `1`, taking `1` character.
- `(SELECT password FROM users WHERE username='admin')` — the subquery target: the password
  belonging to a specific known user, narrowed by the `WHERE` filter so it returns exactly one
  value (required, since `SUBSTRING` can't operate on multiple rows).
- `='a'` — the guess. If the response matches the "true" baseline behavior, character 1 of
  the password is `a`. Iterate through the alphabet/charset for position 1, then increment
  the start position (`2`, `3`, ...) and repeat until a guess returns no character (end of
  string reached), and you've extracted the full password.
- In practice this is automated (Burp Intruder cluster bomb, or sqlmap — see file 07), never
  done manually character-by-character on a real engagement — included here purely so the
  underlying mechanism is understood before automating it.

**Binary search variant (faster than linear character guessing) using `ASCII`:**

```sql
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>109--
```

Breakdown:
- `ASCII(char)` — converts the extracted single character into its numeric ASCII code,
  enabling numeric comparison instead of testing 26+ individual letter guesses per position.
- `>109` — a midpoint guess (109 = ASCII `m`); halving the remaining range each time
  (binary search) finds the exact character in ~7 requests instead of up to 95 (full
  printable ASCII range), versus a linear scan.

PortSwigger lab mapping (Practitioner): **"Blind SQL injection with conditional responses"**,
**"Blind SQL injection with conditional errors"**.

## 3. Boolean-Based — Conditional Errors Variant

When there's no visible content difference but the app *does* throw a generic 500 on DB
errors (without leaking error text), force an error only when the condition is true:

```sql
' AND (SELECT CASE WHEN (1=1) THEN (SELECT 1 FROM information_schema.tables) ELSE 1/0 END)--
```

Breakdown:
- `CASE WHEN condition THEN x ELSE y END` — standard SQL conditional expression.
- `WHEN (1=1)` — the condition being tested (replace with your actual data-dependent test,
  e.g., `(SELECT username FROM users LIMIT 1)='admin'`).
- `THEN (SELECT 1 FROM information_schema.tables)` — a harmless, always-valid subquery
  executed when the condition is true — the response renders normally.
- `ELSE 1/0` — division by zero, which is a guaranteed, deliberate database error when the
  condition is false — the app throws its generic error page, giving you a binary true/false
  signal without ever seeing real error text or real data.

PortSwigger lab mapping (Practitioner): **"Blind SQL injection with conditional errors"**.

## 4. Time-Based Blind SQLi

### 4.1 When To Use It
Used when there's *no* observable difference at all between true/false conditions — identical
page content, identical status code, identical length. The only remaining signal is response
time, by deliberately injecting a conditional delay.

### 4.2 MySQL

```sql
' AND IF(1=1,SLEEP(5),0)--
```

Breakdown:
- `IF(condition, true_value, false_value)` — MySQL's inline conditional function.
- `SLEEP(5)` — pauses query execution for 5 seconds; only executed when the condition (`1=1`)
  is true. If the HTTP response takes ~5 seconds longer than baseline, the condition was true.
- `0` — a trivial false-branch value (no delay), so a false condition returns near-instantly.
- 5 seconds (not 1) is chosen deliberately to produce a clear, unambiguous signal distinct
  from normal network jitter/latency noise.

Extracting data via time-based (same `SUBSTRING` logic as boolean-based, but the *signal* is
delay instead of content difference):

```sql
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--
```

Breakdown: identical structure to the boolean-based character extraction in section 2.3, with
the comparison result fed into `IF(...)` so a correct guess triggers a 5-second delay instead
of a content change.

### 4.3 MSSQL

```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

Breakdown:
- `;` — MSSQL supports stacked queries by default in many drivers, allowing a second
  statement after the original query (see file 08 for full stacked-query coverage).
- `IF (1=1) WAITFOR DELAY '0:0:5'` — MSSQL's conditional + delay syntax; `WAITFOR DELAY` takes
  a `'HH:MM:SS'` time literal, here pausing 5 seconds if the condition holds.

### 4.4 PostgreSQL

```sql
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

Breakdown:
- `pg_sleep(seconds)` — PostgreSQL's native delay function, the equivalent of MySQL's
  `SLEEP()`.
- Wrapped in `CASE WHEN` (same conditional pattern as section 3) since `pg_sleep` itself takes
  no condition argument — Postgres needs the conditional logic expressed separately.

### 4.5 Oracle

```sql
' AND 1=(SELECT CASE WHEN (1=1) THEN dbms_lock.sleep(5) ELSE 1 END FROM dual)--
```

Breakdown:
- `dbms_lock.sleep(5)` — Oracle's native delay procedure (requires `EXECUTE` privilege on the
  `DBMS_LOCK` package; if it errors with "insufficient privileges," try `dbms_pipe.receive_message` as a fallback delay primitive instead).
- Same `CASE WHEN` + `FROM dual` pattern explained in files 01/02.

PortSwigger lab mapping (Practitioner): **"Blind SQL injection with time delays"**, **"Blind
SQL injection with time delays and information retrieval"**.

## 5. Real-World Notes

- **Common mistake:** Using a delay that's too short (e.g., `SLEEP(1)`) — easily lost in
  normal network jitter, producing false negatives. 5 seconds is a reasonable default; raise
  it on high-latency or rate-limited targets.
- **Engagement reality:** Time-based extraction is *slow* — character-by-character over a slow
  network can take hours for a single column. Always hand this off to sqlmap (file 07) for any
  real extraction; manual time-based testing is for *confirming* the vector only.
- **Operational risk:** Time-based payloads can degrade application performance for other
  users if run aggressively (many concurrent threads × multi-second sleeps). Throttle request
  concurrency during testing windows, especially on client-shared/production environments —
  note this explicitly in the engagement rules of engagement (RoE) and in the report.
- **Report-writing tip:** For blind findings, always include the literal *time delta* observed
  (e.g., "baseline 240ms, payload response 5,240ms") as evidence — this is far more convincing
  to a technical reviewer than just stating "time-based blind SQLi confirmed."

## Next File
→ `04-oob-sqli.md` — Out-of-band SQLi via DNS/HTTP exfiltration channels.
