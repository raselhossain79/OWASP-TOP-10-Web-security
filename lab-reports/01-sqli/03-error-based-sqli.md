# PostgreSQL Error-Based SQL Injection via TrackingId Cookie

## 1. Summary

During testing of the target web application, an Error-Based SQL Injection vulnerability was identified in the `TrackingId` cookie associated with the `/filter` endpoint.

The application processed user-controlled cookie input as part of a backend SQL query without properly handling it.

By exploiting PostgreSQL type conversion errors using the `CAST()` function, it was possible to extract username and password values from the `users` table.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** SQL Injection (Error-Based)
- **DBMS:** PostgreSQL
- **Affected endpoint:** `/filter`
- **Affected parameter:** `TrackingId` (Cookie)
- **HTTP method:** GET
- **Target URL:** `https://0a41001803b7595e80f3c10c00ef00b8.web-security-academy.net/filter?category=Gifts`

## 3. Severity (CVSS)

**Severity:** High

**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Base Score:** 7.5 (High)

**Rationale:**
- **Attack Vector: Network** – The vulnerability is exploitable remotely through an HTTP request.
- **Attack Complexity: Low** – No special conditions were required to exploit the injection point.
- **Privileges Required: None** – The vulnerable functionality was accessible without authentication.
- **User Interaction: None** – No additional user interaction was required.
- **Confidentiality: High** – Username and password values were successfully extracted from the database.
- **Integrity: None** – No data modification was demonstrated.
- **Availability: None** – No availability impact was demonstrated.

## 4. Steps to Reproduce

1. Accessed the target application and identified the `/filter` endpoint.

2. Intercepted the HTTP GET request and located the `TrackingId` cookie.

   ```http
   GET /filter?category=Gifts HTTP/2
   Host: 0a41001803b7595e80f3c10c00ef00b8.web-security-academy.net
   Cookie: TrackingId=<value>; session=<value>
   ```

3. Tested the `TrackingId` cookie for SQL injection and identified PostgreSQL-specific error behavior.

4. Used PostgreSQL's `current_user` expression with `CAST()` to trigger a type conversion error and expose the database user:

   ```sql
   ' AND 1=CAST((SELECT current_user) AS int)-- -
   ```

5. Kept the original `TrackingId` value empty to avoid conflicts with the injected SQL expression.

6. Retrieved the first username from the `users` table using the following payload:

   ```sql
   'AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)-- -
   ```

   The conversion error exposed the selected username.

7. Retrieved the corresponding password value using:

   ```sql
   'AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- -
   ```

   The resulting conversion error exposed the selected password value.

8. Successfully demonstrated that database values could be extracted through PostgreSQL error messages.

## 5. Proof of Concept (Payload and Result)

 

## 6. Impact

An attacker exploiting this vulnerability may be able to:

- Extract sensitive information from database tables.
- Retrieve usernames and password-related values.
- Expose additional database information depending on the database account's privileges.
- Potentially compromise user accounts if the extracted credentials are valid and usable.

The demonstrated impact primarily affects the confidentiality of database information.

## 7. Remediation

- Use **parameterized queries / prepared statements** for all database operations involving user-controlled input.
- Never concatenate cookie values directly into SQL statements.
- Apply strict input validation to the `TrackingId` cookie according to its expected format.
- Enforce the **principle of least privilege** for the application's database account.
- Prevent detailed database error messages from being exposed to external users.
- Store passwords using strong, salted password hashing algorithms such as Argon2id or bcrypt.
- Conduct regular code reviews and security testing to identify SQL injection vulnerabilities.

## 8. References

- [OWASP – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger – SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PostgreSQL – SQL Expressions](https://www.postgresql.org/docs/current/sql-expressions.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
