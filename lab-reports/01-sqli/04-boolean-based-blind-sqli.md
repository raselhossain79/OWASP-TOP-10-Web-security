# SQL Injection – Boolean-Based Blind SQL Injection, Password Extraction

## 1. Summary

During security testing of the target web application, a Boolean-Based Blind SQL Injection vulnerability was identified in the `TrackingId` cookie parameter of the root (`/`) endpoint.

The application did not directly return database query results or SQL error messages. However, it was possible to manipulate the backend SQL query using conditional SQL expressions and observe differences in the application's responses.

By comparing responses for TRUE and FALSE conditions, the SQL injection vulnerability was confirmed.

Further exploitation using `ASCII()` and `SUBSTRING()` allowed character-by-character extraction of the administrator's password from the `users` table.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** SQL Injection (Boolean-Based Blind)
- **Affected endpoint:** `/`
- **HTTP method:** GET
- **Affected parameter:** `TrackingId` (Cookie)
- **Target URL:** `https://0a4b002103b4a60d809308670046005b.web-security-academy.net/`

## 3. Severity (CVSS)

**Provisional CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Provisional Base Score:** 7.5 (High)

**Rationale:**

- **Attack Vector: Network** – The vulnerability can be exploited remotely through an HTTP request.
- **Attack Complexity: Low** – Exploitation requires modifying the vulnerable cookie parameter and observing application responses.
- **Privileges Required: None** – No additional application privileges were required in the tested scenario.
- **User Interaction: None** – The attacker can trigger the vulnerability directly.
- **Confidentiality: High** – Sensitive information, including the administrator's password, could be extracted.
- **Integrity: None** – No data modification was demonstrated.
- **Availability: None** – No denial-of-service impact was demonstrated.

*Note: This is a provisional assessment based on the demonstrated lab impact. A real-world assessment should consider the application's authentication requirements, deployment context, and confirmed business impact.*

## 4. Steps to Reproduce

### Step 1: Identify the Injection Point

1. Opened the target application and captured a normal HTTP request.
2. Inspected the request cookies and identified the `TrackingId` parameter as a potential injection point.
3. Modified the cookie value and tested SQL injection conditions.

Example request:

```http
GET / HTTP/1.1
Host: 0a4b002103b4a60d809308670046005b.web-security-academy.net
Cookie: TrackingId=<valid-value>' AND 1=1--; session=<session-value>
```

### Step 2: Confirm Boolean-Based SQL Injection

First, tested a condition that evaluates to TRUE:

```sql
' AND 1=1--
```

The application returned its normal TRUE-condition response.

Next, tested a condition that evaluates to FALSE:

```sql
' AND 1=2--
```

The application returned a different response.

The difference between the TRUE and FALSE responses indicated that the injected SQL condition was influencing the application's behavior.

### Step 3: Identify the Administrator's Password

After confirming the Boolean-based SQL injection, used conditional expressions to extract information from the database.

The following payload checks whether the second character of the administrator's password has ASCII value `107`:

```sql
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),2,1))=107--
```

**Payload breakdown:**

- `SELECT password FROM users` – Retrieves the password column from the users table.
- `WHERE username='administrator'` – Selects the administrator's record.
- `SUBSTRING(...,2,1)` – Extracts one character starting at position 2.
- `ASCII(...)` – Converts the extracted character into its ASCII decimal value.
- `=107` – Checks whether the character's ASCII value is 107.

### Step 4: Automate Character Extraction

Used Caido Automate to automate the extraction process.

Two numeric payload positions were configured:

1. **Character Position:** Iterated through the password positions.
2. **ASCII Value:** Tested possible ASCII values from 32 to 126.

Used the Matrix strategy to test combinations of character positions and ASCII values.

By identifying the TRUE-condition responses, the corresponding ASCII values for each password character were obtained.

### Step 5: Decode the Extracted Password

Converted the extracted ASCII decimal values into their corresponding characters.

The extracted password was:

```text
lpk8g3b2fe9537sscq84
```

This confirmed successful character-by-character extraction of the administrator's password.

## 5. Proof of Concept (Payload and Result)

**TRUE condition:**

```sql
' AND 1=1--
```

**FALSE condition:**

```sql
' AND 1=2--
```

**Character extraction:**

```sql
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),2,1))=107--
```

**Result:**

The application responded differently to TRUE and FALSE conditions. Automated character extraction successfully recovered the administrator's password.

## 6. Impact

Exploitation of this vulnerability could allow an attacker to:

- Extract sensitive database information without directly viewing database query results.
- Retrieve usernames and passwords stored in the database.
- Obtain administrator credentials, potentially enabling unauthorized account access.
- Perform further database enumeration depending on the database user's privileges and accessible data.

Although the application did not directly display database errors or query results, response differences provided a reliable channel for extracting sensitive information.

## 7. Remediation

- Use parameterized queries or prepared statements for all database interactions involving user-controlled input.
- Never concatenate cookie values directly into SQL statements.
- Treat all client-controlled values, including tracking cookies, as untrusted input.
- Apply strict input validation where appropriate.
- Enforce the principle of least privilege for database accounts.
- Store passwords using strong salted password-hashing algorithms such as Argon2id or bcrypt.
- Implement security testing and code reviews to identify SQL injection vulnerabilities.
- Use a Web Application Firewall as an additional defensive layer, not as a replacement for secure SQL query construction.

## 8. References

- [OWASP – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger – Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [PortSwigger – SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [CWE-89 – Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
