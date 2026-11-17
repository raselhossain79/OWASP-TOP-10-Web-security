# SQL Injection – UNION-Based Data Extraction via XML Encoding WAF Bypass

## 1. Summary

During testing of the stock-check functionality, a SQL Injection vulnerability was identified in the `storeId` parameter of the `/product/stock` endpoint.

The application accepts XML-formatted requests and processes user-controlled values without properly preventing SQL injection.

A Web Application Firewall (WAF) was present and blocked requests containing recognizable SQL injection patterns. However, XML hexadecimal character references were used to obfuscate SQL keywords, allowing the XML parser to decode the payload before it reached the backend SQL query.

By exploiting this behavior, it was possible to perform a UNION-based SQL injection and extract sensitive information, including usernames and passwords from the `users` table.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** SQL Injection (UNION-based)
- **WAF bypass technique:** XML Hexadecimal Character Reference Encoding
- **Affected endpoint:** `/product/stock`
- **Affected parameter:** `storeId`
- **HTTP method:** POST
- **Content-Type:** `application/xml`
- **Target URL:** `https://0aa4001a045969df811cdf26001c00f9.web-security-academy.net/product/stock`

## 3. Severity (CVSS)

**Suggested Severity:** High

**CVSS v3.1 Vector:** To be determined based on the application's authentication requirements, database privileges, and actual deployment impact.

**Rationale:**

- **Attack Vector: Network** – The vulnerability can be triggered through an HTTP request.
- **Attack Complexity:** Requires bypassing the WAF using XML character references.
- **Privileges Required:** Depends on the endpoint's authentication requirements.
- **User Interaction:** None observed.
- **Confidentiality: High** – Sensitive database records, including usernames and passwords, were successfully retrieved.
- **Integrity:** Not demonstrated.
- **Availability:** Not demonstrated.

## 4. Steps to Reproduce

1. Intercepted the stock-check request to `/product/stock` and identified that the application accepts XML-formatted input.

2. Identified the following XML structure:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <stockCheck>
       <productId>2</productId>
       <storeId>1</storeId>
   </stockCheck>
   ```

3. Tested the `storeId` parameter with SQL injection syntax and observed that the WAF detected and blocked recognizable SQL injection payloads.

4. Tested XML hexadecimal character references to understand how the WAF and XML parser handled encoded characters.

5. Used XML hexadecimal character reference encoding to obfuscate SQL keywords, allowing the SQL payload to pass the WAF inspection.

6. Confirmed the UNION-based injection by testing a single-column `UNION SELECT NULL` payload.

7. Identified that the original SQL query accepts one column in the UNION result.

8. Used the following SQL statement to retrieve usernames and passwords from the `users` table:

   ```sql
   UNION SELECT username || '~' || password FROM users
   ```

9. Encoded the SQL statement using XML hexadecimal character references and supplied it through the `storeId` parameter.

10. Observed the HTTP response containing the following extracted database records:

   ```text
   wiener~n2301nqqyv8ihdu7gnzt
   administrator~5ksr36uv0is8xnrvjne8
   carlos~h33krtfgmbly83tncv51
   ```

11. Successfully retrieved the database records, confirming the SQL injection vulnerability and completing the lab.

## 5. Proof of Concept (Payload and Result)

*Not included in this writeup.*

## 6. Impact

Exploitation of this vulnerability could allow an attacker to:

- Bypass WAF inspection through XML hexadecimal character reference encoding.
- Manipulate backend SQL queries through the vulnerable `storeId` parameter.
- Retrieve sensitive information from database tables.
- Extract usernames and password values stored in the `users` table.
- Potentially compromise user accounts if extracted credentials are valid and reusable.
- Access additional database information depending on the database account's privileges.

The demonstrated impact is primarily unauthorized database information disclosure.

## 7. Remediation

- **Use parameterized queries:** Implement prepared statements for all database operations involving user-controlled input.
- **Validate XML input:** Apply strict validation to XML elements and their expected data types.
- **Normalize before filtering:** Ensure security inspection considers the decoded and normalized representation of XML input.
- **Avoid relying solely on WAF rules:** A WAF should be treated as an additional security layer, not as a replacement for secure SQL query construction.
- **Apply least privilege:** Restrict database accounts to only the permissions required by the application.
- **Protect credentials:** Store passwords using secure, salted password hashing algorithms such as Argon2id or bcrypt.
- **Perform security testing:** Regularly test XML-based endpoints for injection vulnerabilities and inconsistent input-processing behavior.

## 8. References

- [OWASP – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger – SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [PortSwigger – SQL Injection](https://portswigger.net/web-security/sql-injection)
- [W3C – XML 1.0 Specification](https://www.w3.org/TR/xml/)
- [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
