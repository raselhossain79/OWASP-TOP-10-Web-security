# SQL Injection – Authentication Bypass

## 1. Summary
The login functionality of the target application was found to be vulnerable to SQL Injection in the `username` field. By injecting SQL syntax into the username input, an attacker was able to bypass the authentication mechanism entirely and log in as the `administrator` user without valid credentials.

## 2. Vulnerability Type and Affected Endpoint/Parameter
- **Vulnerability type:** SQL Injection (Authentication Bypass)
- **Affected endpoint:** `/login`
- **Affected parameter:** `username`
- **Target URL:** `https://0ac3007704ec353281e6713000da0049.web-security-academy.net/login`

## 3. Severity (CVSS)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**Base Score:** 9.1 (Critical)

**Rationale:**
- **Attack Vector: Network** – The login form is reachable and exploitable remotely.
- **Attack Complexity: Low** – The bypass required only a simple, well-known injection payload in the username field.
- **Privileges Required: None** – The attacker starts with no valid account or credentials.
- **User Interaction: None** – No action from another user is required.
- **Confidentiality: High** – The attacker gains access to the `administrator` account, exposing all data and functionality available to that privileged user.
- **Integrity: High** – As an authenticated administrator, the attacker could potentially modify application data or settings (not tested, but implied by the privilege level gained).
- **Availability: None** – No impact on availability was observed or attempted.

## 4. Steps to Reproduce
1. Navigated to the login page at the target URL.
2. In the `username` field, entered the value `administrator' AND 1=1 -- `, and entered any arbitrary value in the `password` field (the form required a non-empty value but did not validate it).
3. Submitted the login form. The application responded by logging the session in as **administrator**, confirming the injection manipulated the backend authentication query to bypass the password check.
4. Repeated the test using a second payload, this time with an intentionally incorrect/arbitrary username value combined with `' OR 1=1 -- ` (instead of the valid `administrator` username), and an arbitrary password value.
5. Submitted the form again. This payload also resulted in the application logging the session in as **administrator**, confirming that the `OR 1=1` condition caused the query to match the first user record (or otherwise satisfy the login check) regardless of the username supplied.

## 5. Proof of Concept (Payload and Result)
*Not included in this writeup.

**Payloads used (username field, password field = arbitrary value):**
- `administrator' AND 1=1 -- ` → Result: Logged in as administrator
- `<arbitrary/incorrect username>' OR 1=1 -- ` → Result: Logged in as administrator

## 6. Impact
Exploitation of this vulnerability allows an unauthenticated attacker to:
- Bypass the authentication mechanism entirely without knowledge of a valid password.
- Gain access to a privileged account (`administrator`), potentially exposing sensitive data and administrative functionality.
- Depending on what the administrator account can access/modify, this could lead to full application compromise, including unauthorized data disclosure, data tampering, or further privilege escalation.

## 7. Remediation
- Use **parameterized queries / prepared statements** for all authentication logic. User-supplied input must never be concatenated directly into SQL queries.
- Implement **server-side input validation** to reject unexpected characters (such as quotes and SQL comment sequences) in login fields where they are not legitimately needed.
- Use a vetted authentication library or framework component that handles credential verification securely rather than building custom SQL-based login logic.
- Enforce **account lockout / rate limiting** on login attempts to reduce the impact of brute-force or injection-based bypass attempts.
- Apply the **principle of least privilege** to the database account used by the login functionality.
- Perform regular security testing (manual and automated) on all authentication flows.

## 8. References
- [OWASP – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger Web Security Academy – Authentication bypass via SQL injection](https://portswigger.net/web-security/sql-injection)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
