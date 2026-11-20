# Reflected Cross-Site Scripting (XSS) — JavaScript String Injection

## 1. Summary

The search functionality of the target application was found to be vulnerable to Reflected Cross-Site Scripting (XSS) through JavaScript string injection.

During testing, the application reflected user-controlled input inside a JavaScript string within an HTML response. Although angle brackets (`<` and `>`) were HTML-encoded, the application did not properly escape single quotation marks (`'`).

This allowed an attacker to break out of the existing JavaScript string and inject executable JavaScript statements.

A harmless JavaScript payload using `alert(document.domain)` was submitted through the `search` parameter. The browser executed the injected JavaScript and displayed an alert containing the application's domain, confirming the vulnerability.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** Reflected Cross-Site Scripting (XSS)
- **Injection technique:** JavaScript String Breakout
- **Affected context:** JavaScript string inside an HTML `<script>` block
- **Affected endpoint:** `/`
- **Affected parameter:** `search`
- **HTTP method:** GET
- **Target URL:** `https://0abc003703eb6de180b017e100870055.web-security-academy.net/`

## 3. Severity (CVSS)

**Suggested Severity:** Medium

**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Base Score:** 6.1 (Medium)

**Rationale:**

- **Attack Vector: Network** – The vulnerable search functionality is accessible remotely over HTTP/HTTPS.
- **Attack Complexity: Low** – Exploitation requires a specially crafted URL containing a JavaScript string breakout payload.
- **Privileges Required: None** – No authentication is required to access the vulnerable functionality.
- **User Interaction: Required** – A victim must visit the maliciously crafted URL for the injected JavaScript to execute.
- **Scope: Changed** – The injected JavaScript executes in the security context of the vulnerable application's origin.
- **Confidentiality: Low** – Depending on the victim's permissions and accessible application data, injected JavaScript may expose sensitive information.
- **Integrity: Low** – An attacker may perform unauthorized actions through the victim's browser within the application's security context.
- **Availability: None** – No availability impact was demonstrated.

*Note: This is an illustrative severity assessment for the lab. A real-world CVSS score requires evaluating the actual application's security context and impact.*

## 4. Steps to Reproduce

1. Navigated to the target application and identified the search functionality.

2. Intercepted the search request using Caido.

3. Initially submitted a unique marker string through the `search` parameter:

   `GET /?search=zzXSS12345zz`

4. Inspected the server response and identified that the supplied input was reflected inside a JavaScript string within an HTML `<script>` block.

5. Tested angle brackets (`<` and `>`) and observed that they were HTML-encoded.

6. Identified the JavaScript string context and attempted to break out of it using a double quote (`"`).

7. Observed that double quotes were also encoded, preventing the intended string breakout.

8. Tested a single quote (`'`) and determined that it was not properly escaped.

9. Constructed the following JavaScript string breakout payload:

   `';alert(document.domain);//`

10. Submitted the payload through the `search` parameter:

    `GET /?search=';alert(document.domain);//`

11. Inspected the server response and observed that the injected JavaScript was reflected inside the script block:

    ```javascript
    var searchTerms = '';alert(document.domain);//';
    ```

12. Opened the resulting URL in the browser and observed an alert displaying the application's domain.

13. This confirmed successful Reflected XSS exploitation through JavaScript string injection.

## 5. Proof of Concept (PoC)



## 6. Impact

Successful exploitation of this vulnerability could allow an attacker to:

- Execute arbitrary JavaScript in a victim's browser under the vulnerable application's origin.
- Manipulate page content and modify the appearance of the application.
- Perform unauthorized actions on behalf of an authenticated victim, depending on the application's functionality and security controls.
- Potentially access sensitive information available to the victim's browser context.
- Conduct phishing attacks by injecting misleading content into legitimate application pages.

The actual impact depends on the victim's privileges, application functionality, and browser-side security controls.

## 7. Remediation

- **Implement context-aware output encoding:** Properly escape user-controlled input before inserting it into JavaScript strings.
- **Escape JavaScript string delimiters:** Ensure single quotes, double quotes, backslashes, and other relevant characters are safely handled according to JavaScript string context.
- **Avoid embedding untrusted data directly in JavaScript:** Prefer passing data through safely encoded JSON or external data structures.
- **Use secure templating:** Utilize template engines that correctly handle context-specific output escaping.
- **Avoid unsafe JavaScript execution:** Do not use unsafe dynamic code execution methods such as `eval()` with user-controlled input.
- **Apply Content Security Policy (CSP):** Implement a restrictive CSP to reduce the impact of successful script injection.

## 8. References

- [OWASP – Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger – Reflected Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger – XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
