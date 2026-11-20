# Reflected Cross-Site Scripting (XSS)

## 1. Summary

The search functionality of the target application was found to be vulnerable to Reflected Cross-Site Scripting (XSS).

By submitting a specially crafted JavaScript payload through the `search` parameter, the application reflected the supplied input into the HTML response without properly neutralizing the injected script.

During testing, a harmless JavaScript payload using `alert(document.domain)` was submitted. The browser executed the injected JavaScript, confirming that an attacker could inject and execute arbitrary JavaScript in the context of the application's origin.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** Reflected Cross-Site Scripting (XSS)
- **Affected endpoint:** `/`
- **Affected parameter:** `search`
- **HTTP method:** GET
- **Target URL:** `https://0a550001045dba94804a1712005f0030.web-security-academy.net/`

## 3. Severity (CVSS)

**Suggested Severity:** Medium

**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Base Score:** 6.1 (Medium)

**Rationale:**

- **Attack Vector: Network** – The vulnerable search functionality is accessible remotely over HTTP/HTTPS.
- **Attack Complexity: Low** – Exploitation requires a specially crafted URL containing a JavaScript payload.
- **Privileges Required: None** – No authentication is required to access the vulnerable functionality.
- **User Interaction: Required** – A victim must visit a maliciously crafted URL for the payload to execute.
- **Scope: Changed** – The injected JavaScript executes in the security context of the vulnerable application's origin.
- **Confidentiality: Low** – Depending on the victim's permissions and accessible application data, injected JavaScript may expose sensitive information.
- **Integrity: Low** – An attacker may perform unauthorized actions through the victim's browser within the application's security context.
- **Availability: None** – No availability impact was demonstrated.

## 4. Steps to Reproduce

1. Navigated to the target application and identified the search functionality.

2. Intercepted the search request using Caido.

3. Initially submitted a unique marker string (`zzXSS12345zz`) through the `search` parameter:

   `GET /?search=zzXSS12345zz`

4. Inspected the server response and identified that the supplied marker was reflected inside the HTML response body.

5. Based on the reflection location, determined that the input was being inserted into an HTML context.

6. Submitted a JavaScript test payload through the same parameter:

   `GET /?search=<script>alert(document.domain)</script>`

7. Observed that the browser executed the injected JavaScript and displayed an alert containing the application's domain.

8. This confirmed that the application was vulnerable to Reflected  XSS through the `search` parameter.

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

- **Implement context-aware output encoding:** Properly HTML-encode untrusted user input before inserting it into HTML responses.
- **Avoid unsafe HTML insertion:** Do not insert untrusted input directly into HTML using unsafe DOM methods such as `innerHTML`.
- **Use secure templating:** Utilize template engines that automatically escape user-controlled output.
- **Apply Content Security Policy (CSP):** Implement a restrictive CSP to reduce the impact of successful script injection.
- **Validate input:** Apply appropriate server-side input validation based on the expected input format.
- **Use safe DOM APIs:** Prefer `textContent` instead of `innerHTML` when displaying user-controlled text.

## 8. References

- [OWASP – Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger – Reflected Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [OWASP – Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
