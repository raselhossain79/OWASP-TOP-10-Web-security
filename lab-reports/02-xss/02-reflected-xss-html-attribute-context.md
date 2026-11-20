# Reflected Cross-Site Scripting (XSS) — HTML Attribute Injection

## 1. Summary

The search functionality of the target application was found to be vulnerable to Reflected Cross-Site Scripting (XSS) through an HTML attribute injection vulnerability.

During testing, the application reflected user-controlled input inside an HTML attribute. Although angle brackets (`<` and `>`) were HTML-encoded, double quotes (`"`) were not properly encoded.

This allowed an attacker to break out of the existing HTML attribute and inject a new event-handler attribute containing JavaScript.

A harmless JavaScript payload using `alert(document.domain)` was submitted through the `search` parameter. The browser executed the injected JavaScript and displayed an alert containing the application's domain, confirming the vulnerability.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** Reflected Cross-Site Scripting (XSS)
- **Injection technique:** HTML Attribute Injection / Attribute Breakout
- **Affected endpoint:** `/`
- **Affected parameter:** `search`
- **HTTP method:** GET
- **Target URL:** `https://0a0100f704f172ca80d403be0010006a.web-security-academy.net/`

## 3. Severity (CVSS)

**Suggested Severity:** Medium

**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Base Score:** 6.1 (Medium)

**Rationale:**

- **Attack Vector: Network** – The vulnerable search functionality is accessible remotely over HTTP/HTTPS.
- **Attack Complexity: Low** – Exploitation requires a specially crafted URL containing an attribute injection payload.
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

3. Initially submitted a unique marker string (`zzXSS12345zz`) through the `search` parameter:

   `GET /?search=zzXSS12345zz`

4. Inspected the server response and identified that the supplied marker was reflected inside an HTML attribute.

5. Tested angle brackets (`<` and `>`) to determine how the application handled HTML special characters. Observed that angle brackets were HTML-encoded.

6. Tested a double quote (`"`) separately and observed that it was not properly encoded, making it possible to break out of the existing HTML attribute.

7. Constructed an attribute injection payload:

   `" autofocus onfocus=alert(document.domain) x="`

8. Submitted the payload through the `search` parameter. When testing through Caido Repeater, URL-encoded the payload to ensure the HTTP request was valid.

9. Opened the resulting URL in the browser and observed that the injected JavaScript executed automatically when the input element received focus.

10. An alert displaying the application's domain appeared, confirming successful Reflected XSS exploitation through HTML attribute injection.

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

- **Implement context-aware output encoding:** Properly encode user-controlled input according to its output context, especially when inserting data into HTML attributes.
- **Encode quotation marks:** Ensure both single and double quotes are safely encoded when user input is placed inside HTML attributes.
- **Use secure templating:** Utilize template engines that automatically escape user-controlled output.
- **Avoid unsafe HTML insertion:** Do not insert untrusted input directly into HTML using unsafe DOM methods such as `innerHTML`.
- **Use safe DOM APIs:** Prefer `textContent` and safe attribute-handling methods when displaying user-controlled data.
- **Apply Content Security Policy (CSP):** Implement a restrictive CSP to reduce the impact of successful script injection. Avoid relying on CSP as the primary fix.

## 8. References

- [OWASP – Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger – Reflected Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger – XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
