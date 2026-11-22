# Reflected Cross-Site Scripting (XSS) — HTML context with most tags and attributes blocked

## 1. Summary         

The search functionality of the target application was found to be vulnerable to Reflected Cross-Site Scripting (XSS) despite restrictions on commonly used HTML tags and event-handler attributes.

During testing, the application reflected user-controlled input directly into the HTML body context. Although the application blocked several common HTML tags and attributes, certain less commonly used HTML elements and event handlers were still accepted.

Testing revealed that a `<body>` element with an `onresize` event handler could be injected through the `search` parameter. This allowed JavaScript execution when the target document's viewport was resized.

To trigger the event without requiring manual interaction from the victim, an iframe-based exploit was constructed and hosted on the PortSwigger Exploit Server. The iframe's `onload` handler modified its width after loading, triggering the `onresize` event in the embedded vulnerable page.

The JavaScript function `print()` was executed successfully, confirming the Reflected XSS vulnerability and demonstrating an automated exploit delivery technique.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** Reflected Cross-Site Scripting (XSS)
- **Injection technique:** HTML Injection / Event Handler Injection
- **Affected context:** HTML Body Context
- **Affected endpoint:** `/`
- **Affected parameter:** `search`
- **HTTP method:** GET
- **Target URL:** `https://YOUR-LAB-ID.web-security-academy.net/`

## 3. Severity (CVSS)

**Suggested Severity:** Medium

**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Base Score:** 6.1 (Medium)

**Rationale:**

- **Attack Vector: Network** – The vulnerable search functionality is accessible remotely over HTTP/HTTPS.
- **Attack Complexity: Low** – Exploitation requires a specially crafted URL and an HTML-based payload.
- **Privileges Required: None** – No authentication is required to access the vulnerable functionality.
- **User Interaction: Required** – The victim must visit the attacker's exploit page for the payload to execute.
- **Scope: Changed** – Injected JavaScript executes in the security context of the vulnerable application's origin.
- **Confidentiality: Low** – Depending on the victim's permissions and accessible application data, injected JavaScript may expose sensitive information.
- **Integrity: Low** – An attacker may perform unauthorized actions through the victim's browser within the application's security context.
- **Availability: None** – No availability impact was demonstrated.

*Note: This is an illustrative severity assessment for the lab. A real-world CVSS score requires evaluating the actual application's security context and demonstrated impact.*

## 4. Steps to Reproduce

1. Navigated to the target application and identified the search functionality.

2. Intercepted the search request using Caido.

3. Initially submitted a unique marker string through the `search` parameter to identify where user-controlled input appeared in the response.

4. Inspected the server response and identified that the supplied input was reflected directly inside the HTML body context:

   ```html
   <section class=blog-header>
       <h1>0 search results for '<customtag>'</h1>
       <hr>
   </section>
   ```

5. Tested common HTML tags such as `<script>`, `<img>`, `<svg>`, `<iframe>`, and `<details>`. These were blocked by the application's filtering mechanism.

6. Tested alternative HTML elements and discovered that certain tags, including `<body>`, were accepted.

7. Tested different event-handler attributes and identified that `onresize` was accepted, while several common handlers such as `onload` were blocked.

8. Constructed the following HTML injection payload:

   ```html
   <body onresize=print()>
   ```

9. URL-encoded the payload and submitted it through the `search` parameter:

   ```text
   %3Cbody%20onresize=print()%3E
   ```

10. Inspected the response and confirmed that the application reflected the decoded HTML markup without safely neutralizing the injected event handler.

11. However, simply injecting the event handler did not automatically trigger JavaScript execution. The `onresize` event required the embedded document's viewport to be resized.

12. Created an iframe-based exploit using the PortSwigger Exploit Server:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

13. Hosted the payload on the Exploit Server and selected **Deliver exploit to victim**.

14. When the simulated victim loaded the exploit page, the iframe loaded the vulnerable application. Its `onload` handler changed the iframe's width, triggering the embedded document's `onresize` event.

15. The injected JavaScript executed automatically, and the PortSwigger lab was successfully solved without requiring manual interaction from the victim.

## 5. Proof of Concept (PoC)

**Injected HTML payload:**

```html
<body onresize=print()>
```

**URL-encoded payload:**

```text
%3Cbody%20onresize=print()%3E
```

**Complete iframe-based exploit:**

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

**Execution flow:**

1. The attacker hosts the iframe payload on the Exploit Server.
2. The victim visits the attacker's exploit page.
3. The iframe loads the vulnerable application with the injected HTML payload.
4. The iframe's `onload` handler changes its width.
5. The embedded document receives a resize event.
6. The injected `onresize` handler executes `print()`.

**Observed result:** Successful JavaScript execution, confirmed by the PortSwigger lab completion.

## 6. Impact

Successful exploitation of this vulnerability could allow an attacker to:

- Execute arbitrary JavaScript in a victim's browser under the vulnerable application's origin.
- Manipulate page content and modify the appearance of the application.
- Perform unauthorized actions on behalf of an authenticated victim, depending on the application's functionality and security controls.
- Potentially access sensitive information available to the victim's browser context.
- Conduct phishing attacks by injecting misleading content into legitimate application pages.

The use of an iframe-based exploit demonstrates how an attacker may trigger a less common event handler automatically without requiring the victim to manually interact with the vulnerable element.

The actual impact depends on the victim's privileges, application functionality, and browser-side security controls.

## 7. Remediation

- **Implement context-aware output encoding:** Encode all user-controlled input according to its output context. HTML body content must be encoded so that user input is treated as text rather than executable markup.
- **Avoid HTML injection:** Do not insert untrusted input directly into HTML documents.
- **Use secure templating:** Use template engines that automatically escape user-controlled output.
- **Validate input appropriately:** Apply allowlist-based validation where specific input formats are expected. However, input filtering should not replace output encoding.
- **Use safe DOM APIs:** Prefer `textContent` instead of unsafe HTML insertion methods such as `innerHTML`.
- **Apply Content Security Policy (CSP):** Implement a restrictive CSP to reduce the impact of successful script injection. Avoid relying on CSP as the primary fix.

## 8. References

- [OWASP – Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger – Reflected Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger – XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [PortSwigger – Exploiting Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting/exploiting)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)


## 9. Testing Approach — Quick Summary

The following approach was used to identify and exploit the XSS vulnerability:

1. **Reflection Detection:** Submitted a unique marker through the `search` parameter and inspected the HTTP response to identify the reflection point and HTML context.

2. **HTML Tag Discovery:** Tested common HTML tags (`script`, `img`, `svg`, `iframe`, etc.) and identified that most were blocked. Further testing revealed that `<body>` was allowed.

3. **Event Handler Discovery:** Tested multiple event-handler attributes to identify which ones bypassed the application's filtering. Found that `onresize` was accepted, while common handlers such as `onload` were blocked.

4. **Payload Construction:** Combined the allowed `<body>` tag with `onresize=print()` to create a JavaScript execution payload.

5. **Encoding & Validation:** URL-encoded the payload, submitted it through Caido, and inspected the response to confirm successful reflection.

6. **Exploit Delivery:** Used the PortSwigger Exploit Server and an iframe-based payload to automatically trigger the resize event in the victim's browser.

**Key Takeaway:** When common HTML tags and event handlers are blocked, systematically test alternative tags and event handlers instead of relying only on common XSS payloads.
