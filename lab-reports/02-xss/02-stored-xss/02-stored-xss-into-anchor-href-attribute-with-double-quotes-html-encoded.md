# Stored XSS into anchor href attribute with double quotes HTML-encoded

## 1. Summary

The blog comment functionality was found to be vulnerable to Stored (Persistent) Cross-Site Scripting (XSS).

The application stored user-submitted comments and website URLs, then rendered them inside an HTML anchor element.

Although double quotes were HTML-encoded, the application failed to properly validate the URL scheme in the `href` attribute.

This allowed an attacker to inject a `javascript:` URL into the stored website field. When a user clicked the affected link, JavaScript executed in the context of the application's origin.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability:** Stored (Persistent) Cross-Site Scripting (XSS)
- **Injection Context:** HTML Attribute (`href`)
- **Endpoint:** `POST /post/comment`
- **Parameter:** `website`
- **Affected Functionality:** Blog comment submission and website link rendering

## 3. Severity (CVSS)

- **Suggested Severity:** Medium (Provisional)
- **Suggested CVSS:** 6.1 (Provisional)
- **Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

Actual severity depends on the application's functionality, affected users, and exploitation conditions.

## 4. Steps to Reproduce

1. Open the target blog post:
   `https://0a6a0063035dd020808e034300d000d2.web-security-academy.net/post?postId=3`

2. Locate the comment submission form.

3. Enter a test comment and a name in their respective fields.

4. Enter a dummy website URL in the `website` field and submit the comment.

5. Return to the blog post and inspect the submitted comment using browser Developer Tools.

6. Observe that the submitted name is rendered inside an HTML anchor element and the website URL is placed inside its `href` attribute.

7. Replace the dummy website URL with the following payload:

   ```javascript
   javascript:alert(document.domain)
   ```

8. Submit the comment and revisit the affected blog post.

9. Click the website link associated with the submitted comment.

10. Observe that the JavaScript executes and displays an alert containing the application's domain.

## 5. Proof of Concept (PoC)

**Affected Parameter:**

```text
https://0a6a0063035dd020808e034300d000d2.web-security-academy.net/post?postId=3
```

**Payload:**

```javascript
javascript:alert(document.domain)
```

**Resulting HTML (Conceptual):**

```html
<a href="javascript:alert(document.domain)">abc</a>
```

**Execution Breakdown:**

- `href` specifies the destination of an HTML link.
- Normally, it contains a URL such as `https://example.com`.
- The `javascript:` scheme allows JavaScript execution when the link is activated.
- The application accepted and stored the injected URL scheme without proper validation.
- Clicking the rendered link triggered the JavaScript execution.

**Observed Result:**

The injected JavaScript executed successfully after clicking the stored website link, displaying an alert with the application's domain and confirming the Stored XSS vulnerability.

## 6. Impact

An attacker could potentially exploit this vulnerability by submitting a malicious URL through the comment functionality.

When other users visit the affected blog post and click the injected link, JavaScript executes in the context of the application's origin.

Depending on the application's functionality and the victim's privileges, potential impacts include:

- Performing unauthorized actions through the victim's authenticated session.
- Accessing sensitive information available to client-side JavaScript.
- Modifying page content and manipulating user interactions.
- Conducting phishing attacks through the trusted application interface.

The exploitation requires user interaction because the injected link must be clicked.

Actual impact depends on the application's functionality, affected users, and security controls.

## 7. Remediation

- Validate URLs using a strict allowlist of permitted schemes, such as `https:` and `http:`.
- Reject dangerous URL schemes such as `javascript:`.
- Apply context-aware output encoding when rendering user-controlled attributes.
- Avoid trusting user-submitted URLs, even when they are stored in the database.
- Implement a restrictive Content Security Policy (CSP) as an additional security layer.

## 8. Testing Workflow – How the Vulnerability Was Identified

1. Identified the blog comment functionality as a potential persistent input source.
2. Submitted a test comment, name, and dummy website URL.
3. Inspected the rendered comment using browser Developer Tools.
4. Identified that the submitted name was rendered inside an anchor tag and the website value was placed in its `href` attribute.
5. Recognized the `href` attribute as the injection point.
6. Tested the URL field with the `javascript:` scheme.
7. Submitted `javascript:alert(document.domain)` as the website value.
8. Clicked the rendered website link and confirmed successful JavaScript execution through the alert popup.

## 9. Key Learning Points

- Stored XSS can occur inside HTML attributes, not just HTML body content.
- HTML-encoding double quotes does not automatically prevent dangerous URL schemes.
- The `href` attribute requires URL scheme validation in addition to appropriate output encoding.
- The `javascript:` scheme can execute JavaScript when an affected link is clicked.
- User interaction requirements affect exploitability and severity.
- Identifying the exact rendering context is essential for selecting an appropriate testing approach.

## 10. References

- [PortSwigger – Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [PortSwigger – Cross-site scripting contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [OWASP – Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN – HTML Anchor Element](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a)
