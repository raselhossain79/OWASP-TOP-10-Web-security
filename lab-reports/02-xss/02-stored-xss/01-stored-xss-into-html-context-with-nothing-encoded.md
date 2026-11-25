# Stored XSS – HTML Context with Nothing Encoded

## 1. Summary

The blog comment functionality was found to be vulnerable to Stored (Persistent) Cross-Site Scripting (XSS).

The application stored user-submitted comments and later rendered them inside the HTML body without proper output encoding.

As a result, an attacker could submit a malicious JavaScript payload through the comment functionality. The payload remained stored and executed whenever a user visited the affected blog post.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability:** Stored (Persistent) Cross-Site Scripting (XSS)
- **Injection Context:** HTML Body
- **Endpoint:** `POST /post/comment`
- **Parameter:** `comment`
- **Affected Functionality:** Blog comment submission and display

## 3. Severity (CVSS)

- **Suggested Severity:** Medium (Provisional)
- **Suggested CVSS:** 6.1 (Provisional)
- **Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

Actual severity depends on the application's functionality, affected users, required privileges, and exploitation conditions.

## 4. Steps to Reproduce

1. Open the target blog post.

2. Locate the comment submission functionality.

3. Intercept the comment submission request using Caido or Burp Suite.

4. Submit a unique marker in the `comment` parameter to identify where the input is rendered:

   ```text
   rasel_stored_test_92831
   ```

5. Submit the comment and reload the blog post.

6. Inspect the rendered comment using browser Developer Tools (Inspect Element).

7. Observe that the submitted marker appears inside the HTML body of the page, within an HTML element.

8. Replace the marker with the following payload:

   ```html
   <script>alert(1)</script>
   ```

9. Submit the comment again and revisit the affected blog post.

10. Observe that the injected JavaScript executes and displays an alert popup.

## 5. Proof of Concept (PoC)

**Affected Parameter:**

```text
comment
```

**Payload:**

```html
<script>alert(1)</script>
```

**Observed Result:**

The application stored the submitted comment and rendered it as HTML without proper output encoding.

When the affected blog post was loaded, the browser interpreted the injected script tag and executed the JavaScript, displaying an alert popup.

This confirmed the Stored XSS vulnerability.

## 6. Impact

An attacker could potentially exploit this vulnerability to execute arbitrary JavaScript in the browsers of users visiting the affected blog post.

Depending on the application's functionality and the victim's privileges, potential impacts include:

- Performing unauthorized actions through the victim's authenticated session.
- Accessing sensitive information available to client-side JavaScript.
- Modifying page content and manipulating user interactions.
- Conducting phishing attacks through the trusted application interface.
- Targeting multiple users who visit the affected page.

Since the payload remains stored, exploitation does not require sending a specially crafted link to every victim.

Actual impact depends on the application's functionality, user privileges, and security controls.

## 7. Remediation

- Apply context-aware output encoding before rendering user-submitted comments.
- Treat all user-controlled input, including stored content, as untrusted.
- Use safe templating mechanisms that automatically encode HTML output.
- Avoid inserting untrusted content directly into executable HTML.
- Implement a restrictive Content Security Policy (CSP) as an additional security layer.
- Review all locations where stored comment data is rendered.

## 8. Testing Workflow – How the Vulnerability Was Identified

1. Identified the blog comment functionality as a potential persistent input source.
2. Submitted a unique marker through the `comment` parameter.
3. Reloaded the blog post to verify that the submitted data persisted.
4. Used browser Developer Tools to inspect the rendered comment.
5. Identified that the input was rendered inside the HTML body context.
6. Observed that the application did not properly encode the submitted HTML.
7. Submitted `<script>alert(1)</script>` as the comment payload.
8. Reloaded the affected blog post and confirmed successful JavaScript execution through the alert popup.

## 9. Key Learning Points

- Stored XSS occurs when user-controlled data is persisted and later rendered unsafely.
- A unique marker helps identify where submitted data is rendered.
- Persistence should be verified through a fresh page request.
- Browser Developer Tools can help identify the exact HTML injection context.
- HTML body context allows injected HTML elements such as script tags to be interpreted when proper output encoding is missing.
- Stored XSS and Reflected XSS use similar injection mechanics, but differ in how the payload is delivered to users.
- Testing cross-user visibility is important to establish the actual impact of Stored XSS.

## 10. References

- [PortSwigger – Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger – Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [OWASP – Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN – HTML Script Element](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script)
