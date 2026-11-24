# Reflected XSS – JavaScript String Escape via Backslash Handling Bypass

## 1. Summary                      

The search functionality was found to be vulnerable to Reflected Cross-Site Scripting (XSS).

The application reflected user-controlled input inside a JavaScript string. Although single quotes were escaped and angle brackets and double quotes were HTML-encoded, backslashes were not properly escaped.

This allowed an attacker to manipulate JavaScript string parsing, break out of the string context, and execute arbitrary JavaScript.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability:** Reflected Cross-Site Scripting (XSS)
- **Injection Context:** JavaScript String
- **Endpoint:** `GET /`
- **Parameter:** `search`
- **Affected Functionality:** Search query tracking

## 3. Severity (CVSS)

- **Suggested Severity:** Medium
- **Suggested CVSS:** 6.1 (Provisional)
- **Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

Actual severity depends on the application's functionality, affected users, and exploitation conditions.

## 4. Steps to Reproduce

1. Open the target application.
2. Enter a unique test string in the search functionality.
3. Intercept the search request using Burp Suite or Caido.
4. Submit a request containing special characters:

   ```text
   GET /?search=zzXSS123\45"z/'z> HTTP/1.1
   ```

5. Inspect the HTTP response and locate the reflected JavaScript variable:

   ```javascript
   var searchTerms = 'zzXSS123\45&quot;z/\'z&gt;';
   ```

6. Observe the application's input handling:
   - Single quotes are escaped using backslashes.
   - Angle brackets and double quotes are HTML-encoded.
   - Backslashes are not properly escaped.

7. Submit the following payload:

   ```javascript
   \'-alert(1)//
   ```

8. Inspect the response:

   ```javascript
   var searchTerms = '\\'-alert(1)//';
   ```

9. The JavaScript string is terminated, and the injected `alert(1)` executes.

## 5. Proof of Concept (PoC)

**Payload:**

```text
\'-alert(1)//
```

**Resulting JavaScript:**

```javascript
var searchTerms = '\\'-alert(1)//';
```

**Execution breakdown:**

- `\\` is interpreted as a literal backslash inside the JavaScript string.
- The following `'` terminates the string.
- `-alert(1)` executes as JavaScript outside the string.
- `//` comments out the remaining characters, preventing a syntax error.

**Observed Result:** The injected JavaScript executed successfully, displaying an alert box and confirming the XSS vulnerability.

## 6. Impact

An attacker could potentially exploit this vulnerability to execute JavaScript in a victim's browser under the application's origin.

Depending on the application's functionality and the victim's privileges, potential impacts include:

- Performing unauthorized actions as the victim.
- Accessing sensitive information available to client-side JavaScript.
- Modifying page content and manipulating user interactions.
- Conducting phishing attacks through the trusted application interface.

Actual impact depends on browser protections, application security controls, and the victim's privileges.

## 7. Remediation

- Properly escape backslashes before applying quote escaping.
- Use context-aware output encoding for JavaScript strings.
- Avoid inserting untrusted input directly into executable JavaScript.
- Prefer safely serialized data structures, such as JSON, when transferring data into scripts.
- Implement a restrictive Content Security Policy (CSP) as an additional security layer.

## 8. Testing Workflow – How the Vulnerability Was Identified

1. Identified the search parameter as a user-controlled input.
2. Submitted a unique marker to locate its reflection in the HTTP response.
3. Identified the reflection inside a JavaScript string.
4. Tested single quotes, backslashes, double quotes, and angle brackets to understand the application's encoding behavior.
5. Discovered that single quotes were escaped but backslashes were not.
6. Used a backslash followed by a single quote to bypass the application's quote escaping.
7. Used `-alert(1)` to execute JavaScript outside the string and `//` to comment out the remaining code.
8. Confirmed successful JavaScript execution through the alert popup.

## 9. Key Learning Points

- JavaScript string escaping must handle both quotes and backslashes correctly.
- `\\` in JavaScript source represents one literal backslash.
- An escaped quote (`\'`) does not terminate a JavaScript string.
- Improper backslash handling can invalidate otherwise correct quote escaping.
- XSS testing requires identifying the exact output context and understanding how the browser parses the resulting code.

## 10. References

- [PortSwigger – Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger – Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [MDN – JavaScript String](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String)
- [OWASP – Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
