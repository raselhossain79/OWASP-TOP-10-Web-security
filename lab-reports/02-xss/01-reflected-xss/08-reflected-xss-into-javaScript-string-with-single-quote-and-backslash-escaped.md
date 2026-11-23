# Reflected XSS – JavaScript String Escape via Script Block Breakout      08-reflected-xss-into-javaScript-string-with-single-quote-and-backslash-escaped.md

## 1. Summary

During security testing of the target web application, a Reflected Cross-Site Scripting (XSS) vulnerability was identified in the search functionality.

The application reflected user-controlled search input inside a JavaScript string assigned to the `searchTerms` variable within an inline `<script>` element.

Although the application escaped single quotation marks (`'`) and backslashes (`\`), it failed to prevent HTML script element termination.

By injecting a `</script>` sequence followed by a new script element, it was possible to escape the original script block and execute arbitrary JavaScript in the browser.

This confirmed a Reflected XSS vulnerability through HTML script block breakout.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** Reflected Cross-Site Scripting (XSS)
- **Injection context:** JavaScript String inside HTML Script Element
- **Affected functionality:** Search
- **Affected variable:** `searchTerms`
- **Affected endpoint:** `/`
- **HTTP method:** GET
- **Affected parameter:** `search`
- **Target URL:** `<TARGET_URL>`

## 3. Severity (CVSS)

**Provisional CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Provisional Base Score:** 6.1 (Medium)

**Rationale:**

- **Attack Vector: Network** – The vulnerability can be exploited remotely through a crafted URL.
- **Attack Complexity: Low** – Exploitation requires injecting a script termination sequence and a new script element.
- **Privileges Required: None** – No authentication was required in the tested lab.
- **User Interaction: Required** – A victim must visit the crafted URL.
- **Scope: Changed** – Successful exploitation executes JavaScript in the context of the vulnerable application's origin.
- **Confidentiality: Low** – JavaScript may access information available to the victim's browser context, subject to browser security restrictions.
- **Integrity: Low** – JavaScript may perform actions available within the victim's application context.
- **Availability: None** – No availability impact was demonstrated.

*Note: This is a provisional assessment based on the demonstrated lab behavior. Actual severity depends on the application's deployment context and confirmed business impact.*

## 4. Steps to Reproduce

### Step 1: Identify the Reflection Point

1. Opened the target application.
2. Used the search functionality with a unique marker (`TEST123`).
3. Inspected the HTTP response and identified two reflection points.

First reflection inside HTML:

```html
<h1>0 search results for 'TEST123'</h1>
```

Second reflection inside JavaScript:

```javascript
var searchTerms = 'TEST123';

document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
```

The second reflection point was selected for further testing because the user-controlled input was inserted into a JavaScript string.

### Step 2: Analyze Character Escaping

Tested single quotation marks using:

```text
TEST'123
```

Observed response:

```javascript
var searchTerms = 'TEST\'123';
```

The application escaped the single quotation mark using a backslash.

Next, tested backslashes:

```text
TEST\123
```

Observed response:

```javascript
var searchTerms = 'TEST\\123';
```

The application escaped backslashes by doubling them.

These observations indicated that the application attempted to prevent JavaScript string breakout through single quotes and backslashes.

### Step 3: Identify Script Element Breakout

After identifying the escaping behavior, tested whether the HTML script element could be terminated independently of JavaScript string parsing.

The following payload was injected:

```html
</script><script>alert(1)</script>
```

The resulting response showed that the original script element was terminated and a new script element was introduced.

Conceptual resulting HTML:

```html
<script>
    var searchTerms = '</script>
    <script>alert(1)</script>';

    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

The HTML parser recognized the `</script>` sequence and terminated the original script element, regardless of the JavaScript string context.

### Step 4: Validate JavaScript Execution

1. Submitted the crafted payload through the search functionality.
2. Inspected the HTTP response to verify that the original script block was terminated.
3. Confirmed that a new script element was injected.
4. Observed the JavaScript alert dialog.

The successful execution of `alert(1)` confirmed the Reflected XSS vulnerability.

## 5. Proof of Concept (Payload and Result)

**Injected Payload:**

```html
</script><script>alert(1)</script>
```

**Crafted URL:**

```text
<TARGET_URL>/?search=%3C%2Fscript%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

**Resulting HTML Structure:**

```html
<script>
    var searchTerms = '</script>
    <script>alert(1)</script>';
</script>
```

**Result:**

Successfully terminated the original HTML script element, injected a new script element, and executed JavaScript through the reflected search parameter.

## 6. Impact

Successful exploitation of this vulnerability could allow an attacker to:

- Execute arbitrary JavaScript in the context of the vulnerable application's origin.
- Access sensitive information available to the victim's browser context, subject to browser security restrictions.
- Perform unauthorized actions through the victim's authenticated session where applicable.
- Manipulate webpage content and user interactions.
- Potentially access sensitive application data depending on the application's security controls.

The vulnerability could be exploited by convincing a victim to visit a specially crafted URL.

## 7. Remediation

- Avoid directly embedding untrusted user input inside inline JavaScript.
- Prefer passing data through safely encoded JSON or using external JavaScript files with appropriate data handling.
- Apply context-specific output encoding based on the HTML and JavaScript parsing contexts.
- Prevent untrusted input from introducing HTML script termination sequences.
- Use safe DOM APIs instead of unsafe HTML construction methods.
- Implement a strict Content Security Policy (CSP) as an additional defensive layer.
- Perform security testing to identify unsafe reflection and script injection vulnerabilities.

## 8. Testing Workflow – How the Vulnerability Was Identified

1. **Identify Reflection:** Submitted a unique search marker and inspected the HTTP response to locate all reflection points.

2. **Determine JavaScript Context:** Identified that the search input was reflected inside the `searchTerms` variable in an inline JavaScript block.

3. **Analyze Escaping:** Tested single quotation marks and backslashes to understand how the application handled JavaScript string delimiters and escape characters.

4. **Identify Alternative Breakout:** Recognized that escaping JavaScript string characters did not necessarily prevent the HTML parser from terminating the script element.

5. **Test Script Termination:** Injected a `</script>` sequence followed by a new script element containing `alert(1)`.

6. **Validate Execution:** Inspected the response and confirmed successful JavaScript execution through the alert dialog.

**Key Takeaway:** JavaScript string escaping alone does not guarantee protection against XSS when untrusted input is embedded inside an HTML script element. HTML parsing behavior must also be considered.

## 9. References

- [PortSwigger – Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger – Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [OWASP – Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN – The Script Element](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script)
