# Reflected Cross-Site Scripting (XSS) — SVG Markup and Event Handler Filter Bypass

## 1. Summary

The search functionality of the target application was found to be vulnerable to Reflected Cross-Site Scripting (XSS).

The application implemented filtering that blocked common HTML tags and event handlers but allowed certain SVG elements and event handlers.

During testing, automated tag and event handler detection techniques were used to identify permitted HTML/SVG elements and compatible event attributes. By combining an allowed SVG element (`svg`) with an SVG animation element (`animatetransform`) and the `onbegin` event handler, a working JavaScript payload was constructed.

The browser successfully executed the injected JavaScript, confirming that the application's filtering mechanism could be bypassed.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** Reflected Cross-Site Scripting (XSS)
- **Affected endpoint:** `/`
- **Affected parameter:** `search`
- **HTTP method:** GET
- **Target URL:** [Insert target URL]

## 3. Severity (CVSS)

**Suggested Severity:** Medium

**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Base Score:** 6.1 (Medium)

**Rationale:**

- **Attack Vector: Network** – The vulnerable search functionality is accessible remotely over HTTP/HTTPS.
- **Attack Complexity: Low** – Exploitation requires a specially crafted URL containing an XSS payload.
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

5. Determined that the input was being reflected within an HTML context.

6. Tested common HTML and JavaScript injection techniques. The application rejected common tags and certain event handlers.

7. Used automated HTML tag detection to identify elements permitted by the application's filtering mechanism. The testing identified several allowed elements, including `svg`, `img`, and SVG animation-related elements such as `animatetransform`.

8. Performed automated event handler detection to identify which event attributes were accepted by the filtering mechanism.

9. Identified that `onload` was rejected, while `onbegin` was accepted when used within an appropriate SVG animation context.

10. Combined the permitted SVG elements and event handler to construct the following payload:

    `<svg><animatetransform onbegin=alert(1) attributeName=transform>`

11. Submitted the URL-encoded payload through the `search` parameter using Caido.

12. Observed an HTTP 200 response and verified that the reflected payload executed successfully in the browser, displaying a JavaScript alert.

13. This confirmed that the application's filtering mechanism could be bypassed, resulting in Reflected XSS through the `search` parameter.

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

- **Implement context-aware output encoding:** Properly encode untrusted user input before inserting it into HTML responses.
- **Avoid blacklist-based filtering:** Do not rely on blocking selected HTML tags or event handlers as the primary XSS defense.
- **Use HTML sanitization:** If HTML input is required, use a well-maintained sanitizer with a strict allowlist of permitted elements and attributes.
- **Restrict SVG content:** Disallow unnecessary SVG elements and executable event handler attributes.
- **Apply Content Security Policy (CSP):** Implement a restrictive CSP to reduce the impact of successful script injection.
- **Use safe DOM APIs:** Prefer `textContent` instead of unsafe HTML insertion methods such as `innerHTML` when displaying user-controlled text.

## 8. References

- [OWASP – Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger – Reflected Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger – XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP – Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)



## 9. Technical Notes — Automated Tag and Event Handler Detection

This section documents the methodology used to identify permitted HTML/SVG elements and event handlers when testing an application that implements tag-based and attribute-based XSS filtering.

### 9.1 Why Automated Detection Was Used

The application blocked common HTML tags and event handlers, making manual payload testing less efficient.

Instead of randomly trying different payloads, an automated detection approach was used to systematically identify which HTML/SVG elements and event handler attributes were accepted by the application.

The objective was to identify:

- Which HTML/SVG tags were permitted.
- Which event handler attributes were accepted.
- Which elements supported the identified event handlers.
- Which element and event handler combinations could successfully execute JavaScript.

### 9.2 Automated HTML/SVG Tag Detection

**Purpose:** Identify which HTML and SVG elements could pass through the application's filtering mechanism.

**Testing approach:**

1. Start with a known reflection point, such as the `search` parameter.
2. Prepare a list of candidate HTML and SVG tags.
3. Submit each candidate tag individually through the vulnerable parameter.
4. Observe the HTTP response and inspect how each candidate is reflected.
5. Compare the submitted input with the returned HTML to identify accepted, removed, modified, or encoded elements.
6. Record the elements that remain usable in the browser.

This process is similar to dictionary-based or brute-force testing: a predefined collection of candidate tags is tested systematically rather than relying on manual guessing.

Examples of candidate elements include:

- `svg`
- `img`
- `iframe`
- `video`
- `details`
- `animatetransform`

**Result:** Several elements were identified as permitted, including SVG-related elements.

### 9.3 Automated Event Handler Detection

**Purpose:** Identify which event handler attributes were allowed by the application's filtering mechanism.

After identifying permitted elements, the next step was to test different event handler attributes.

**Testing approach:**

1. Prepare a list of candidate event handler names.
2. Insert each candidate attribute into an allowed HTML/SVG element.
3. Submit the modified element through the same vulnerable parameter.
4. Inspect the response to determine whether the attribute was removed, encoded, or preserved.
5. Record accepted event handler attributes for further testing.

Examples of event handlers to investigate include:

- `onload`
- `onerror`
- `onclick`
- `onfocus`
- `onmouseover`
- `onbegin`

The detection process helps distinguish between event handlers that are explicitly blocked and those that are still accepted.

**Result:** The `onload` event handler was rejected, while `onbegin` was identified as an accepted candidate.

### 9.4 Element and Event Handler Compatibility Testing

Identifying an allowed tag and an accepted event handler does not automatically confirm that they can execute JavaScript together.

Event handlers are associated with specific browser events, and those events require the appropriate execution conditions.

For example:

- `onerror` requires an applicable error event.
- `onload` requires an applicable load event.
- `onclick` requires a click event.
- `onbegin` requires an SVG animation begin event.

Therefore, the next step is to identify which permitted elements can actually trigger the selected event handler.

In this test, the `onbegin` event handler was associated with the SVG animation element `animatetransform`.

The resulting combination was:

`<svg><animatetransform onbegin=alert(1) attributeName=transform>`

This provided the required SVG animation context for the `onbegin` event to trigger.

### 9.5 Browser-Based Validation

Automated detection results must be validated in a real browser because a server accepting or reflecting an element does not guarantee that the browser will execute it.

The final validation process involved:

1. Submitting the constructed payload through the vulnerable parameter.
2. Checking that the server returned the reflected markup.
3. Opening the resulting URL in a browser.
4. Observing whether the expected JavaScript alert appeared.
5. Confirming successful execution.

The successful execution of `alert(1)` demonstrated that the identified element and event handler combination bypassed the application's filtering mechanism.

### 9.6 Overall Automated Detection Workflow

The complete methodology can be summarized as follows:

1. **Reflection Discovery:** Identify where user-controlled input appears in the response.
2. **Context Identification:** Determine whether the input is reflected in HTML, an attribute, JavaScript, or another context.
3. **Tag Enumeration:** Automatically test a predefined list of HTML/SVG elements.
4. **Tag Filtering Analysis:** Compare submitted and reflected markup to identify permitted elements.
5. **Event Handler Enumeration:** Automatically test candidate event handler attributes.
6. **Attribute Filtering Analysis:** Identify which event handlers survive the application's filtering.
7. **Compatibility Testing:** Determine whether an allowed element can trigger an accepted event.
8. **Payload Construction:** Combine compatible elements and event handlers.
9. **Browser Validation:** Confirm actual JavaScript execution.

**Important:** Automated tag and event handler enumeration is a discovery technique, not proof of XSS by itself. The vulnerability is confirmed only after successful browser-side JavaScript execution.
