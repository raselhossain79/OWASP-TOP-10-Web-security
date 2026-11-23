# Reflected XSS – HTML Attribute Injection via Canonical Link Tag

## 1. Summary

During security testing of the target web application, a Reflected Cross-Site Scripting (XSS) vulnerability was identified in the canonical link tag on the home page.

The application reflected user-controlled URL input inside the `href` attribute of an HTML `<link rel="canonical">` element without properly encoding single quotation marks.

Although angle brackets (`<` and `>`) were escaped, the application failed to prevent HTML attribute breakout using single quotes.

By injecting additional HTML attributes, including `accesskey` and an `onclick` event handler, it was possible to execute arbitrary JavaScript in the browser when the simulated user activated the assigned keyboard shortcut.

This confirmed a Reflected XSS vulnerability through HTML attribute injection.

## 2. Vulnerability Type and Affected Endpoint/Parameter

- **Vulnerability type:** Reflected Cross-Site Scripting (XSS)
- **Injection context:** HTML Attribute
- **Affected HTML element:** `<link rel="canonical">`
- **Affected attribute:** `href`
- **Affected endpoint:** `/`
- **HTTP method:** GET
- **Affected input:** URL query string
- **Target URL:** `https://0a06006903f231918112891b005000f9.web-security-academy.net/`

## 3. Severity (CVSS)

**Provisional CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Provisional Base Score:** 6.1 (Medium)

**Rationale:**

- **Attack Vector: Network** – The vulnerability can be exploited remotely through a crafted URL.
- **Attack Complexity: Low** – Exploitation requires injecting additional HTML attributes into the reflected canonical link.
- **Privileges Required: None** – No authentication was required in the tested lab.
- **User Interaction: Required** – The victim must visit the crafted URL and activate the assigned keyboard shortcut.
- **Scope: Changed** – Successful exploitation executes JavaScript in the context of the vulnerable application's origin.
- **Confidentiality: Low** – JavaScript execution may allow access to information available to the victim's browser context.
- **Integrity: Low** – JavaScript may perform actions available to the victim's session.
- **Availability: None** – No availability impact was demonstrated.

*Note: This is a provisional assessment based on the demonstrated lab behavior. Actual severity depends on the application's context, victim interaction requirements, and demonstrated impact.*

## 4. Steps to Reproduce

### Step 1: Identify the Reflection Point

1. Opened the target application.
2. Inspected the page source and searched for the canonical link element.
3. Identified that user-controlled URL input was reflected inside the `href` attribute.

Example HTML:

```html
<link rel="canonical" href='https://example.com/?test123'/>
```

This indicated that the application was inserting user-controlled input into an HTML attribute.

### Step 2: Test HTML Attribute Injection

Injected a single quotation mark into the URL query string:

```text
?'test'
```

The resulting HTML was:

```html
<link rel="canonical" href='https://example.com/?'test''/>
```

The reflected input was able to interfere with the original `href` attribute structure.

This demonstrated that single quotation marks were not properly encoded, allowing attribute breakout.

### Step 3: Inject an Event Handler

After identifying the attribute breakout, constructed a payload to inject additional HTML attributes.

The injected attributes included:

- `accesskey` – Assigns a keyboard shortcut to the element.
- `onclick` – Defines JavaScript execution when the element is activated.

The resulting HTML structure was conceptually:

```html
<link rel="canonical"
      href='?'
      accesskey='x'
      onclick='alert(1)'/>
```

### Step 4: Trigger JavaScript Execution

1. Loaded the crafted URL in the browser.
2. Activated the assigned keyboard shortcut.
3. Observed the JavaScript alert dialog.

The following shortcuts were supported by the lab's simulated user:

- `ALT + SHIFT + X`
- `CTRL + ALT + X`
- `ALT + X`

During testing:

- Chrome: `ALT + X` triggered the alert.
- Firefox: `ALT + SHIFT + X` triggered the alert.

This confirmed successful JavaScript execution through the injected HTML attribute.

## 5. Proof of Concept (Payload and Result)

**Injected Payload:**

**Crafted URL:**

**Result:**

## 6. Impact

Successful exploitation of this vulnerability could allow an attacker to:

- Execute arbitrary JavaScript in the context of the vulnerable application's origin.
- Access sensitive information available to the victim's browser context, subject to browser security restrictions.
- Perform unauthorized actions through the victim's authenticated session where applicable.
- Manipulate webpage content and user interactions.
- Potentially access sensitive application data depending on the application's security controls.

The vulnerability requires victim interaction because the injected event handler must be activated through the assigned keyboard shortcut.

## 7. Remediation

- Properly encode user-controlled input according to its output context.
- Apply HTML attribute encoding to prevent quotation marks from breaking out of attribute values.
- Avoid directly inserting untrusted input into HTML attributes.
- Use context-aware output encoding rather than relying only on filtering angle brackets.
- Validate URL inputs against expected formats and permitted values.
- Implement a strict Content Security Policy (CSP) as an additional defensive layer.
- Prefer safe DOM APIs and avoid unsafe HTML construction.

## 8. Testing Workflow – How the Vulnerability Was Identified

1. **Identify Reflection:** Supplied a unique test value in the URL and inspected the HTML source to locate where the input was reflected.

2. **Determine HTML Context:** Identified that the input was reflected inside the `href` attribute of the canonical link element.

3. **Test Attribute Breakout:** Injected single quotation marks to determine whether the application properly encoded attribute delimiters.

4. **Identify Injection Opportunity:** Observed that the single quote could terminate the existing `href` value, allowing additional HTML attributes to be injected.

5. **Inject Event Handler:** Added an `accesskey` attribute and an `onclick` event handler containing `alert(1)`.

6. **Trigger the Payload:** Used the keyboard shortcut specified by the lab to activate the injected element and execute JavaScript.

7. **Validate the Vulnerability:** Confirmed successful JavaScript execution through the appearance of the alert dialog.

**Key Takeaway:** The vulnerability was identified through reflection analysis, HTML context identification, quote-breakout testing, event-handler injection, and manual JavaScript execution validation.

## 9. References

- [PortSwigger – Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger – Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [OWASP – Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN – HTML accesskey Global Attribute](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/accesskey)
