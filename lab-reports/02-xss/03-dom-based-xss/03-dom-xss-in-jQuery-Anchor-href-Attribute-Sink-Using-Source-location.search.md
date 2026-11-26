# DOM XSS in jQuery Anchor href Attribute Sink Using Source location.search

**Lab:** PortSwigger Web Security Academy   
**Difficulty:** Apprentice  
**Vulnerability:** DOM-based Cross-Site Scripting (XSS)  
**Status:** Solved

---

## 1. Vulnerability Overview

This lab contains a DOM-based Cross-Site Scripting vulnerability in the Submit Feedback page.

The application uses the jQuery library to retrieve an anchor element and dynamically modify its `href` attribute using data obtained from the URL query string.

The application retrieves the `returnPath` parameter from `window.location.search` and assigns its value directly to the Back link's `href` attribute using jQuery's `.attr()` method.

Since the application does not validate the URL scheme, an attacker can supply a `javascript:` URL and execute JavaScript when a victim clicks the Back link.

**Root Cause:** Untrusted URL input is assigned directly to an anchor's `href` attribute without validating the URL scheme.

## 2. Source & Sink Identification

### Source

```javascript
(new URLSearchParams(window.location.search)).get('returnPath')
```

**Source:** `window.location.search`

The application retrieves the `returnPath` parameter from the URL.

For example:

```text
https://example.com/feedback?returnPath=/home
```

- `window.location.search` retrieves the query string from the current URL.
- `URLSearchParams()` parses the query string.
- `.get('returnPath')` extracts the value of the `returnPath` parameter.

The extracted value is attacker-controlled because an attacker can modify the URL parameter.

### Sink

```javascript
$('#backLink').attr("href", userInput);
```

**Sink:** jQuery `.attr()` modifying the `href` attribute.

- `$('#backLink')` uses a jQuery selector to find the HTML element with the ID `backLink`.
- `.attr()` modifies an HTML attribute.
- `"href"` specifies which attribute should be modified.
- `userInput` supplies the new attribute value.

The problem is not the `.attr()` method itself. The vulnerability occurs because untrusted input is assigned to the `href` attribute without validating the URL scheme.

## 3. Vulnerable Code Analysis

The original HTML element:

```html
<a id="backLink" href="xsstest">Back</a>
```

The vulnerable JavaScript:

```javascript
$(function() {
    $('#backLink').attr(
        "href",
        (new URLSearchParams(window.location.search)).get('returnPath')
    );
});
```

**How the code works:**

1. `$(function() {})` executes the callback when the document is ready.
2. `$('#backLink')` selects the Back link.
3. `URLSearchParams()` retrieves the `returnPath` parameter from the URL.
4. `.attr("href", ...)` replaces the original `href` value with the extracted input.

Because the application accepts the supplied value without checking whether it uses a safe URL scheme, an attacker can inject a JavaScript URL.

## 4. Proof of Concept (PoC)

### Injected Payload

```javascript
javascript:alert(document.cookie)
```

### Execution Steps

1. Identified `location.search` as the source.
2. Identified jQuery's `.attr()` method modifying the anchor's `href` attribute as the sink.
3. Confirmed that the `returnPath` parameter controls the Back link's destination.
4. Injected the following payload into the `returnPath` parameter:

```javascript
javascript:alert(document.cookie)
```

5. The application assigned the payload to the Back link's `href` attribute.
6. Clicked the Back link.
7. The browser interpreted the `javascript:` URL and executed the JavaScript.

### Final DOM After Injection

```html
<a id="backLink" href="javascript:alert(document.cookie)">Back</a>
```

**Result:** The browser displayed an alert containing `document.cookie`, successfully demonstrating the DOM-based XSS vulnerability.

## 5. Payload Breakdown

```javascript
javascript:alert(document.cookie)
```

| Component | Explanation |
|---|---|
| `javascript:` | A URL scheme that allows JavaScript execution when used in an executable URL context. |
| `alert()` | Displays a browser alert dialog. |
| `document.cookie` | Retrieves cookies accessible to JavaScript for the current document. |

**Why does this work?**

Normally, an anchor's `href` attribute contains a URL that the browser navigates to when clicked.

However, the `javascript:` scheme allows the browser to execute JavaScript instead of navigating to a conventional web address.

Since the application assigns the attacker-controlled value directly to `href`, clicking the Back link executes the injected JavaScript.

## 6. Attack Flow

```text
Attacker-controlled URL
          |
          v
    location.search
          |
          v
 URLSearchParams()
          |
          v
    returnPath value
          |
          v
    jQuery .attr()
          |
          v
 Back link's href modified
          |
          v
     Victim clicks link
          |
          v
 javascript: URL executed
          |
          v
 document.cookie accessed
          |
          v
     JavaScript execution
```

Unlike Stored XSS, the payload does not need to be stored in a database.

The vulnerable client-side JavaScript processes the URL parameter and modifies the DOM directly.

## 7. Potential Impact

Depending on the application's functionality and security controls, successful DOM-based XSS may allow an attacker to:

- Perform unauthorized actions within the victim's authenticated session.
- Access sensitive information available to JavaScript.
- Modify page content and manipulate the user interface.
- Capture user input or manipulate application workflows.
- Deliver phishing content through a legitimate application.

**Cookie-related limitation:** Cookies protected with the `HttpOnly` flag cannot be accessed through `document.cookie`. Therefore, successful XSS does not automatically mean all session cookies can be stolen.

## 8. Remediation

### 1. Validate URL Schemes

The application should validate user-controlled URLs before assigning them to an anchor's `href` attribute.

For example, if the Back link only needs to navigate to internal application paths, accept only expected relative paths or explicitly approved destinations.

Reject dangerous schemes such as:

```text
javascript:
data:
```

### 2. Use Safe URL Handling

The application should parse and validate the supplied URL and ensure that only approved protocols and destinations are accepted.

A simple example of restricting the protocol:

```javascript
const url = new URL(userInput, window.location.origin);

if (url.protocol === 'https:' || url.protocol === 'http:') {
    $('#backLink').attr('href', url.href);
}
```

For applications that only require internal navigation, stricter same-origin validation is preferable.

### 3. Implement Content Security Policy (CSP)

A properly configured CSP can provide an additional layer of protection against script execution.

However, CSP should not replace URL validation and safe DOM manipulation.

## 9. Key Learning Points

- DOM-based XSS can occur through unsafe manipulation of HTML attributes, not just `innerHTML`.
- `window.location.search` can act as an attacker-controlled source.
- jQuery's `.attr()` can become part of a vulnerable data flow when untrusted input is assigned to sensitive attributes.
- The `href` attribute can execute JavaScript when supplied with a `javascript:` URL.
- Clicking the affected link triggers the JavaScript execution in this scenario.
- URL scheme validation is essential when handling user-controlled navigation destinations.
- `HttpOnly` cookies cannot be accessed through `document.cookie`.

**Main Takeaway:**

Never trust user-controlled URL values when assigning them to navigation attributes. Validate the destination and restrict allowed URL schemes before using them.
