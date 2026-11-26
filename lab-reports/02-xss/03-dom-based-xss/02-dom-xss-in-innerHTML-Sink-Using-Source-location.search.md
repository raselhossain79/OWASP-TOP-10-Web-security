# DOM XSS in innerHTML Sink Using Source location.search        

**Lab:** PortSwigger Web Security Academy  
**Difficulty:** Apprentice  
**Vulnerability:** DOM-based Cross-Site Scripting (XSS)  
**Status:** Solved

---

## 1. Vulnerability Overview

This lab contains a DOM-based Cross-Site Scripting vulnerability in the search functionality.

The application retrieves user-controlled input from the URL using `window.location.search` and passes it to an `innerHTML` assignment.

Since `innerHTML` interprets the supplied data as HTML rather than plain text, an attacker can inject malicious HTML elements and execute JavaScript through event handlers.

In this lab, an attacker can exploit the vulnerability by injecting an HTML image element with an `onerror` event handler.

**Root Cause:** Untrusted URL input is directly assigned to an `innerHTML` sink without proper handling.

## 2. Source & Sink Identification

Understanding the source and sink is essential when identifying DOM-based XSS vulnerabilities.

### Source

```javascript
var query = (new URLSearchParams(window.location.search)).get('search');
```

**Source:** `window.location.search`

The application retrieves the search parameter from the URL.

For example:

```text
https://example.com/?search=hello
```

- `window.location.search` retrieves the query string from the URL.
- `URLSearchParams()` parses the query string.
- `.get('search')` extracts the value of the `search` parameter.

The extracted value is stored in the `query` variable.

Since an attacker can control the URL parameter, this is an attacker-controlled source.

### Sink

```javascript
document.getElementById('searchMessage').innerHTML = query;
```

**Sink:** `innerHTML`

This statement finds the HTML element with the ID `searchMessage` and assigns the value of `query` to its HTML content.

The problem is that `innerHTML` interprets the supplied value as HTML.

As a result, an attacker can inject HTML elements containing executable event handlers.

## 3. Vulnerable Code Analysis

The complete vulnerable JavaScript code:

```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}

var query = (new URLSearchParams(window.location.search)).get('search');

if(query) {
    doSearchQuery(query);
}
```

**How the code works:**

1. `doSearchQuery(query)` receives the search input.
2. `getElementById('searchMessage')` locates the target HTML element.
3. `.innerHTML = query` inserts the supplied input as HTML.
4. `URLSearchParams()` retrieves the user-controlled search parameter.
5. If the parameter contains a value, the application passes it to `doSearchQuery()`.

There is no safe handling of the input before it reaches the HTML-rendering sink.

This creates a direct flow:

**Source → Variable → Sink → JavaScript Execution**

## 4. Proof of Concept (PoC)

### Injected Payload

```html
<img src=x onerror=alert(1)>
```

### Execution Steps

1. Identified `location.search` as the source.
2. Identified `innerHTML` as the vulnerable sink.
3. Confirmed that the search parameter was reflected inside the `searchMessage` element.
4. Injected the following payload into the search parameter:

```html
<img src=x onerror=alert(1)>
```

5. The browser attempted to load the image.
6. Since `x` was an invalid image source, the image failed to load.
7. The `onerror` event was triggered, executing `alert(1)`.

**Result:** A JavaScript alert appeared successfully, confirming the DOM-based XSS vulnerability.

## 5. Payload Breakdown

```html
<img src=x onerror=alert(1)>
```

| Component | Explanation |
|---|---|
| `<img>` | Creates an HTML image element. |
| `src=x` | Provides an invalid image source. |
| `onerror` | Executes its event handler when the image fails to load. |
| `alert(1)` | Executes JavaScript and displays an alert box. |

**Why does this work?**

The application inserts the payload using `innerHTML`. Therefore, the browser interprets the injected string as an actual HTML element instead of displaying it as plain text.

When the image fails to load, its error event triggers the JavaScript handler.

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
     query variable
          |
          v
      innerHTML
          |
          v
  Injected HTML element
          |
          v
    Image load failure
          |
          v
     onerror event
          |
          v
    JavaScript execution
```

Unlike Stored XSS, this attack does not require the malicious input to be saved in a database.

The vulnerable JavaScript processes the URL input directly in the victim's browser.

## 7. Potential Impact

Depending on the application's functionality and the victim's privileges, successful DOM-based XSS may allow an attacker to:

- Perform unauthorized actions within the victim's authenticated session.
- Modify page content and manipulate the user interface.
- Steal sensitive information accessible to JavaScript.
- Capture user input or manipulate application workflows.
- Deliver phishing content through a legitimate website.

The actual impact depends on the application's security controls, user privileges, and accessible data.

## 8. Remediation

### 1. Use `textContent` Instead of `innerHTML`

**Vulnerable implementation:**

```javascript
element.innerHTML = query;
```

**Secure alternative:**

```javascript
element.textContent = query;
```

`textContent` treats the supplied value as plain text rather than interpreting it as HTML.

For example, if the input is:

```html
<img src=x onerror=alert(1)>
```

The browser displays the characters as text instead of creating an image element and executing its event handler.

### 2. Use a Trusted HTML Sanitizer When HTML Is Required

If an application genuinely needs to accept and render user-supplied HTML, it should use a well-maintained HTML sanitization library such as DOMPurify.

This helps remove dangerous HTML elements and attributes while preserving permitted formatting.

### 3. Implement Content Security Policy (CSP)

A properly configured CSP can restrict which scripts are allowed to execute and reduce the impact of XSS vulnerabilities.

However, CSP should be treated as an additional security layer, not a replacement for safe DOM manipulation.

## 9. Key Learning Points

- DOM-based XSS occurs when client-side JavaScript handles untrusted data in an unsafe way.
- `window.location.search` can act as an attacker-controlled source.
- `innerHTML` is a dangerous sink when used with untrusted input.
- HTML elements can trigger JavaScript execution through event handlers such as `onerror`.
- `textContent` is a safer alternative when displaying untrusted data as text.
- DOM-based XSS can occur entirely within the browser without requiring backend database storage.

**Main Takeaway:**

Never assign untrusted user input directly to an HTML-rendering sink. Always use safe DOM APIs and handle data according to its intended context.
