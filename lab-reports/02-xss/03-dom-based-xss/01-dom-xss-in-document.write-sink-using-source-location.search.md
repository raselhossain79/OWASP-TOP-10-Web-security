# Lab: DOM XSS in `document.write` sink using source `location.search`

**Difficulty:** Apprentice  
**Vulnerability:** DOM-Based Cross-Site Scripting (DOM XSS)  
**Source:** `location.search`  
**Sink:** `document.write()`  
**Status:** Solved

## 1. Summary

The application contains a DOM-based Cross-Site Scripting (XSS) vulnerability in its search query tracking functionality.

The vulnerability occurs because the application retrieves the `search` parameter from the URL using `location.search` and passes its value to the `document.write()` function without proper validation or safe handling.

Since `document.write()` interprets the supplied data as HTML, an attacker can manipulate the search parameter to inject HTML elements and execute JavaScript in the victim's browser.

The vulnerability was successfully confirmed by injecting an SVG element with an `onload` event handler that executed JavaScript.

## 2. Vulnerability Analysis

### 2.1 Identifying the Source

During the initial investigation, the search functionality was tested using a simple marker value:

```text
?search=RASEL123
```

The marker appeared in the page's HTML, indicating that the search parameter was being used by the application.

Further inspection of the JavaScript code revealed the following:

```javascript
var query = (new URLSearchParams(window.location.search)).get('search');
```

**Explanation:**

- `window.location.search` retrieves the query string from the current URL.
- `URLSearchParams()` parses the query string.
- `.get('search')` extracts the value of the `search` parameter.
- The extracted value is stored in the `query` variable.

For example, if the URL contains:

```text
https://example.com/?search=RASEL123
```

The `query` variable receives:

```text
RASEL123
```

This makes `location.search` the source of attacker-controllable input.

### 2.2 Identifying the Sink

Further inspection revealed the following JavaScript function:

```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
```

The function constructs an HTML image element and inserts the supplied search query into its `src` attribute.

For example, if the query value is `RASEL123`, the generated HTML becomes:

```html
<img src="/resources/images/tracker.gif?searchTerms=RASEL123">
```

**Root cause:**

The application directly concatenates user-controlled input into an HTML string and passes it to `document.write()`.

The function does not safely handle special HTML characters or prevent the input from breaking out of the existing HTML attribute.

As a result, an attacker can manipulate the generated HTML structure.

### 2.3 Understanding the Data Flow

The following code checks whether a search query exists and passes it to the tracking function:

```javascript
if(query) {
    trackSearch(query);
}
```

The complete data flow is:

1. The application retrieves the search parameter from the URL.
2. The value is stored in the `query` variable.
3. The value is passed to the `trackSearch()` function.
4. The function concatenates it into an HTML string.
5. `document.write()` writes the resulting HTML into the document.

This creates an unsafe flow from an attacker-controlled source to an HTML execution sink.

## 3. Proof of Concept (PoC)

**Payload:**

```html
"><svg onload=alert(1)>
```

**URL-encoded payload:**

```text
%22%3E%3Csvg%20onload%3Dalert(1)%3E
```

**Testing procedure:**

1. Identified the `search` parameter as a user-controllable input.
2. Inspected the JavaScript code and identified `location.search` as the source.
3. Traced the input to the `document.write()` sink.
4. Injected the crafted payload into the `search` parameter.
5. Observed that the injected SVG element triggered the `onload` event.
6. Confirmed successful JavaScript execution through the `alert(1)` dialog.

**Result:** The JavaScript alert executed successfully, confirming the DOM-based XSS vulnerability.

## 4. Technical Explanation

The original JavaScript generates the following HTML structure:

```html
<img src="/resources/images/tracker.gif?searchTerms=USER_INPUT">
```

The injected payload contains three important parts:

**1. `"` — Attribute breakout**

Closes the existing double-quoted `src` attribute.

**2. `>` — Tag breakout**

Closes the existing `img` element.

**3. `<svg onload=alert(1)>` — JavaScript execution**

Creates an SVG element with an `onload` event handler. The handler executes `alert(1)` when the SVG element loads.

After injecting the payload, the browser receives HTML conceptually similar to:

```html
<img src="/resources/images/tracker.gif?searchTerms=">
<svg onload=alert(1)>
">
```

The injected SVG element is interpreted as HTML rather than ordinary text, allowing its event handler to execute.

### Why URL Encoding Did Not Prevent the XSS

The payload was also tested in URL-encoded form.

URL encoding represents certain special characters using percent-encoded values. For example:

- `"` becomes `%22`
- `<` becomes `%3C`
- `>` becomes `%3E`
- Space becomes `%20`

The `URLSearchParams` API decodes percent-encoded parameter values when extracting them.

Therefore, the JavaScript eventually receives the decoded payload and passes it to `document.write()`.

URL encoding alone does not provide XSS protection.

## 5. Impact

If exploited against a real application, DOM-based XSS may allow an attacker to execute JavaScript in another user's browser under the vulnerable application's origin.

Depending on the application's functionality and security controls, potential consequences include:

- Performing unauthorized actions using the victim's authenticated session.
- Reading sensitive information accessible to the page.
- Modifying page content or manipulating user interactions.
- Stealing sensitive data that is accessible to JavaScript.
- Conducting phishing attacks through manipulated page content.

The actual impact depends on the application's functionality, browser security controls, and implemented protections.

The successful `alert(1)` execution confirms JavaScript execution but does not, by itself, demonstrate all these potential impacts.

## 6. Remediation

The primary remediation is to avoid inserting untrusted input directly into HTML using `document.write()`.

### Recommended approach

If the application only needs to display user-controlled text, use `textContent` instead of HTML-parsing methods.

For the tracking functionality, construct the image element safely and assign its URL through the `src` property.

Example:

```javascript
function trackSearch(query) {
    const img = document.createElement('img');

    img.src = '/resources/images/tracker.gif?searchTerms='
        + encodeURIComponent(query);

    document.body.appendChild(img);
}
```

**Why this is safer:**

- `document.createElement()` creates an actual HTML element.
- Assigning the URL through the `src` property avoids constructing an HTML string containing attacker-controlled markup.
- `encodeURIComponent()` safely encodes the query value when it is included as a URL parameter.

Additional recommendations:

- Avoid unsafe HTML sinks such as `document.write()` and `innerHTML` when handling untrusted input.
- Use context-appropriate output handling.
- Apply a restrictive Content Security Policy (CSP) as an additional security layer.
- Review client-side code to ensure attacker-controlled data cannot reach dangerous sinks without appropriate handling.

## 7. Testing Summary

The vulnerability was identified and validated through the following process:

1. Submitted a unique marker through the search functionality.
2. Identified the marker in the page output.
3. Inspected the JavaScript responsible for processing the search parameter.
4. Identified `location.search` as the source and `document.write()` as the sink.
5. Traced the input flow from the URL to the HTML-writing function.
6. Injected an HTML-breaking payload containing an SVG event handler.
7. Confirmed JavaScript execution through `alert(1)`.

## 8. Conclusion

The application was vulnerable to DOM-based XSS because attacker-controlled URL input was passed directly into `document.write()` without safe handling.

The vulnerability was successfully demonstrated by breaking out of an existing HTML attribute and injecting an SVG element with an executable event handler.

The issue can be prevented by avoiding unsafe HTML string insertion and using safer DOM manipulation techniques.
