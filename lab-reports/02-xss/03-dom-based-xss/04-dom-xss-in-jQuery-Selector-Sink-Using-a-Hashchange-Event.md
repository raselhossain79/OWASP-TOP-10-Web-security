# DOM XSS in jQuery Selector Sink Using a Hashchange Event   
## 1. Vulnerability Overview

**Vulnerability Type:** DOM-Based Cross-Site Scripting (DOM XSS)  
**Severity:** Depends on application context and victim interaction  
**Affected Component:** jQuery selector  
**Source:** `window.location.hash`  
**Sink:** jQuery `$()` selector function  
**Trigger:** `hashchange` event

This lab demonstrates a DOM-based XSS vulnerability caused by inserting attacker-controlled URL fragment data into a jQuery selector.

The application reads the URL hash, decodes it, and concatenates it into a jQuery selector without proper validation. Because the selector is dynamically constructed using untrusted input, an attacker can manipulate the selector and trigger JavaScript execution.

The vulnerability is exploited by delivering a crafted URL through an iframe hosted on the Exploit Server.

## 2. Source & Sink Identification

### Source

```javascript
window.location.hash.slice(1)
```

The source is `window.location.hash`, which retrieves the fragment portion of the current URL.

For example:

```text
https://example.com/#post-123
```

Here, `#post-123` is the URL fragment.

The `.slice(1)` removes the leading `#`, leaving:

```text
post-123
```

Since an attacker can control the URL fragment, this value is considered untrusted input.

### Sink

```javascript
$('section.blog-list h2:contains(' + userInput + ')')
```

The `$()` function is jQuery's selector function. It receives a dynamically constructed selector string.

The application directly concatenates the user-controlled hash value into that selector.

This creates a dangerous flow:

**Attacker-controlled URL hash → jQuery selector → DOM manipulation behavior**

## 3. Vulnerable Code Analysis

The vulnerable application code:

```javascript
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' +
        decodeURIComponent(window.location.hash.slice(1)) + ')');

    if (post) post.get(0).scrollIntoView();
});
```

### Code Breakdown

**1. Event listener**

```javascript
$(window).on('hashchange', function(){
```

Registers an event listener that executes whenever the URL fragment changes.

**2. Reading the URL hash**

```javascript
window.location.hash.slice(1)
```

Retrieves the URL fragment and removes the leading `#`.

**3. Decoding the input**

```javascript
decodeURIComponent(...)
```

Decodes URL-encoded characters into their original representation.

**4. Constructing the jQuery selector**

```javascript
$('section.blog-list h2:contains(' + userInput + ')')
```

Searches for an `h2` element inside `section.blog-list` whose text contains the supplied value.

However, the application inserts the input directly into the selector string without validating it.

**5. Automatic scrolling**

```javascript
post.get(0).scrollIntoView();
```

Scrolls the browser to the matching element.

The intended functionality is to locate a blog post and automatically scroll to it. However, the unsafe selector construction allows an attacker to manipulate how jQuery interprets the selector.

## 4. Proof of Concept (PoC)

### Step 1: Locate the vulnerable JavaScript

I opened the browser Developer Tools and navigated to the **Debugger** tab.

Then I used:

```text
Ctrl + Shift + F
```

This opened the global search functionality.

I searched for:

```text
<script
```

By examining the matching JavaScript code, I located the vulnerable `hashchange` event handler and identified the unsafe use of `window.location.hash` inside the jQuery selector.

### Step 2: Validate the behavior

I tested the URL fragment using:

```html
#<img src=x onerror=alert(1)>
```

The input was reflected through the URL hash, and the page's automatic scrolling behavior was triggered.

This helped identify the vulnerable input flow and investigate the selector sink.

### Step 3: Prepare the exploit

The lab required delivering an exploit that executes `print()` in the victim's browser.

I used the following HTML in the Exploit Server's Body:

```html
<iframe src="https://0a030081040d9609808503e300560070.web-security-academy.net/"
        onload="this.src += '#<img src=x onerror=print()>'">
</iframe>
```

### Step 4: Deliver the exploit

1. Saved the HTML using the Exploit Server's **Store** button.
2. Selected **Deliver exploit to victim**.
3. The victim's browser loaded the iframe and triggered the payload.
4. The browser's print dialog appeared, confirming successful JavaScript execution.

**Result:** Lab successfully solved.

## 5. Payload Breakdown

### Injected payload

```html
<img src=x onerror=print()>
```

- `<img>` creates an image element.
- `src=x` provides an invalid image source.
- `onerror` is an event handler that executes when the image fails to load.
- `print()` invokes the browser's print functionality.

### Why use an iframe?

```html
<iframe src="TARGET_URL" onload="..."></iframe>
```

The iframe loads the vulnerable application inside the exploit page.

Its `onload` handler executes after the iframe loads.

```javascript
this.src += '#<img src=x onerror=print()>'
```

This appends the crafted fragment to the iframe's existing URL.

Changing the fragment triggers the target application's `hashchange` event, causing the vulnerable JavaScript code to execute again with the attacker-controlled input.

The injected input reaches the jQuery selector and triggers the XSS behavior.

## 6. Attack Flow

1. Attacker creates a malicious page on the Exploit Server.
2. The page loads the vulnerable application inside an iframe.
3. The iframe's `onload` handler appends a malicious URL fragment.
4. The target application's `hashchange` event is triggered.
5. The application reads the attacker-controlled fragment.
6. The input is inserted into a jQuery selector without proper validation.
7. The manipulated selector causes JavaScript execution.
8. `print()` executes in the victim's browser.

## 7. Potential Impact

Depending on the application and browser context, DOM-based XSS can allow an attacker to:

- Execute arbitrary JavaScript in the vulnerable application's origin.
- Manipulate page content and user interactions.
- Perform actions using the victim's authenticated session, subject to browser and application security controls.
- Access non-HttpOnly data available to JavaScript.
- Conduct phishing or other client-side attacks.

The actual impact depends on the application's functionality, security controls, and victim interaction.

## 8. Remediation

**1. Avoid inserting untrusted input directly into jQuery selectors.**

Do not construct selector strings by concatenating attacker-controlled values.

**2. Validate and constrain URL fragment values.**

If the application expects a post identifier, validate it against an expected format rather than accepting arbitrary input.

**3. Use safer DOM selection techniques.**

Where possible, retrieve elements using known identifiers and compare their text content separately instead of dynamically constructing selectors from untrusted input.

**4. Keep jQuery updated.**

Use a supported and up-to-date jQuery version. However, updating jQuery alone does not fix unsafe application-level input handling.

**5. Implement Content Security Policy (CSP).**

A properly configured CSP can reduce the impact of certain XSS attacks, although it should not replace secure input handling.

## 9. Key Learning Points

- `window.location.hash` is a potential attacker-controlled source.
- `hashchange` is an event triggered when the URL fragment changes.
- jQuery's `$()` function can become a dangerous sink when given dynamically constructed selectors containing untrusted input.
- DOM XSS can occur even when the application does not send the malicious input to the server.
- An iframe can be used to deliver an exploit and trigger the vulnerable event in another page.
- Browser Developer Tools' global search (`Ctrl + Shift + F`) is useful for locating JavaScript code during security testing.
- Identifying a source and sink is more important than memorizing individual payloads.

**Main Takeaway:** Never assume that data from a URL fragment is safe. Even though it is not sent to the server by default, it can still reach dangerous JavaScript functions and cause DOM-based XSS.
