# Stored DOM XSS 

**Difficulty:** Practitioner  
**Platform:** PortSwigger Web Security Academy  
**Status:** Solved

## 1. Vulnerability Overview

This lab demonstrates a Stored DOM-based Cross-Site Scripting (XSS) vulnerability in the blog comment functionality.

Stored DOM XSS occurs when attacker-controlled data is stored by an application and later retrieved by client-side JavaScript, which processes the data unsafely and inserts it into the DOM.

In this lab:

1. An attacker submits a comment containing malicious input.
2. The application stores the comment on the server.
3. When someone visits the blog post, JavaScript retrieves the stored comments.
4. The client-side code attempts to escape HTML characters before inserting the comment into the DOM.
5. However, the escaping function uses JavaScript's `replace()` method incorrectly.
6. This allows additional HTML markup to bypass the escaping and execute JavaScript.

The vulnerability exists because the application relies on incomplete HTML escaping before using `innerHTML`.

## 2. Source & Sink Identification

| Component | Identification |
|---|---|
| Source | Stored comment data returned by the server |
| Data retrieval | `XMLHttpRequest` |
| Data parsing | `JSON.parse()` |
| Vulnerable sanitization | `escapeHTML()` |
| Dangerous sink | `innerHTML` |
| Vulnerable fields | `comment.body` and potentially `comment.author` |

### Source

```javascript
let xhr = new XMLHttpRequest();

xhr.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        let comments = JSON.parse(this.responseText);
        displayComments(comments);
    }
};

xhr.open("GET", postCommentPath + window.location.search);
xhr.send();
```

The application retrieves stored comments from the server using an HTTP GET request.

The response is parsed using:

```javascript
let comments = JSON.parse(this.responseText);
```

The parsed comment data is then passed to:

```javascript
displayComments(comments);
```

The source is the attacker-controlled comment data returned by the server, particularly:

```javascript
comment.body
comment.author
```

Unlike reflected DOM XSS, the malicious input does not need to be supplied through the victim's current URL. It was previously submitted and stored as a comment.

## 3. Vulnerable Code Analysis

### Step 1: The HTML escaping function

The application attempts to escape HTML using:

```javascript
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```

At first glance, this function appears to replace HTML angle brackets.

However, there is a problem with how JavaScript's `replace()` method works.

When its first argument is a string, `replace()` replaces only the **first matching occurrence**.

It does not automatically replace every occurrence.

For example:

**Input:**

```html
<> <img src=x onerror=alert(1)>
```

**Output:**

```text
&lt;&gt; <img src=x onerror=alert(1)>
```

Notice the difference:

- The first `<` was replaced with `&lt;`.
- The first `>` was replaced with `&gt;`.
- The next `<` and `>` remained unchanged.

As a result, the second HTML tag was not properly escaped.

### Step 2: Processing the comment body

The application processes the comment body using:

```javascript
if (comment.body) {
    let commentBodyPElement = document.createElement("p");
    commentBodyPElement.innerHTML = escapeHTML(comment.body);

    commentSection.appendChild(commentBodyPElement);
}
```

The application:

1. Creates a new paragraph element.
2. Passes the comment body through `escapeHTML()`.
3. Assigns the returned value to `innerHTML`.
4. Appends the paragraph to the comment section.

The problem is that `innerHTML` parses its assigned value as HTML.

Since the escaping function does not escape every angle bracket, an attacker-controlled HTML element can survive and become part of the DOM.

### Step 3: Processing the author field

The application also uses `innerHTML` when processing the comment author:

```javascript
let newInnerHtml = firstPElement.innerHTML + escapeHTML(comment.author);
firstPElement.innerHTML = newInnerHtml;
```

This is another potentially vulnerable location because it uses the same incomplete escaping function before assigning the result to `innerHTML`.

However, the successful exploit in this lab used the comment body.

## 4. Proof of Concept (PoC)

The following payload was submitted through the blog comment functionality:

```html
<> <img src=x onerror=alert(1)>
```

### Payload Breakdown

**Part 1:**

```html
<>
```

This is an initial HTML-like sequence containing one opening and one closing angle bracket.

Its purpose is to consume the first occurrences of `<` and `>` in the escaping function.

After processing:

```text
&lt;&gt;
```

**Part 2:**

```html
<img src=x onerror=alert(1)>
```

This is the actual injected HTML element.

Because the first occurrences of `<` and `>` have already been replaced, the angle brackets surrounding this image element remain unchanged.

Therefore, the browser can interpret it as an HTML element.

**Part 3:**

```html
src=x
```

The image source points to an invalid location.

When the browser fails to load the image, its error event is triggered.

**Part 4:**

```javascript
onerror=alert(1)
```

This event handler executes `alert(1)` when the image fails to load.

**Result:** The browser executed the alert function, confirming successful XSS exploitation.

## 5. Attack Flow

1. The attacker submits a malicious comment containing the PoC payload.
2. The application stores the comment on the server.
3. A visitor opens the affected blog post.
4. The browser requests the stored comments through `XMLHttpRequest`.
5. The server returns the comment data.
6. JavaScript parses the response using `JSON.parse()`.
7. The comment body is passed to `escapeHTML()`.
8. The escaping function replaces only the first occurrences of `<` and `>`.
9. The remaining HTML markup reaches the `innerHTML` sink.
10. The browser creates the injected image element.
11. The image fails to load, triggering `onerror`.
12. JavaScript executes `alert(1)` in the context of the vulnerable page.

Because the malicious comment is stored, the attack can affect other visitors who view the same blog post.

## 6. Potential Impact

Depending on the application's functionality and the privileges of affected visitors, Stored DOM XSS may allow an attacker to:

- Execute JavaScript in other users' browsers.
- Perform actions on behalf of authenticated users.
- Modify page content and manipulate the user interface.
- Access sensitive information available to JavaScript.
- Deliver phishing content through the trusted application origin.
- Potentially access session-related information if it is exposed to JavaScript.

HttpOnly cookies cannot be directly accessed through `document.cookie`.

Stored XSS can be particularly serious because the malicious content remains saved and can affect multiple visitors without requiring each victim to receive a separate malicious URL.

## 7. Remediation

### 1. Avoid unsafe HTML insertion

The application should use `textContent` when displaying comment content as plain text.

**Vulnerable:**

```javascript
commentBodyPElement.innerHTML = escapeHTML(comment.body);
```

**Safer:**

```javascript
commentBodyPElement.textContent = comment.body;
```

`textContent` treats the supplied value as text rather than parsing it as HTML.

### 2. Use a proper HTML sanitizer when HTML is required

If the application intentionally supports HTML in comments, it should use a well-maintained HTML sanitization library such as DOMPurify.

Example:

```javascript
commentBodyPElement.innerHTML = DOMPurify.sanitize(comment.body);
```

The sanitizer should be configured according to the application's allowed HTML elements and attributes.

### 3. Do not rely on incomplete character replacement

The original implementation:

```javascript
html.replace('<', '&lt;').replace('>', '&gt;');
```

does not replace every occurrence.

Simply changing it to a global replacement is not a complete substitute for context-aware output encoding or a proper HTML sanitizer.

### 4. Implement Content Security Policy (CSP)

A properly configured CSP can provide an additional layer of defense against XSS.

However, CSP should not replace fixing unsafe DOM manipulation.

## 8. Key Learning Points

- Stored DOM XSS involves malicious data being stored and later processed unsafely by client-side JavaScript.
- The source can be server-returned stored data rather than a URL parameter.
- `JSON.parse()` safely parses valid JSON; it does not make the resulting data safe for HTML insertion.
- `innerHTML` parses assigned content as HTML.
- JavaScript's `replace()` with a string argument replaces only the first matching occurrence.
- Incomplete escaping can allow additional HTML markup to bypass sanitization.
- An image's `onerror` event can execute JavaScript when its source fails to load.
- The same escaping weakness can affect multiple fields, not just the comment body.
- `textContent` is preferable when displaying untrusted content as plain text.

**Final Takeaway:** Never assume that user input is safe just because an application has an escaping function. Understand exactly what the function replaces, where the data goes, and whether the final DOM operation interprets that data as HTML or plain text.
