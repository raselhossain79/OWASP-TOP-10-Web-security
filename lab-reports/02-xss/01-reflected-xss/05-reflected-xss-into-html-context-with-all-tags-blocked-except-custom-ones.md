# Reflected XSS — Custom HTML Tags with Automatic Focus

## 1. Lab Information

- **Platform:** PortSwigger Web Security Academy
- **Lab:** Reflected XSS into HTML context with all tags blocked except custom ones
- **Difficulty:** Practitioner
- **Vulnerability:** Reflected Cross-Site Scripting (XSS)
- **Injection Context:** HTML Body
- **Technique:** Custom HTML Element + Event Handler + URL Fragment
- **Status:** Solved

## 2. Vulnerability Overview

The application reflects user-controlled input inside an HTML element in the response.

However, the application blocks standard HTML tags while allowing custom HTML elements.

This filtering behavior creates an opportunity to inject a custom HTML element containing an event handler.

By making the injected element receive focus automatically, JavaScript can execute through its `onfocus` event handler.

## 3. Identifying the Injection Point

A test string was submitted through the search functionality.

Example:

```text
zzXSS12345zz
```

The server reflected the input inside the following HTML structure:

```html
<h1>zzXSS12345zz</h1>
```

### Observation

- User input was reflected inside the HTML body.
- The input was interpreted as HTML content.
- Standard HTML tags were restricted.
- Custom HTML elements were permitted.

This indicated an opportunity to investigate custom HTML element injection.

## 4. Understanding the Payload

The following payload was used:

```html
<xss id=x onfocus=alert(document.cookie) tabindex=1>
```

### Payload Breakdown

| Component | Purpose |
|---|---|
| `<xss>` | Creates a custom HTML element |
| `id=x` | Assigns an identifier to the element |
| `onfocus` | Executes JavaScript when the element receives focus |
| `alert(document.cookie)` | Demonstrates JavaScript execution |
| `tabindex=1` | Makes the element focusable |

### Why a Custom Element?

The application blocked standard HTML tags but allowed custom HTML elements.

Therefore, a custom element was used instead of conventional tags such as `<script>` or `<img>`.

### Why `onfocus`?

The `onfocus` event executes JavaScript when an element receives focus.

However, the element must actually receive focus before the event handler executes.

### Why `tabindex=1`?

Custom elements are not normally focusable through keyboard navigation.

The `tabindex` attribute makes the element focusable.

## 5. Understanding the URL Fragment

The following fragment was appended to the target URL:

```text
#x
```

The complete URL structure:

```text
https://target.com/?search=PAYLOAD#x
```

The fragment identifier references the element whose ID is `x`.

The browser uses this fragment for client-side navigation and focus behavior.

The fragment is not sent to the server as part of the HTTP request.

When the browser navigates to the matching focusable element, the `onfocus` event can execute.

## 6. URL Encoding

The HTML payload needed URL encoding before being included in the query parameter.

Example:

```text
<xss id=x onfocus=alert(document.cookie) tabindex=1>
```

Encoded representation:

```text
%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E
```

Some important encodings:

| Character | Encoded |
|---|---|
| `<` | `%3C` |
| `>` | `%3E` |
| `=` | `%3D` |
| `(` | `%28` |
| `)` | `%29` |
| Space | `%20` or `+` |

URL encoding ensures special characters can be transmitted correctly as part of the query parameter.

## 7. Exploit Delivery Using Exploit Server

The lab provided an Exploit Server to deliver the attack to the simulated victim.

The following JavaScript was placed in the Exploit Server's Body:

```html
<script>
location = 'https://TARGET-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```

Replace `TARGET-LAB-ID` with the actual lab hostname.

### Explanation

- `<script>` executes JavaScript on the Exploit Server page.
- `location` changes the browser's current URL.
- The victim's browser navigates to the vulnerable target.
- The target reflects and parses the custom HTML element.
- The `#x` fragment identifies the injected element.
- Focus triggers the `onfocus` event.
- JavaScript executes in the target's origin.

### Execution Flow

```text
Attacker
   |
   v
Exploit Server
   |
   v
Victim visits exploit page
   |
   v
JavaScript redirects victim
   |
   v
Vulnerable target receives request
   |
   v
Custom HTML element is reflected
   |
   v
Browser focuses element
   |
   v
onfocus event executes
   |
   v
JavaScript execution
```

### Final Steps

1. Save the exploit on the Exploit Server.
2. Click **Deliver exploit to victim**.
3. The victim's browser loads the malicious URL.
4. The lab confirms successful exploitation.

## 8. Key Technical Lessons

- Reflection alone does not prove XSS.
- Always identify the HTML injection context.
- HTML filtering does not necessarily prevent custom element injection.
- Event handlers can provide JavaScript execution without a script tag.
- `tabindex` can make otherwise non-focusable elements focusable.
- URL fragments are processed by the browser, not the server.
- Exploit delivery and vulnerability execution are two separate stages.
- URL encoding is important when transmitting HTML payloads through query parameters.

---

# 9. Real-World Bug Bounty / Penetration Testing Workflow

The PortSwigger lab uses a controlled Exploit Server and simulated victim. In real Bug Bounty or authorized penetration testing, the workflow is slightly different.

## Step 1 — Identify the Injection Point

Start by examining application functionality:

- Search parameters
- URL query parameters
- Form submissions
- Profile fields
- Feedback forms
- Other user-controlled inputs

Use Burp Suite or Caido to inspect HTTP requests and responses.

Example:

```http
GET /search?q=test HTTP/1.1
Host: target.com
```

## Step 2 — Identify the Reflection Context

Submit a harmless unique test string and inspect the response.

Determine whether the input appears inside:

- HTML body
- HTML attribute
- JavaScript string
- URL attribute
- Other contexts

Do not assume that every reflected input is vulnerable.

## Step 3 — Understand Filtering and Encoding

Investigate how the application handles special characters.

Check whether:

- HTML tags are filtered.
- Angle brackets are encoded.
- Event handler attributes are removed.
- Input is reflected unchanged.
- Different payloads produce different responses.

Understand the browser's interpretation of the resulting HTML.

## Step 4 — Test JavaScript Execution

Use a harmless proof-of-concept such as:

```html
<script>alert(1)</script>
```

If script tags are blocked, investigate other execution contexts and event handlers based on the identified injection point.

For a custom-element scenario, investigate:

```html
<xss id=x tabindex=1 onfocus=alert(1)>
```

The exact technique depends on the application's filtering behavior and browser context.

## Step 5 — Validate the Impact

If JavaScript execution works in your own browser, determine whether the vulnerability can affect another user.

Consider:

- Does the victim need to click a link?
- Does execution happen automatically?
- Is authentication required?
- Does the vulnerability affect other users?
- Are there restrictions from CSP or browser security controls?

Use only authorized test accounts and controlled demonstrations.

## Step 6 — Exploit Delivery

You do not always need an Exploit Server.

### Situation A: Direct Reflected XSS

If the payload executes when a user opens the crafted target URL, the URL itself may be sufficient for demonstrating the vulnerability.

### Situation B: Custom HTML or Automatic Execution

If the attack requires a specially constructed HTML page, use an authorized controlled hosting environment.

Possible options:

- Burp Suite Exploit Server
- Your own controlled web server
- An approved static hosting service

The hosting page can redirect a test browser or embed the vulnerable page where appropriate.

### Situation C: Victim Interaction Required

If the payload requires clicking, focusing, or another action, document that requirement accurately.

Do not claim automatic exploitation if user interaction is necessary.

## Step 7 — Prepare the Proof of Concept

A good PoC should demonstrate:

1. The affected endpoint.
2. The vulnerable parameter.
3. The injection context.
4. The JavaScript execution.
5. The conditions required for exploitation.
6. The security impact.

Use a harmless alert or another approved demonstration.

Never steal cookies, access another user's private information, or perform actions outside the program's authorization.

## Step 8 — Write the Security Report

A professional report should contain:

- Title
- Summary
- Affected endpoint
- Vulnerability details
- Reproduction steps
- HTTP request and response
- Proof of concept
- Impact
- Recommended remediation

### Suggested Remediation

- Apply context-aware output encoding.
- Avoid inserting untrusted input directly into HTML.
- Use safe DOM APIs such as `textContent`.
- Avoid unsafe HTML insertion methods.
- Apply an appropriate Content Security Policy as defense in depth.
- Do not rely exclusively on tag or keyword filtering.

## 10. Lab vs Real-World Comparison

| Aspect | PortSwigger Lab | Real Bug Bounty |
|---|---|---|
| Target | Simulated application | Authorized program target |
| Filtering | Known lab behavior | Unknown implementation |
| Injection point | Provided | Must discover |
| Payload | Known technique | Requires investigation |
| Exploit delivery | Provided Exploit Server | Depends on attack scenario |
| Victim | Simulated victim | Authorized test account or approved user |
| Reporting | Lab completion | Professional vulnerability report |

## 11. Final Takeaway

The most important lesson from this lab is not memorizing the payload.

It is understanding how user-controlled input becomes HTML, how the browser parses custom elements, how focus triggers event handlers, and how an attacker can deliver a crafted URL or page to another browser.

In real-world security testing, first prove the vulnerability, understand its execution conditions, validate its impact safely, and then prepare a reproducible report.
