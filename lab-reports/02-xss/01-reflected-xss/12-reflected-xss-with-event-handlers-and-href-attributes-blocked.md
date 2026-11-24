# Reflected XSS with Event Handlers and `href` Attributes Blocked


## 1. Summary

The search functionality was found to be vulnerable to reflected Cross-Site Scripting (XSS).

The application allowed certain HTML and SVG elements while blocking JavaScript event handlers and directly injected anchor `href` attributes.

However, the filtering mechanism could be bypassed by leveraging SVG SMIL animation to dynamically modify the `href` attribute of an SVG anchor element.

When the injected SVG link was clicked, the JavaScript `alert()` function executed successfully.

## 2. Vulnerability Classification

- **Vulnerability:** Reflected Cross-Site Scripting (XSS)
- **Injection Point:** Search parameter
- **Context:** HTML / SVG
- **Technique:** SVG SMIL Animation
- **Impact:** JavaScript execution in the victim's browser

## 3. Reconnaissance and Testing

A unique marker was submitted through the search functionality:

```http
GET /?search=zzXSS12345zz HTTP/1.1
```

The application reflected the supplied input inside an HTML heading:

```html
<h1>0 search results for 'zzXSS12345zz'</h1>
```

Next, different HTML and SVG elements were tested to identify the application's allowed tags.

The following elements returned HTTP 200 responses:

- `<title>`
- `<svg>`
- `<img>`
- `<a>`
- `<animate>`

Other tested elements returned HTTP 400 responses.

JavaScript event handler attributes were also tested, but they were blocked.

## 4. Exploitation Process

### Step 1: Identify allowed elements

The `<svg>`, `<a>`, and `<animate>` elements were confirmed to be accepted and reflected by the application.

### Step 2: Understand SVG animation

SVG SMIL animation allows an element's attributes to be dynamically modified.

The `attributeName` attribute specifies which attribute should be animated, while `values` specifies the value to apply.

### Step 3: Construct the XSS vector

The following vector was used:

```html
<svg>
  <a>
    <animate attributeName="href"
             values="javascript:alert(1)" />
    <text x="20" y="20">Click</text>
  </a>
</svg>
```

### Step 4: Trigger JavaScript execution

The SVG animation modifies the parent anchor element's `href` attribute.

When the simulated victim clicks the visible "Click" text, the browser processes the JavaScript URL and executes `alert(1)`.

## 5. Root Cause

The application relied on an insufficient HTML filtering mechanism.

Although direct event handlers and anchor `href` attributes were blocked, the application permitted SVG animation elements that could dynamically modify sensitive attributes.

This allowed an attacker to bypass the intended restrictions and achieve JavaScript execution.

## 6. Security Impact

Successful exploitation could allow an attacker to execute JavaScript in another user's browser under the vulnerable application's origin.

Depending on the application's security controls and the victim's privileges, potential consequences include:

- Unauthorized actions performed through the victim's session.
- Manipulation of application content.
- Access to information exposed to JavaScript within the page.
- Phishing through manipulated application content.

## 7. Remediation

- Avoid relying on tag and attribute blacklists for XSS prevention.
- Apply context-aware output encoding.
- Sanitize untrusted HTML using a well-maintained HTML sanitization library.
- Restrict unnecessary SVG elements and animation capabilities.
- Validate URLs using strict allowlists.
- Implement Content Security Policy (CSP) as an additional security layer.

## 8. Key Learning Points

- HTML tag filtering alone does not guarantee XSS protection.
- SVG elements have their own browser-specific behaviors.
- SVG SMIL animation can dynamically modify element attributes.
- `attributeName` identifies the attribute being animated.
- `href` and `xlink:href` are different linking mechanisms with different compatibility behavior.
- Always validate the final payload in the browser rather than relying only on HTTP response status codes.
