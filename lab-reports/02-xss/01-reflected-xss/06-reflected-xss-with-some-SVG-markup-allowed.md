# Reflected XSS — SVG Markup and Event Handler Filter Bypass   

## 1. Summary

The search functionality of the application was found to be vulnerable to Reflected Cross-Site Scripting (XSS).

The application implemented filtering that blocked common HTML tags and event handlers. However, certain SVG elements and event handlers were still permitted, allowing JavaScript execution in the browser.

The vulnerability was successfully exploited by identifying allowed SVG elements and combining an SVG animation element with an executable event handler.

## 2. Vulnerability Details

- **Vulnerability:** Reflected Cross-Site Scripting (XSS)
- **Affected Functionality:** Search functionality
- **Injection Context:** HTML Body
- **Severity:** Depends on application context and impact
- **CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation

## 3. Testing Methodology

### Step 1 — Identify Reflection

A unique marker was submitted through the search functionality to identify whether user-controlled input was reflected in the HTML response.

The response showed that the input was reflected inside an HTML heading element without proper output encoding.

### Step 2 — Automated HTML Tag Detection

An automated tag detection technique was used to identify which HTML and SVG elements were accepted by the application's filtering mechanism.

Several elements were identified as permitted, including:

- SVG
- Image
- SVG animation-related elements such as `animatetransform`

### Step 3 — Event Handler Detection

After identifying an allowed SVG element, event handler detection was performed to determine which event attributes were accepted.

The testing process involved:

1. Selecting an allowed SVG element.
2. Testing different event handler attributes.
3. Identifying which event handlers passed the filtering mechanism.
4. Validating whether the selected event could actually execute JavaScript.

The `onload` handler was rejected, while `onbegin` was accepted in the appropriate SVG animation context.

### Step 4 — Payload Construction

The allowed SVG elements and event handlers were combined to construct a working XSS payload.

The `animatetransform` element provided the animation context required for the `onbegin` event to trigger.

The final payload successfully executed JavaScript in the browser and demonstrated the reflected XSS vulnerability.

## 4. Proof of Concept (PoC)

**Request:**

[Leave blank]

**Payload:**

[Leave blank]

**Response:**

[Leave blank]

**Browser Execution Screenshot:**

[Leave blank]

## 5. Impact

An attacker could potentially exploit this vulnerability to execute JavaScript in the context of a victim's browser session when the victim accesses a crafted URL.

Depending on the application's security controls and execution context, this could lead to:

- Unauthorized actions performed through the victim's session.
- Manipulation of page content.
- Phishing through injected content.
- Exposure of accessible client-side information.

Actual impact depends on the application's authentication mechanisms, cookie protections, and other security controls.

## 6. Remediation

- Apply context-aware output encoding to all untrusted user input.
- Avoid relying on blacklist-based HTML tag and event handler filtering.
- Sanitize HTML using a well-maintained allowlist-based HTML sanitizer when HTML input is required.
- Restrict unnecessary SVG elements and event handler attributes.
- Implement Content Security Policy (CSP) as an additional defense-in-depth measure.

## 7. Testing Workflow Summary

The vulnerability was identified and validated using the following workflow:

1. Identify user input reflection in the HTML response.
2. Determine the injection context.
3. Automate HTML/SVG tag detection to identify permitted elements.
4. Use automated event handler detection to identify accepted event attributes.
5. Combine an allowed SVG animation element with a compatible event handler.
6. Validate JavaScript execution in the browser.
7. Document the successful payload, request, response, and execution evidence.
