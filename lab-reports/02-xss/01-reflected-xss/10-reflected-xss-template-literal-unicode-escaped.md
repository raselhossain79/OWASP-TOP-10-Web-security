# Lab: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

## 1. Summary

The search functionality was vulnerable to Reflected Cross-Site Scripting (XSS) because user-controlled input was directly embedded inside a JavaScript Template Literal.

Although the application Unicode-escaped several special characters, it did not prevent JavaScript expression interpolation using `${...}`.

This allowed JavaScript execution inside the Template Literal context.

## 2. Vulnerability Analysis

The search input was reflected inside the following JavaScript code:

```javascript
var message = `0 search results for 'USER_INPUT'`;
```

The application Unicode-escaped several special characters:

| Character | Unicode Escape |
|---|---|
| `'` | `\u0027` |
| `"` | `\u0022` |
| `\` | `\u005c` |
| `>` | `\u003e` |
| Backtick | `\u0060` |

However, the application did not neutralize the `${...}` expression interpolation syntax.

## 3. Exploitation

### Step 1: Identify Reflection

Submitted a unique marker through the search functionality and inspected the HTTP response.

### Step 2: Analyze JavaScript Context

Identified that the reflected input was placed directly inside a JavaScript Template Literal.

### Step 3: Test Expression Injection

Submitted the following payload:

```javascript
${alert(1)}
```

The browser executed the JavaScript expression and displayed an alert.

### Step 4: Additional Testing

Also tested:

```javascript
${alert(1)}//
```

This payload executed successfully as well.

The `//` was unnecessary because it remained ordinary text inside the Template Literal. The `${alert(1)}` expression alone was sufficient to trigger JavaScript execution.

## 4. Root Cause

The application embedded untrusted user input directly into a JavaScript Template Literal without safely handling JavaScript expression interpolation.

Unicode-escaping selected special characters did not prevent `${...}` from being interpreted as an executable JavaScript expression.

## 5. Impact

An attacker could potentially execute arbitrary JavaScript in a victim's browser under the vulnerable application's origin.

Depending on the application's functionality and security controls, this could lead to:

- Unauthorized actions through the victim's authenticated session.
- Access to sensitive information available to page JavaScript.
- Phishing or malicious content injection.

Actual impact depends on the application's context and security controls.

## 6. Remediation

- Avoid inserting untrusted input directly into JavaScript code.
- Prefer passing dynamic data through safe DOM APIs.
- Use `textContent` instead of unsafe HTML insertion methods where appropriate.
- Apply context-appropriate output encoding.
- Use a restrictive Content Security Policy (CSP) as an additional security layer.

## 7. Key Learnings

- Template Literals use backticks instead of single or double quotes.
- `${...}` allows JavaScript expressions to be evaluated inside Template Literals.
- Unicode escaping selected characters does not automatically prevent XSS.
- `//` does not act as a comment inside ordinary Template Literal content.
- Understanding the JavaScript execution context is more important than memorizing payloads.

**Vulnerability Type:** Reflected Cross-Site Scripting (XSS)  
**Injection Context:** JavaScript Template Literal  
**Technique:** Template Literal Expression Injection  
**Validation:** Successful execution of `alert(1)`
