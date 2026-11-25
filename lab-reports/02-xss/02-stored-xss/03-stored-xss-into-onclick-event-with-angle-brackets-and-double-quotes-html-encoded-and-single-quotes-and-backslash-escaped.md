# Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

## 1. Objective

The objective was to identify and exploit a Stored XSS vulnerability where user-controlled input was embedded inside an HTML `onclick` event handler.

The application applied multiple encoding and escaping mechanisms, making direct JavaScript injection difficult.

## 2. Initial Investigation

Submitted ordinary test values through the comment form and inspected the resulting HTML.

The relevant output was:

```html
<a id="author" href="https://abc.com"
onclick="var tracker={track(){}};tracker.track('https://abc.com');">
rasel</a>
```

**Observation:**

- The `website` parameter was reflected inside the anchor's `href` attribute.
- The same value was also included inside a JavaScript string within the `onclick` event handler.
- The JavaScript string was enclosed in single quotes.

This identified the `onclick` handler as the injection context.

## 3. Filtering Analysis

Tested special characters individually to understand the application's filtering behavior.

| Input | Observed output | Behavior |
|---|---|---|
| `'` | `\'` | Single quote escaped |
| `"` | `&quot;` | HTML encoded |
| `\` | `\\` | Backslash escaped |
| `<` and `>` | Unchanged in the observed output | Not encoded in this context |

The application attempted to prevent JavaScript string breakout by escaping single quotes and backslashes.

However, this protection did not account for HTML character references.

## 4. Bypass Discovery

Tested HTML entities as an alternative representation of single quotes.

**Payload 1:**

```text
&#39;-alert(1)-&#39;
```

**Payload 2:**

```text
&apos;-alert(1)-&apos;
```

Both payloads successfully triggered JavaScript execution.

### Why did they work?

The application escaped directly supplied single quotes, but the HTML entities were not converted into actual quotes during its filtering process.

When the browser parsed the HTML attribute, it decoded the character references:

- `&#39;` → `'`
- `&apos;` → `'`

The decoded quotes then reached the JavaScript event handler and changed the original string context.

## 5. Execution Flow

The original JavaScript structure was:

```javascript
tracker.track('https://abc.com');
```

After HTML entity decoding, the relevant structure became conceptually equivalent to:

```javascript
tracker.track('https://abc.com'-alert(1)-'');
```

The browser interpreted this as a JavaScript expression:

1. The first single quote closed the original string.
2. The first `-` acted as a subtraction operator.
3. `alert(1)` executed as JavaScript code.
4. The second `-` connected the expression to the following empty string.

The author link had to be clicked to trigger the `onclick` event handler.

## 6. Key Takeaways

- Identify the exact HTML and JavaScript context before testing payloads.
- Understand how the application handles quotes, backslashes and HTML entities.
- HTML entity encoding and JavaScript string escaping are different mechanisms.
- Browser parsing order matters: HTML entities can be decoded before the event-handler JavaScript is interpreted.
- A successful injection does not always execute immediately; event handlers may require user interaction.
- Do not rely only on direct special-character tests. Alternative character representations can reveal filtering weaknesses.

## 7. Remediation

- **Avoid inline JavaScript:** Do not place user-controlled data directly inside HTML event-handler attributes such as `onclick`. Use external JavaScript and `addEventListener()` instead.
- **Apply context-aware output encoding:** Encode untrusted data according to its final output context. HTML attribute encoding alone is not sufficient when the value is embedded inside JavaScript.
- **Avoid unsafe HTML construction:** Use safe DOM APIs and avoid dynamically constructing executable JavaScript from user-controlled input.
- **Validate URLs:** If user input is intended to represent a URL, allow only approved schemes such as `https://` and `http://` where appropriate.
- **Use Content Security Policy (CSP):** Deploy a restrictive CSP as an additional security layer. Avoid relying on CSP as the primary XSS prevention mechanism.
- **Test encoding behavior:** Verify that HTML entities, quotes, backslashes and other special characters cannot change the intended parsing context.

## 8. Practical Testing Notes

During real-world testing:

1. Identify user-controlled values reflected inside event-handler attributes.
2. Inspect the actual server response.
3. Determine which characters are encoded or escaped.
4. Test alternative representations when direct injection is blocked.
5. Verify the browser's interpretation and actual execution.
6. Record whether execution requires a click or another user interaction.

**Main Lesson:** A filter that escapes dangerous characters may still be vulnerable if it fails to account for how the browser decodes and interprets the final HTML and JavaScript.

## 9. References

- [PortSwigger Web Security Academy – Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
