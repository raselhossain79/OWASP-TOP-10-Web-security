# 06 — Content Security Policy (CSP) Bypass

## What CSP Actually Is

Content Security Policy is a response header (`Content-Security-Policy: ...`) that tells the browser **which sources of content are allowed to execute or load** on a page — restricting where scripts, styles, images, frames, and other resources can come from. It is a **browser-enforced allowlist**, not a server-side filter — the browser itself refuses to execute/load anything that violates the policy, regardless of what HTML actually reached it.

This is why CSP is described as a **defense-in-depth / last line of defense** mechanism rather than a primary XSS fix: it doesn't prevent the injection from happening, it tries to prevent the **injected script from running** even if the injection succeeds.

## Why CSP Bypass Is Its Own Topic (Not Just "Filter Bypass")

General filter/WAF bypass (file 07) is about getting a payload **past server-side input validation or encoding** so it lands in the HTML at all. CSP bypass is a **completely separate, later-stage problem**: assume your payload *already* landed perfectly in the HTML, unencoded, in the exact right context — CSP can still block it from executing because the browser checks the policy before running any script, regardless of how it got there. You can have a textbook-perfect injection point and still fail to get code execution purely because of policy.

## Reading a CSP Header — What Actually Matters for Bypass

Example header:
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'; base-uri 'self';
```
Breakdown of the directives most relevant to XSS bypass:
- `default-src 'self'` — fallback for any directive not explicitly specified; restricts to the page's own origin.
- `script-src 'self' https://cdn.example.com` — **this is the one that matters most for XSS.** It says scripts may only load from the page's own origin or from `cdn.example.com`. Inline `<script>` blocks and inline event handlers (`onerror=...`) are **blocked by default** under any `script-src` directive unless `'unsafe-inline'` is also present.
- `object-src 'none'` — blocks `<object>`/`<embed>`/`<applet>`, closing off a historically common bypass route (Flash-based and plugin-based attacks).
- `base-uri 'self'` — restricts what `<base href="...">` can be set to; matters because `<base>` injection can otherwise be used to hijack relative script/resource URLs on the page even without directly violating `script-src`.

**Bypass triage order:** always check `script-src` first (if absent, `default-src` governs scripts; if neither restricts scripts at all, there may be no real protection regardless of how strict other directives look), then check for `'unsafe-inline'`, `'unsafe-eval'`, overly broad host/wildcard entries, and `nonce-`/`hash-` based exceptions.

## Bypass Technique 1 — `'unsafe-inline'` Present

If the policy includes `script-src 'self' 'unsafe-inline'`, inline scripts and inline event handlers execute normally — **CSP is providing essentially no XSS protection** in this configuration. This is far more common in real-world deployments than it should be, often added by developers to "make CSP stop breaking the site" without understanding it neutralizes the XSS-mitigation purpose entirely. Standard payloads from files 02-04 apply directly with no CSP-specific adjustment needed.

## Bypass Technique 2 — Overly Broad Host Allowlist (JSONP / Open Redirect on an Allowed Host)

If `script-src` allows a third-party host (e.g. `https://*.googleapis.com` or a specific CDN), and that host happens to serve a **JSONP endpoint** (a script-returning endpoint that wraps a JSON response in a caller-specified function name) or hosts an **open redirect**, you can smuggle execution through the trusted host:
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)"></script>
```
Breakdown:
- `script-src` allowed `accounts.google.com` (or whichever allowlisted domain has a similar callback-style endpoint), so the browser permits loading a `<script>` from that exact origin without question — CSP only checks the **origin** of the script source, never the content.
- The legitimate endpoint at that URL accepts a `callback` query parameter and wraps its JSON response as `alert(document.domain)({...the actual JSON...})` — i.e. it executes whatever function name you supply as if it were calling it with the response data.
- Since `alert` is a real global function, `alert(document.domain)({...})` is valid JS: it calls `alert(document.domain)` (your actual payload), and the function call's return value — `undefined`, since `alert()` returns nothing — is then itself nonsensically "called" with the JSON data as an argument, which throws a harmless `TypeError` *after* your payload has already run. The error is irrelevant; execution already happened.
- This is why CSP guidance strongly recommends **never allowlisting entire third-party domains broadly** — any JSONP endpoint, open redirect, or attacker-controllable upload feature (e.g. a CDN that lets you host arbitrary files, like some `*.azurewebsites.net` or `*.s3.amazonaws.com` wildcard allowlists) anywhere on that allowlisted origin becomes a CSP bypass.

## Bypass Technique 3 — `'unsafe-eval'` Present + AngularJS Sandbox Escape

Older AngularJS applications (Angular 1.x, **not** modern Angular 2+) evaluate double-curly-brace expressions (`{{...}}`) client-side as JS-like expressions inside any element with the `ng-app` attribute. If the page both loads AngularJS and has `'unsafe-eval'` in `script-src` (often required for AngularJS's own internal templating to function), an attacker who can inject **plain HTML text** (no `<script>`, no event handlers needed — just an Angular template expression) can achieve full JS execution that legitimately uses the page's own already-trusted AngularJS script:
```html
{{constructor.constructor('alert(document.domain)')()}}
```
Breakdown:
- This is plain text content, not a `<script>` tag or an `on*` attribute — so a CSP that only blocks inline scripts/handlers doesn't even register this as a script-execution attempt; AngularJS's own already-allowlisted JS is what evaluates it.
- `constructor.constructor(...)` — in JavaScript, every function object has a `.constructor` property pointing to the `Function` constructor. Calling `Function('alert(document.domain)')` dynamically creates a **new function** whose body is the string `alert(document.domain)`, functionally identical to `eval()`.
- The trailing `()` immediately **invokes** that freshly constructed function, running your payload.
- AngularJS sandboxes (in versions that had one) were specifically designed to block direct calls to `Function`/`eval`-like constructs inside `{{}}` expressions, leading to a long, well-documented cat-and-mouse history of increasingly obscure sandbox-escape one-liners — this exact technique area is why AngularJS-specific CSP bypass research became its own niche within XSS research.
- This technique requires `'unsafe-eval'` specifically because dynamically constructing and calling a `Function` from a string is exactly the category of dynamic-code-execution CSP's `'unsafe-eval'` flag governs.

## Bypass Technique 4 — Missing `object-src` / `base-uri` → Dangling Markup / Base-Tag Hijack

If `base-uri` is **not** restricted (no `base-uri 'self'` or `base-uri 'none'` directive present, and it doesn't fall back to a restrictive `default-src` either), injecting a `<base>` tag — even with **no script execution at all** — can rewrite how all *relative* URLs on the page resolve:
```html
<base href="https://attacker.com/">
```
Breakdown:
- `<base href="...">` sets the base URL that the browser uses to resolve every relative URL (`<script src="app.js">`, `<link href="style.css">`, relative form `action`s, etc.) elsewhere on the page.
- If the legitimate page later loads `<script src="js/app.js">` (a relative path) and you've injected a `<base>` tag earlier in the document, that legitimate-looking relative script reference now actually resolves to `https://attacker.com/js/app.js` — letting you serve **your own JavaScript** under a path the page's own markup unwittingly requests, with no CSP violation at all if `script-src` still only checks origins like `'self'` (and the attacker's malicious payload is now technically being requested as if it were a same-relative-path resource the page intended to load — though note this still typically requires the actual `script-src` policy to allow whatever resulting absolute origin you redirect it to, so this is most powerful combined with a permissive `script-src` or chained with technique 2/5).
- The more universally effective use of an unrestricted `base-uri` (regardless of `script-src` strictness) is the **dangling markup data-exfiltration** technique described in file 09 — it doesn't need script execution permission at all, since it abuses how the browser resolves resource URLs, not how it runs scripts.

## Bypass Technique 5 — Nonce/Hash Reuse or Leakage

Strict modern CSP often uses a per-response **nonce**:
```
Content-Security-Policy: script-src 'nonce-r4nd0mBase64Value';
```
Only `<script nonce="r4nd0mBase64Value">` tags matching that exact, per-response-unique value are allowed to execute. Bypass routes:
- **Nonce reflected/leaked elsewhere in the page** (e.g. visible in an HTML comment, a separate non-script tag, or a debug endpoint) — if you can read the nonce value from the response itself (it's not secret by cryptographic design — it's a one-time value meant to differ from any value an *external* attacker could predict, but if your injection point is *in the same response* that contains the real nonce, you can simply copy it).
- **Static/reused nonce across responses** (a server misconfiguration where the "nonce" is actually a hardcoded string, not regenerated per response) — defeats the entire point of nonces; test this by requesting the page twice and comparing nonce values.

## Practical CSP Bypass Testing Workflow

1. Capture the full `Content-Security-Policy` header text — note every directive present.
2. Check `script-src` (or `default-src` fallback) specifically: is `'unsafe-inline'` present? `'unsafe-eval'`? Any wildcarded or broad third-party hosts?
3. For any allowlisted third-party host, research (or test directly) whether it serves JSONP-style callback endpoints or hosts user-uploadable content / open redirects.
4. Check if the application loads any known-vulnerable client-side framework (older AngularJS, certain older jQuery/Angular combos) that creates sandbox-escape opportunities under `'unsafe-eval'`.
5. Check `base-uri` and `object-src` — if either is missing entirely (and not covered by a restrictive `default-src`), consider markup-injection-only techniques that don't need script-execution permission at all.
6. If a nonce/hash scheme is used, check whether the nonce value is exposed anywhere else accessible to your injection point, and whether it's actually regenerated per response.
7. If none of the above apply, the CSP may be genuinely effective — state this explicitly and accurately in the report rather than forcing a bypass narrative; a well-configured CSP blocking exploitation is a legitimate, reportable positive control, and the underlying injection should still be reported as a finding (lower severity, noting CSP as a mitigating control) since CSP could be removed or misconfigured later.

## PortSwigger Lab Mapping (CSP)

| Order | Lab | What it teaches |
|---|---|---|
| 1 | Reflected XSS protected by CSP, with CSP bypass | Allowlisted-host JSONP-style bypass (Technique 2) |
| 2 | Reflected XSS protected by very strict CSP, with CSP bypass | Forces dangling-markup-style or nonce-related bypass reasoning under a near-total lockdown policy (Technique 4/5 territory) |
| 3 | Reflected XSS with AngularJS sandbox escape and CSP | Combines AngularJS sandbox escape with `'unsafe-eval'`-permitting CSP (Technique 3) |

> Verify exact current lab titles/order at `portswigger.net/web-security/cross-site-scripting/content-security-policy`.

## Real-World Engagement Notes

- **The single most common real-world CSP weakness is `'unsafe-inline'` left in `script-src`**, almost always added during initial CSP rollout to avoid breaking legacy inline `onclick`-style code, and never removed afterward. Always check for this first — it's the highest-frequency finding in this category by far.
- **Broad allowlists like `script-src https://*.googleapis.com` or `https://*.amazonaws.com`** are extremely common in real applications using major cloud/analytics providers, and are a realistic, frequently-reportable bypass vector — always specifically research whether the allowlisted domain hosts any JSONP/callback/user-content endpoint before declaring CSP "effective."
- **CSP reporting mode (`Content-Security-Policy-Report-Only`)** provides **zero actual enforcement** — it only logs violations to a reporting endpoint without blocking anything. Always check whether the header is `Content-Security-Policy` (enforcing) vs. `Content-Security-Policy-Report-Only` (logging only, fully bypassable by definition) before assuming any protection exists at all.

## Common Mistakes

- Assuming CSP presence automatically means "this XSS isn't exploitable" without actually parsing the directive contents.
- Forgetting to check `Report-Only` mode, leading to incorrectly downgrading severity for a header that provides no real enforcement.
- Attempting AngularJS-style sandbox-escape payloads against modern Angular (2+) applications, which use a fundamentally different, non-expression-evaluating architecture — confirm the actual framework/version in use before reaching for legacy techniques.

## Report-Writing Notes

- Quote the **exact CSP header value** in the report and annotate which specific directive/value enabled the bypass.
- If CSP **did** successfully block exploitation, say so explicitly and credit it as a working mitigating control while still reporting the underlying injection point at appropriately adjusted (typically lower) severity.
- For nonce-leakage findings, explain precisely **where** the nonce value was exposed, since the fix is usually a specific, narrow code change (stop reflecting the nonce in that one location) rather than a CSP redesign.

---
**Next:** `07_Filter_WAF_Bypass_Encoding.md`
