# 04 — DOM-Based XSS (Including Mutation XSS)

## Definition Recap

DOM-based XSS arises when **client-side JavaScript** reads attacker-controllable data from a **source** and writes it into a **sink** in an unsafe way — entirely within the browser. The server's HTTP response can be byte-for-byte identical for every request; the vulnerability lives in how the page's own JavaScript processes the DOM after the page has loaded.

This is why DOM-based XSS needs its own dedicated testing methodology: **server-side output encoding and server-side WAFs are structurally blind to it.** The malicious data never gets server-side processed as "output" in the traditional sense — it flows entirely client-side, source to sink.

## Sources (Where Attacker-Controlled Data Enters Client-Side JS)

| Source | Notes |
|---|---|
| `location.hash` / `location.search` / `location.pathname` / `location.href` | URL-derived; classic for Reflected-style DOM XSS delivered via a crafted link |
| `document.referrer` | Set by the linking page; attacker controls it by hosting the link themselves |
| `document.cookie` | If the app reads its own cookies into the DOM (rare but real, e.g. a "saved preference" cookie reflected into a welcome message) |
| `window.name` | Persists across navigations within the same tab — usable for cross-page chains |
| `postMessage` event data | Cross-origin messaging; if the receiving page doesn't validate `event.origin`, any page can send malicious data |
| `localStorage` / `sessionStorage` | If populated by another vulnerable flow (e.g. stored XSS write into storage, later read unsafely) |

## Sinks (Where That Data Becomes Dangerous)

### HTML sinks (parsed as markup)
- `element.innerHTML`, `element.outerHTML`
- `document.write()`, `document.writeln()`
- `jQuery.html()`, `$(selector).append()/.prepend()` with raw strings

### JavaScript execution sinks (parsed/run as code)
- `eval()`
- `setTimeout(string, ms)` / `setInterval(string, ms)` — when passed a **string** (not a function reference), the string is implicitly `eval`'d
- `new Function(string)`
- `element.setAttribute('onclick', userInput)` (and similar dynamic event-handler assignment)
- `location = userInput` / `location.href = userInput` / `window.open(userInput)` when the value can be a `javascript:` URL

### Worked Example — `document.write` Sink with `location.search` Source

Client-side JS on the page:
```javascript
function trackSearch(query) {
  document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) { trackSearch(query); }
```
The `search` URL parameter flows directly into `document.write()` with simple string concatenation — no encoding.

Attack URL parameter value:
```
"><script>alert(document.domain)</script>
```
Breakdown:
- `"` closes the `src="..."` attribute that the template was building (`src="/resources/images/tracker.gif?searchTerms=` + your input).
- `>` closes the now-truncated `<img ...>` tag itself.
- `<script>alert(document.domain)</script>` is now a fresh, independent tag injected into the document via `document.write()`, which the browser parses and executes exactly as if it were static HTML — because `document.write()` literally writes raw markup into the page's HTML stream at parse time.

This is delivered as a normal Reflected-style URL (`?search=...`), but it is classified as **DOM-based**, not Reflected, because the vulnerability is in the client-side `trackSearch()` function, not in server-rendered HTML — the server's response is unaffected by this URL parameter's value at all in this example.

### Worked Example — `innerHTML` Sink

```javascript
function doSearchQuery(query) {
  document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
doSearchQuery(query);
```
Here, `<script>` tags inserted via `innerHTML` **do not execute** — this is a real browser behavior: scripts injected through `innerHTML` are parsed into the DOM but deliberately not run, by design, to limit exactly this kind of attack. You must use a tag/attribute combination that **auto-fires an event handler** instead:
```
<img src=1 onerror=alert(document.domain)>
```
Breakdown:
- `<img src=1 ...>` — a deliberately broken image source (`1` is not a valid image path).
- `onerror=alert(document.domain)` — the browser fires the `error` event the moment it fails to load `src=1` (which is immediate and guaranteed, since `1` will never resolve to a valid image), and the `onerror` handler executes as JS.
- This combination is the standard go-to payload for any sink (`innerHTML`, etc.) where `<script>` itself is parsed-but-inert — it relies on a *different* execution trigger (an event handler firing) rather than the script-parsing mechanism.

## DOM Clobbering

A distinct technique where, instead of injecting *script*, the attacker injects **plain HTML elements with `id`/`name` attributes** that overwrite (clobber) global JavaScript variables or expected DOM properties the page's own script relies on, redirecting program logic without ever executing attacker JS directly via a sink.

Example: if vulnerable client JS does something like:
```javascript
if (window.adminUser) { /* trusted behavior */ }
```
and the attacker can inject HTML (even in a context where script tags and event handlers are fully blocked, e.g. a strict sanitizer that only strips `<script>`/`on*` attributes but allows arbitrary other tags), they can clobber `window.adminUser` with:
```html
<a id="adminUser"></a>
```
Breakdown:
- Named/`id`'d HTML elements are automatically exposed as global properties on `window` by the browser (a legacy HTML feature called "named access on the Window object").
- This single anchor tag — containing **no script, no event handler, nothing a typical filter would flag** — creates `window.adminUser` as a reference to that DOM element, which is **truthy**, satisfying `if (window.adminUser)` even though no malicious code ran.
- DOM clobbering is a logic-corruption technique, not direct code execution — but it's frequently chained into full XSS when the clobbered variable controls something like a script `src` URL or a sanitizer configuration flag.

## Mutation XSS (mXSS)

mXSS is a payload that is **safe as submitted** but becomes dangerous after the browser's HTML parser (or a sanitizer's internal parse-and-reserialize step) processes it. The classic real-world case involves sanitizers that take input, parse it into a DOM tree, and then call `.innerHTML` (or equivalent serialization) to produce "cleaned" output — and HTML parsing/serialization round-trips are **not perfectly symmetric**, so a sanitizer can output something more dangerous than what it consumed.

### Worked Mechanism Example (Conceptual — `<style>`/`<noscript>` context confusion)

A sanitizer config that considers the following input safe (no `<script>`, no `on*` attributes, no `javascript:`):
```html
<style><img src="</style><img src=x onerror=alert(document.domain)>">
```
Breakdown of why this is dangerous **after** parse/reserialize even though it looks inert as raw text:
- The sanitizer's HTML parser treats content inside `<style>` as raw CDATA-like text until it sees a **literal** `</style>` closing sequence — so to the parser, the actual style content is just `<img src="`, and parsing resumes as normal HTML the moment it hits `</style>`.
- That means the rest of the string — `<img src=x onerror=alert(document.domain)>">` — is parsed as **real HTML elements**, not as harmless text inside the style block, because the `</style>` appeared earlier than a naive "this whole blob is inert CSS text" assumption would expect.
- When the sanitizer then serializes its cleaned DOM tree back into an HTML string (to hand back to the application, or directly into `innerHTML`), the resulting markup contains a genuine `<img onerror=...>` element — introduced by the parser's own (correct, per-spec) handling of `<style>` content boundaries, not by anything the sanitizer's filter logic explicitly allowed.
- This is why mXSS is described as a parser-confusion bug, not a filter-keyword-bypass bug: the sanitizer's blocklist/allowlist logic for tags and attributes is working exactly as configured — the bug is in the *assumption* that "parse, inspect, and reserialize" preserves meaning, when HTML's parsing grammar makes that assumption false in specific tag-boundary edge cases.

### Real-World mXSS Notes
- mXSS gained major industry attention through real bypasses of widely-used sanitizers (notably historical DOMPurify and Closure Sanitizer versions) — it is rarely something you "guess" manually; it's usually found by fuzzing a specific sanitizer/browser combination or by tracking published research/CVEs for the exact sanitizer library version in use.
- **Practical testing approach:** identify exactly which sanitization library and version the target uses (check JS bundle source maps, `package.json` if exposed, or library-specific marker strings/comments), then check for known mXSS bypasses against that specific version rather than attempting to discover a novel one from scratch in a time-boxed engagement.

## DOM XSS via `postMessage` (Web Messaging)

```javascript
window.addEventListener('message', function(event) {
  document.getElementById('output').innerHTML = event.data;
});
```
If there's no `event.origin` check, **any** page (including an attacker-hosted one, loaded e.g. in an iframe or popup the victim is lured to) can send:
```javascript
targetWindow.postMessage('<img src=x onerror=alert(document.domain)>', '*');
```
Breakdown:
- `targetWindow` is a reference to the vulnerable page's window object, typically obtained by the attacker's page opening it via `window.open()` or embedding it in an `<iframe>`.
- `postMessage(data, '*')` sends `data` to `targetWindow` regardless of its origin (the `'*'` on the *sender* side just means "I don't care what origin the recipient is" — the real missing check is on the **receiving** side, which never validates `event.origin` before trusting `event.data`).
- The vulnerable listener then takes that attacker-supplied string and pipes it straight into `innerHTML`, triggering execution via the same `onerror` mechanism described above.
- **The fix is always on the receiving side** — validate `event.origin` against an explicit allowlist before trusting `event.data` at all. This is worth stating explicitly in reports since it's a very common omission.

## How to Actually Find DOM XSS (Practical Workflow)

1. **Use a marker string in every plausible source** (`location.hash`, `location.search`, etc.) and use browser DevTools to search the live DOM for where it lands — this finds simple URL-driven cases quickly.
2. **For sinks not reachable via simple URL sources** (e.g. `postMessage`, `localStorage`, non-HTML sinks like `setTimeout`), there's genuinely no substitute for **reading the JavaScript source** — search bundled/minified JS for the sink function names listed above, then trace backward to see what feeds them.
3. **Burp Suite's DOM Invader** (built into Burp's embedded browser) automates source-to-sink tracing by instrumenting sinks at runtime and showing you exactly which controllable source reaches which sink — use it as a first pass before manual code reading on large JS bundles.
4. **Check third-party libraries**, not just first-party code — older jQuery versions had documented DOM XSS sink behavior in `$(selector)` when passed attacker-controlled strings starting with `#` due to selector-vs-HTML-fragment ambiguity, and older AngularJS had its own expression-sandbox class of issues (briefly covered in file `06` since AngularJS sandbox escapes intersect heavily with CSP bypass history).

## PortSwigger Lab Mapping (DOM-Based XSS — Difficulty Progression)

| Order | Lab | What it teaches |
|---|---|---|
| 1 | DOM XSS in `document.write` sink using source `location.search` | Baseline source→sink trace via `document.write`, attribute breakout |
| 2 | DOM XSS in `innerHTML` sink using source `location.search` | `innerHTML` sink requires event-handler payload (`<script>` inert here) |
| 3 | DOM XSS in jQuery anchor `href` attribute sink using `location.search` source | Library-specific sink (`$(...).attr('href', ...)`-style pattern), `javascript:` scheme delivery |
| 4 | DOM XSS in jQuery selector sink using a `hashchange` event | jQuery's `$(location.hash)` selector-as-HTML-fragment ambiguity |
| 5 | DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded | Client-side template injection foundations (expanded fully alongside CSP bypass crossover in file 06) |
| 6 | Reflected DOM XSS | Burp DOM Invader / source-sink tracing without an obvious textbook sink name |
| 7 | Stored DOM XSS | Combines persistence (file 03 concepts) with a client-side sink — data is stored, then unsafely read into a DOM sink on a later page view |
| 8 | DOM XSS using web messages | Basic `postMessage` with no origin check, `innerHTML` sink |
| 9 | DOM XSS using web messages and a JavaScript URL | `postMessage` data flows into a navigation sink (`location = data`), enabling `javascript:` scheme delivery |
| 10 | DOM XSS using web messages and `JSON.parse` | Data passed through `JSON.parse` before reaching a sink — teaches that intermediate processing doesn't guarantee safety if the *parsed* value still reaches a dangerous sink unescaped |

> Lab titles/order should be cross-checked at `portswigger.net/web-security/cross-site-scripting/dom-based` — this topic in particular has grown over time as PortSwigger adds new sink/source combinations.

## Real-World Engagement Notes

- DOM-based XSS is the fastest-growing class in real bug bounty programs precisely because SPA frameworks reduced classic server-rendered XSS — but every framework still has an escape hatch (`dangerouslySetInnerHTML` in React, `v-html` in Vue, `[innerHTML]`/`bypassSecurityTrustHtml` in Angular), and developers reach for them constantly for "rich text" features.
- Source maps left enabled in production (`.map` files accessible) make finding DOM XSS dramatically easier — always check for them before resorting to reading minified bundles directly.
- `postMessage` origin-check omissions are extremely common in real third-party widget integrations (chat widgets, payment iframes, SSO popups) — this is a high-value, fast thing to check on almost any modern target.

## Common Mistakes

- Treating "no reflection visible in page source" as "not vulnerable to XSS" — DOM XSS often has **zero** visible difference in server-rendered HTML; you must inspect the live, post-JS-execution DOM.
- Using `view-source:` (raw HTTP response) instead of DevTools' **Elements** panel (live DOM) when hunting for DOM XSS — these can differ enormously after JS execution.
- Assuming a sink is safe because the value "looks like" it went through `JSON.parse` or another transform — always trace whether the *output* of that transform still reaches an unsafe sink.

## Report-Writing Notes

- Cite the **exact source and sink** (e.g. "source: `location.hash`; sink: `element.innerHTML` in `app.bundle.js` line 4821") — this is the single most useful piece of information for a developer fixing a DOM XSS finding, since the bug is purely in client-side code they need to locate precisely.
- For `postMessage` issues, explicitly state that the receiving page performs **no `event.origin` validation**, since that's almost always the actual one-line fix needed.
- Note browser-version dependence if relevant (e.g. an mXSS bypass tied to a specific sanitizer library version) — remediation may simply be "upgrade dependency X to version Y," which is valuable, actionable guidance.

---
**Next:** `05_Blind_XSS.md`
