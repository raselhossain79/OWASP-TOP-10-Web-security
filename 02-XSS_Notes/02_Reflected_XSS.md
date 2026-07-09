# 02 — Reflected XSS

## Definition Recap

Reflected XSS = payload arrives in the **current HTTP request** (URL query string, POST body, header) and is echoed back **in the same response**, unencoded, with no storage step. PortSwigger's own definition: it arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.

## Why It's the "Entry Drug" of XSS Testing

It's the easiest type to find because cause and effect are in the same HTTP transaction — send a request, read the response, no need to track persistence across requests or trace client-side JS. This is exactly why PortSwigger sequences their labs to start here: you learn **context identification** and **payload construction** before adding the complexity of persistence (Stored) or client-side data flow (DOM).

## Step-by-Step Methodology

1. Identify every parameter/header that gets echoed anywhere in the response (search box `q`, error messages, "did you mean", redirect `returnUrl`, `User-Agent` shown in an admin panel, etc.).
2. Send a unique marker (e.g., `zzXSS12345zz`) in that parameter and grep the raw response for it — this tells you the **exact byte-level context** it lands in.
3. Submit raw special characters one at a time (`<`, `>`, `"`, `'`, `` ` ``, `/`) and check each one individually in the response: passed through unchanged, HTML-entity-encoded (`&lt;`), stripped, or substituted.
4. Based on context + which characters survive, build the minimal context-correct payload (see file `01` for context mechanics).
5. Confirm execution in an actual browser (not just by reading raw HTTP text) — render the response or use Burp's built-in browser.

## Worked Example — HTML Body Context (No Encoding)

Request:
```
GET /search?q=zzXSS12345zz HTTP/1.1
```
Response shows: `<h1>0 results for zzXSS12345zz</h1>` — input lands as plain text between tags, and `<` survives unencoded when you test it.

Payload:
```
<script>alert(document.domain)</script>
```
Breakdown:
- `<script>` — opens a new parsing mode; the browser's HTML parser stops treating subsequent characters as text and hands them to the JS engine instead.
- `alert(document.domain)` — calls the built-in `alert()` function with the current page's domain as the argument. Using `document.domain` instead of a literal string (`alert(1)`/`alert("xss")`) is the professional convention because it **proves the script is executing in the vulnerable application's actual origin**, not in some sandboxed iframe, cached copy, or unrelated frame — a real concern in multi-frame applications where a payload could fire harmlessly in the wrong origin and give a false positive.
- `</script>` — closes the script block so the parser correctly resumes normal HTML parsing afterward; without it, some browsers/parsers may still execute the payload but the rest of the page can render incorrectly, which is worth avoiding for a clean PoC screenshot.

## Worked Example — HTML Attribute Context

Suppose the search term is reflected as a sticky form value:
```html
<input type="text" name="q" value="zzXSS12345zz">
```
Testing single characters shows `<` and `>` are HTML-encoded, but `"` is **not** encoded.

Payload:
```
" autofocus onfocus=alert(document.domain) x="
```
Breakdown (full mechanism explained in file `01`, repeated briefly here for context):
- `"` closes the `value="..."` attribute early.
- `autofocus` forces the browser to focus this `<input>` immediately on page load — no click needed.
- `onfocus=alert(document.domain)` runs when focus fires (triggered by `autofocus`).
- `x="` opens a dummy attribute to absorb the template's own trailing `"` so the HTML stays well-formed.

**Why not just inject `<script>` here?** Because `<` and `>` are encoded — you cannot create a *new tag*, only manipulate the *existing* tag's attributes. This is the core lesson reflected-XSS testing teaches: **always test what's actually filtered before picking a payload family.**

## Worked Example — JavaScript String Context

Response includes:
```html
<script>
  var searchTerm = "zzXSS12345zz";
  document.getElementById('msg').innerText = "You searched for: " + searchTerm;
</script>
```
Testing shows `<` and `>` are HTML-encoded (irrelevant here since we're not trying to inject tags), but `"` survives unencoded inside the JS string.

Payload:
```
";alert(document.domain);//
```
Breakdown:
- `"` — closes the JS string literal that was holding your input (`var searchTerm = "..."`).
- `;` — terminates the now-truncated statement cleanly.
- `alert(document.domain);` — your injected statement, executed as real JS by the parser since you're inside an actual `<script>` block already (no need to open a new tag).
- `//` — a JS line comment that swallows everything the server template appends after your input on that line (the closing `";` of the original `var searchTerm = "...";`), preventing a `SyntaxError` that could otherwise abort script execution before your `alert()` runs in some engines/orderings.

If single quotes are used instead of double quotes server-side (`var searchTerm = 'INPUT';`), use `'` to close instead of `"` — always match the exact quote character used in the actual rendered source, not assumptions.

## Worked Example — URL Context (`href` attribute, scheme injection)

```html
<a href="zzXSS12345zz">Visit profile</a>
```
If you can't break out of the attribute (quotes encoded) but you fully control the URL value:
```
javascript:alert(document.domain)
```
Breakdown:
- The browser treats `javascript:` as a pseudo-protocol. When the link is **clicked** (a real user navigation event — this does not fire on page load), the browser evaluates everything after the colon as a JavaScript expression instead of navigating to a network resource.
- This only works in **navigation contexts** (`href`, `formaction`) — not in `src` of `<img>`/`<script>`, which are resource-fetch contexts that fetch and parse a response body, not evaluate a JS expression.
- Real-world caveat: this requires victim interaction (a click), which lowers the practical severity/ease-of-delivery slightly compared to an auto-firing payload — note this in reports.

## Delivery Mechanics for Reflected XSS (Often Overlooked)

Since Reflected XSS requires the victim to issue the malicious request themselves, the **delivery vector matters as much as the payload**:
- **GET-based payloads**: deliverable via a plain hyperlink, shortened URL, QR code, or auto-redirecting link in a phishing email — easiest to weaponize.
- **POST-based payloads**: require an auto-submitting HTML form hosted on an attacker-controlled page (`<form>` + `<script>document.forms[0].submit()</script>`) since you can't put POST data in a plain link — slightly higher delivery complexity, should be noted in severity reasoning.
- **Header-based reflection** (e.g., `User-Agent`, `Referer` reflected unsanitized into an admin log viewer): often **not directly exploitable via browser navigation** since browsers don't let arbitrary JS set `Referer`/`User-Agent` freely for cross-origin requests — usually requires chaining with another bug (open redirect, CSRF to a page that sets headers) or is only exploitable via tools that fully control headers (curl, Burp), which limits real attacker-controllable delivery. Always state this nuance in a report rather than overstating severity.

## PortSwigger Lab Mapping (Reflected XSS — Difficulty Progression)

| Order | Lab | What it teaches |
|---|---|---|
| 1 | Reflected XSS into HTML context with nothing encoded | Baseline `<script>alert(document.domain)</script>` in HTML body context |
| 2 | Reflected XSS into HTML context with most tags and attributes blocked | Tag/attribute allowlist bypass — forces using a permitted tag+event combo (e.g. `<svg onload=...>` or similar) instead of `<script>` |
| 3 | Reflected XSS into HTML context with all tags blocked except custom ones | Browsers execute event handlers on **unknown custom tags** too — teaches that filtering known tag names isn't enough |
| 4 | Reflected XSS with some SVG markup allowed | SVG-specific event vectors (`<svg onload=...>`, animate-based triggers) |
| 5 | Reflected XSS into attribute with angle brackets HTML-encoded | Forces attribute-breakout technique (section above) instead of new-tag injection |
| 6 | Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped | Forces JS-string-context techniques without quotes — uses alternative break-out (e.g. via unicode escapes or backslash neutralization) |
| 7 | Reflected XSS in canonical link tag | Injection into a `<link rel="canonical" href="...">` tag — teaches less-common attribute contexts and that `href`-based execution there needs specific browser behaviors |

> Note: PortSwigger periodically adds/renames labs. Treat this table as the well-established core progression; always cross-check current titles/order at `portswigger.net/web-security/cross-site-scripting/reflected` before an exam or structured run-through, since exact lab counts can shift.

## Real-World Engagement Notes

- In real targets, the cleanest Reflected XSS findings are usually in **search functionality, error/validation messages, and "redirect back to" parameters** — these are high-traffic, commonly-coded-quickly features.
- Modern SPA frameworks (React/Vue/Angular) drastically reduce classic HTML-body Reflected XSS because JSX/templates auto-escape by default — when you do find Reflected XSS in a modern frontend, it's most often via a server-rendered fragment (SSR), a non-framework legacy endpoint, or a `dangerouslySetInnerHTML`/`v-html` sink, which technically blurs into DOM-based XSS (file 04).
- Reflected XSS findings in **GET parameters with no CSRF-token requirement** are the most severely rated because delivery is a single clickable link — always specify this delivery ease explicitly when scoring/reporting severity.

## Common Mistakes

- Stopping after `<script>alert(1)</script>` fails and concluding "not vulnerable" without testing attribute or JS-string contexts.
- Forgetting to test the **same parameter reflected in multiple places** on one page (e.g., once in a meta tag, once in a JS variable) — different contexts on the same page may have inconsistent encoding.
- Treating Content-Type `application/json` reflections as exploitable without confirming the response is actually rendered as HTML by a browser somewhere downstream.

## Report-Writing Notes

- State the exact parameter name, HTTP method, and full vulnerable URL/request.
- State the exact context (HTML body / attribute / JS string / URL) and exactly which characters were and weren't encoded — this is what justifies the chosen payload and helps the dev team fix the right code path.
- Include a PoC URL the client can paste into a browser directly when the vector is GET-based; for POST-based, include an auto-submitting HTML PoC file as PortSwigger/Burp does (`<html><body><form action="..." method="POST">...<script>document.forms[0].submit()</script></body></html>`).

---
**Next:** `03_Stored_XSS.md`
