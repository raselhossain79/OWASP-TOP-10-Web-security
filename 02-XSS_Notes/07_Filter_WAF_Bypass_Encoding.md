# 07 — Filter & WAF Bypass, Encoding Evasion

## Scope of This File vs. File 06

File 06 (CSP) covers bypassing the **browser's own** execution policy after a payload has already reached the page unencoded. This file covers the **earlier** problem: getting a payload **past server-side input filtering, output encoding, or a Web Application Firewall (WAF)** so it lands in the response in an exploitable form at all. These are distinct, sequential obstacles — a payload might sail past every filter described here and still be neutered by CSP, or vice versa.

## Step Zero: Character-by-Character Probing (Always Do This First)

Before attempting any bypass, determine **exactly** what the filter does to each individual special character. Submit each one alone and observe the result:

| Character | Possible outcomes |
|---|---|
| `<` `>` | Passed through / HTML-entity-encoded (`&lt;` `&gt;`) / stripped entirely |
| `"` `'` | Passed through / HTML-entity-encoded (`&quot;` `&#x27;`) / backslash-escaped (`\"` `\'`) / stripped |
| `/` | Sometimes stripped specifically to block closing tags (`</script>`) while leaving opening tags intact |
| `(` `)` | Occasionally stripped/blocked specifically to prevent function calls in JS-context filters |
| backtick `` ` `` | Relevant for template-literal contexts; often forgotten by filters that only think about quotes |

This single step determines which bypass family below is even relevant — never skip it and jump straight to "try a famous bypass payload."

## Technique 1 — Tag/Attribute Allowlist Bypass via Unexpected Elements

When `<script>` specifically is blocked/stripped but other tags pass through, use any element that supports an **auto-firing event handler**:
```html
<svg onload=alert(document.domain)>
```
Breakdown:
- `<svg>` is a legitimate HTML5 element, frequently absent from naive blocklists that only enumerate `script`, `iframe`, `object`, `embed`.
- `onload` fires automatically the moment the SVG element finishes loading — no click, no hover, no additional trigger needed, unlike `onclick`/`onmouseover` which require interaction.
- This is the standard substitute whenever `<script>` is blocked by tag-name but the filter doesn't also strip arbitrary event-handler attributes from other tags.

Other reliable auto-firing alternatives, useful when one specific tag is specifically blocked:
```html
<body onload=alert(document.domain)>
<img src=x onerror=alert(document.domain)>
<video><source onerror=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
```
- `<img src=x onerror=...>` — covered mechanically in file 04; the deliberately invalid `src=x` guarantees the `error` event fires immediately.
- `<details open ontoggle=...>` — the `open` boolean attribute makes the element start in its expanded state, which itself fires the `toggle` event immediately on render, executing `ontoggle` with zero interaction. This one is a favorite when both `<svg>` and `<img>` end up on someone's blocklist (some filters specifically target the two most "famous" alternatives and miss less commonly used elements).

## Technique 2 — Custom/Unknown Tag Names

If a filter strips a **specific list of known tag names** but doesn't validate that injected tags are actual valid HTML elements, browsers still parse and apply attributes to entirely made-up tag names:
```html
<xss onmouseover=alert(document.domain)>hover me</xss>
```
Breakdown:
- `<xss>` is not a real HTML element, but browsers don't reject unrecognized tag names — they render them as generic inline elements and still process any standard event-handler attribute on them.
- This defeats any filter built as a hardcoded denylist of "dangerous" tag names (`script`, `iframe`, `object`, `svg`, `img`, etc.) — since the filter is checking tag *identity*, not the more fundamental fact that *any* element can carry an executing event-handler attribute.

## Technique 3 — Case Variation and Null-Byte/Whitespace Insertion (Legacy Filters)

Older, naive regex-based filters sometimes match tag names case-sensitively or expect no whitespace irregularities:
```html
<ScRiPt>alert(document.domain)</sCrIpT>
<img src=x OnErRoR=alert(document.domain)>
<img src=x on\terror=alert(document.domain)>
```
Breakdown:
- HTML tag names and attribute names are case-**insensitive** to the browser parser — `<ScRiPt>` executes identically to `<script>`. A filter using a case-sensitive string match (`indexOf('<script>')` instead of a case-insensitive regex) is trivially defeated this way.
- A literal tab character (`\t`) or other whitespace inserted mid-attribute-name in `on\terror` is tolerated by some (older/non-standard) parsing paths and by naive filters expecting an exact `onerror=` substring match, though modern standard browser parsers are generally strict about this — test directly against the target browser rather than assuming this works universally; it's included here as a known historical technique worth a quick test, not a guaranteed bypass on modern engines.

## Technique 4 — Double Encoding

If the application HTML-decodes input **once** before applying a security check, but the browser itself will decode entities again at render time, double-encoding can smuggle a payload past the check:
```
%26lt%3Bscript%26gt%3Balert(document.domain)%26lt%3B%2Fscript%26gt%3B
```
Breakdown:
- This is `&lt;script&gt;alert(document.domain)&lt;/script&gt;` (standard single HTML-entity encoding), itself then **URL-encoded** a second time (`&` → `%26`, `;` → `%3B`, etc.).
- If the server's filter/validation step only URL-decodes the request **once** before checking for dangerous substrings like `<script>`, it sees the harmless-looking entity-encoded form `&lt;script&gt;...` and lets it through — but if the value is later **HTML-decoded again** somewhere downstream (e.g. a second processing layer, or the browser's own HTML entity decoding when rendering text content that itself contains entities) the actual `<script>` tag re-emerges and executes.
- This specifically exploits **inconsistent decode-count between the security check and the final render path** — always test whether your target decodes input more times than its filter does.

## Technique 5 — Encoding Inside Already-Established Contexts (Not a "Filter Bypass" Per Se, But Often Confused With One)

Once you're already inside a JS string or HTML attribute context (no tag-injection needed), you can use **JavaScript Unicode escapes** or **HTML character references** to represent otherwise-blocked literal characters:
```javascript
\u0061lert(document.domain)
```
Breakdown:
- `\u0061` is the JavaScript Unicode escape sequence for the character `a` (hex codepoint 0x61). The JS engine decodes escape sequences **before** evaluating the resulting identifier, so `\u0061lert` is parsed as the literal function name `alert` — useful if a filter specifically string-matches the literal substring `alert` (or similar dangerous-function-name blocklist) anywhere in the input but doesn't account for Unicode-escaped equivalents.
- Similarly, HTML attribute contexts accept numeric/named character references inside `javascript:` URLs and certain attribute values: `&#97;lert(1)` decodes to `alert(1)` by the HTML parser before the browser evaluates it as a URL/script.
- This technique matters most against **keyword/substring blocklists** (filters that search literally for `alert`, `eval`, `document.cookie`, etc., rather than fully parsing what the final executed code would be) — it does nothing against `<`/`>` stripping, since it operates entirely *within* a context you've already successfully landed in.

## Technique 6 — Polyglot Payloads

A polyglot is a single payload string engineered to execute correctly across **multiple different injection contexts simultaneously**, useful when you don't know in advance exactly which context your input lands in (e.g., automated scanning, or a CMS that reuses the same field across several different render templates):
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(document.domain) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(document.domain)//>\x3e
```
Breakdown (high level — full character-by-character coverage would be excessive for any one technique, but the structural idea matters):
- The `jaVasCript:` prefix with mixed case targets `javascript:` URL-scheme contexts.
- The chain of `/*...*/` comment markers and varied quote characters (`` ` ``, `'`, `"`) are designed so that whichever quote/comment syntax the actual surrounding context uses, *some* segment of this string correctly closes out the preceding context and exposes the trailing `<svg onload=...>` segment as live markup.
- The `</stYle/</titLe/</teXtarEa/</scRipt/` sequence attempts to close out several different possible *parent* tag contexts (`<style>`, `<title>`, `<textarea>`, `<script>`) the input might have been placed inside, since each of those tags treats its content differently (raw text vs. markup) until its specific closing tag is seen.
- The trailing `<svg onload=alert(document.domain)>` is the actual payload — everything before it exists purely to maximize the chance of breaking out of *whatever* the real, unknown context turns out to be.
- **Practical note:** polyglots are best used as a **fast triage tool** (one submission to see if *anything* fires across an unfamiliar input sink) rather than as your refined, final reportable PoC — once you get a hit, go back and craft the minimal, exact-context payload for clean reporting (per file 01's methodology).

## Technique 7 — WAF-Specific Evasion Patterns

Commercial WAFs (Cloudflare, AWS WAF, Akamai, Imperva, etc.) typically detect XSS via signature/regex rules looking for common payload *shapes*. General evasion principles (test against the specific WAF in scope; none of these are universal):
- **Whitespace/comment substitution inside tags:** `<svg%09onload=alert(1)>` (tab character in place of a space) or `<svg/onload=alert(1)>` (forward slash as separator) — many WAF regexes expect a literal space between tag name and attribute and miss alternate whitespace-equivalent separators that browsers still parse correctly.
- **Concatenation/string-building to break up flagged substrings:** `eval('al'+'ert(1)')` — splits the literal substring `alert` so a signature looking for that exact string doesn't match, while the JS engine concatenates and evaluates it normally at runtime.
- **Encoding mismatches between WAF and origin server:** if the WAF inspects the raw request body but the origin server applies a different decoding step (e.g. handles a non-standard encoding, or processes multipart form data differently than the WAF's parser does), payloads can be hidden from WAF inspection while still reaching and executing on the origin — this requires recon on exactly which encodings/content-types the WAF fully parses vs. passes through unexamined.
- **IMPORTANT:** never assume a WAF bypass technique works without testing it directly against the actual in-scope target — WAF vendors update signatures constantly, and "famous" bypass strings circulating online are the first things vendors patch.

## Practical Bypass Workflow

1. Run Step Zero (single-character probing) — this alone often tells you which technique family is even relevant.
2. If `<`/`>` are blocked but you're in an attribute, you don't need a "filter bypass" at all — use the attribute-breakout technique from file 01/02.
3. If specific tag names are blocked but attributes/angle-brackets survive, try Technique 1 (alternate auto-firing tags) and Technique 2 (custom tag names) before reaching for anything exotic.
4. If a keyword/substring blocklist seems to be in play (e.g. `alert`, `script`, `onerror` specifically stripped as literal strings rather than via HTML-aware parsing), try Technique 5 (escape sequences) and Technique 7's concatenation idea.
5. Only reach for full polyglots (Technique 6) when you genuinely don't know the context yet — it's a recon tool, not a final answer.
6. If a commercial WAF is clearly in front of the app (check response headers, error pages, timing), budget separate time for WAF-specific testing (Technique 7) distinct from the application-level filter testing above — they are different layers with different bypass logic.

## Real-World Engagement Notes

- **Most real filters are denylist-based and incomplete**, not full HTML-aware sanitizers — this is exactly why Techniques 1 and 2 (alternate tags, custom tag names) succeed so often in practice; developers write `str.replace('<script>', '')` far more often than they implement a proper parser-based sanitizer.
- **WAFs in front of an application are not the same as the application's own input handling** — a payload can be blocked by the WAF (403 response, generic block page) while the application itself remains completely unfixed underneath; always note this distinction in reports, since removing/misconfiguring the WAF later would re-expose the underlying bug.
- **Encoding-mismatch bypasses are increasingly valuable against modern stacks** with multiple layers (CDN → WAF → load balancer → app server → framework auto-escaping) — each layer may decode/normalize input differently, and inconsistencies between layers are a rich, currently underexplored area in many real environments.

## Common Mistakes

- Copy-pasting a "famous" bypass payload from a cheat sheet without first doing Step Zero's character probing — wastes time on techniques irrelevant to the actual filter behavior observed.
- Confusing a WAF block page with "the vulnerability doesn't exist" — always distinguish WAF-layer blocking from application-layer fix.
- Over-engineering a polyglot for a final report PoC when a clean, minimal, context-specific payload (once context is known) communicates the finding far more clearly to a development team.

## Report-Writing Notes

- State explicitly which characters/strings were filtered and which technique defeated that specific filter — this gives the development team the precise gap in their current denylist/encoding logic, which is more useful than just "filter can be bypassed."
- If a WAF was involved, separate the finding into two explicit layers: "WAF blocks the common payload variant X, but the following technique Y bypasses the WAF, after which the underlying application has no further server-side defense and the payload executes" — this framing correctly informs both the WAF team and the application development team of their respective remediation responsibilities.

---
**Next:** `08_XSStrike_and_Dalfox.md`
