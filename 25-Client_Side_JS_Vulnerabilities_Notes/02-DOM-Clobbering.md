# 02 — DOM Clobbering

## Mechanism: Named-Access on the Global `window` and `document` Objects

Browsers implement a legacy feature called **named access on the `window` object**: any
HTML element with an `id` or `name` attribute is automatically exposed as a global
JavaScript variable with that name, *if no script-defined global of that name already
exists*. This was originally designed so old-style HTML forms could be referenced from
script without explicit DOM queries (`document.formname.fieldname`).

DOM Clobbering weaponizes this: if you can inject HTML (even when you **cannot** inject
or execute `<script>` — e.g., the site has a strict Content-Security-Policy, or the HTML
sanitizer strips script tags but allows benign-looking elements), you can still overwrite
a global variable the application's *legitimate* JavaScript relies on, simply by
controlling `id`/`name` attributes.

This makes DOM Clobbering distinct from every other entry in this series: it requires
**zero JavaScript execution** to plant the attack. The vulnerability is entirely in how
the application's own script reads global state it assumed only it could set.

### The Vulnerable Code Pattern

```js
var someObject = window.someObject || {};
```

This is an extremely common defensive-looking pattern — "use `someObject` if it's already
defined, otherwise default to an empty object." Piece by piece, why it's dangerous:

- `window.someObject` — reads a property off the global `window` object.
- If an attacker has injected an HTML element with `id="someObject"` (or `name=`)
  anywhere in the page, named access means `window.someObject` now resolves to **that DOM
  element**, not `undefined`.
- `|| {}` — only falls back to an empty object if the left side is falsy. A DOM element is
  not falsy, so the `||` never triggers — `someObject` is now the attacker's injected
  element.
- Later code that reads properties off `someObject` (expecting plain-object properties)
  instead reads **attributes of the injected element**, which the attacker fully controls.

### Basic Single-Level Clobbering

```html
<a id="someObject" href="javascript:alert(1)">click</a>
```

- `<a id="someObject" ...>` — an anchor tag. Because no script-defined `someObject` global
  already exists, `window.someObject` now resolves to this anchor element.
- If the application's code later does something like `location.href = someObject.href`
  or treats `someObject` as a URL string, the attacker controls that value entirely via
  the `href` attribute — no `javascript:` execution needed if the sink is something like a
  dynamically generated `<script src>`.

### Multi-Property Clobbering via the Two-Anchor Pattern

The single-anchor trick above only clobbers a single value (the element itself, which
JS code might coerce to a string). To clobber a *nested* property — i.e., make
`someObject.someProperty` resolve to an attacker-controlled string — you need two anchors
sharing the same `id`:

```html
<a id="defaultAvatar"></a>
<a id="defaultAvatar" name="avatar" href="cid:&quot;onerror=alert(1)//">
```

Piece by piece:

- Two elements with the **same `id`** are grouped by the browser into an `HTMLCollection`
  when accessed via that id — so `window.defaultAvatar` is no longer a single element, but
  a collection of both anchors.
- The **second** anchor additionally has `name="avatar"`. Within an `HTMLCollection`,
  named-access also applies internally: accessing `.avatar` on the collection resolves to
  whichever member element has `name="avatar"` — in this case, the second anchor itself.
- So `window.defaultAvatar.avatar` now resolves to **the second anchor element**, and when
  application code subsequently coerces that to a string (e.g., via template literal
  interpolation or `.toString()`), the browser returns the element's `href` attribute
  value as that string representation — `cid:"onerror=alert(1)//` in this example.
- `cid:` is an unusual but valid-looking URL scheme some HTML sanitizers (DOMPurify
  included, in specific configurations/versions) do not URL-encode the double quote
  character within, when used as an `href`. That undecoded `"` lets the payload break out
  of whatever attribute context the clobbered value is eventually placed into, smuggling
  `onerror=alert(1)` as a live HTML attribute rather than inert text.

This exact technique — two anchors, shared `id`, second one carrying `name` plus a
crafted `href` — is the canonical DOM Clobbering pattern referenced across PortSwigger's
own labs and research, because it's the minimum HTML needed to clobber a two-level
property path using only whitelisted `id`/`name`/`href` attributes.

### Why DOM Clobbering Is the Go-To CSP Bypass

A strict CSP (e.g., `script-src 'self' 'nonce-xyz'`) blocks inline `<script>` and
attacker-hosted external scripts. It does **not** block harmless-looking `<a>` or `<form>`
elements with `id`/`name` attributes — those aren't script, so CSP has nothing to enforce
against them. If the application's own (CSP-permitted, nonce'd) script later reads a
clobbered global and feeds it into a sink — most commonly `script.src` for a *new*,
dynamically created script element — the attacker effectively gets the application's own
legitimately-trusted script to load and execute attacker-controlled code, sidestepping CSP
entirely. This is precisely the technique documented in PortSwigger Research's "Bypassing
CSP via DOM clobbering."

### Clobbering `attributes` to Defeat HTML Sanitizer Filters

A more advanced application is the "Clobbering DOM attributes to bypass HTML filters" lab
pattern. Many client-side HTML sanitizers (e.g., older configurations of HTMLJanitor) loop
over an element's `.attributes` property to strip disallowed ones:

```js
for (let i = 0; i < element.attributes.length; i++) {
  // check/remove attribute
}
```

- If an attacker can clobber the `attributes` property itself — by injecting a child
  element with `id="attributes"` inside the element being sanitized — `element.attributes`
  no longer refers to the real `NamedNodeMap` of HTML attributes. It instead resolves to
  the clobbered child element.
- That clobbered element's `.length` is `undefined` (a plain DOM element has no `length`
  property), so the loop condition `i < element.attributes.length` is `0 < undefined`,
  which evaluates to `false` immediately. The loop body never runs.
- Result: the sanitizer silently does **nothing** for that element — every attribute,
  including ones that should have been stripped (`onclick`, `onfocus`, etc.), passes
  through untouched.

## Defenses, and Why They Matter for Detection

PortSwigger's own stated mitigation is the detection-relevant insight: code should verify
that an object is what it's expected to be (e.g., `attributes instanceof NamedNodeMap`)
rather than trusting it implicitly. The `||` global-default pattern shown at the top of
this file should specifically be avoided — when reviewing source during a real engagement,
grep for `window.X || ` and `var X = X ||` patterns as a fast way to shortlist clobbering
candidates.

## PortSwigger Web Security Academy Lab Mapping

The Academy currently maintains two dedicated DOM Clobbering labs, both Practitioner
difficulty (there is no Apprentice-level DOM Clobbering lab, reflecting that this is
already a moderately advanced technique even at its introductory level):

1. **DOM XSS exploiting DOM clobbering** (Practitioner) — exercises the two-anchor,
   shared-`id` pattern against a comment field that allows "safe" HTML, chained with the
   `cid:` quote-escaping bypass against DOMPurify covered above.
2. **Clobbering DOM attributes to bypass HTML filters** (Practitioner) — exercises the
   `attributes` property clobber against the HTMLJanitor library, chained with a delayed
   iframe-load technique to trigger the payload via a `focus` event.

> **Browser-compatibility note carried over from the Academy:** both labs note that the
> intended solutions are browser-specific (one requires Chrome, the other does not work
> reliably in Firefox), because exact named-access and `HTMLCollection` grouping behavior
> has historically had cross-browser inconsistencies. Always verify clobbering chains in
> the same browser engine the target audience actually uses.

## Real-World Notes

- DOM Clobbering has been used in real, documented research to hijack **service workers**
  — by clobbering a variable that determines the domain a service worker's
  `importScripts()` pulls from, an attacker can gain persistent, full client-side control
  over a site's responses even after the original injection point is fixed, since the
  malicious service worker keeps running independently.
- Because it requires no script execution, DOM Clobbering is a standard technique in bug
  bounty reports against applications that rely heavily on CSP as their primary XSS
  defense — reviewers should never treat "CSP is present" as equivalent to "client-side
  injection is not exploitable."
- DOM Clobbering chains particularly well with file `01` (Prototype Pollution): both
  techniques exist specifically to corrupt application state *without* needing classic
  script injection, and the same CSP-protected, gadget-hunting mindset applies to both.
