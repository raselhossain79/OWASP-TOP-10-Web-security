# 03 — Cross-Origin postMessage Vulnerabilities

## Mechanism: `postMessage()` Has No Built-In Trust Boundary

`window.postMessage()` is the browser's sanctioned API for cross-origin communication
between windows — for example, a parent page and an iframe it embeds from a different
domain. This is deliberate: the Same-Origin Policy normally prevents two different-origin
windows from touching each other's DOM or JavaScript state directly, and `postMessage`
exists specifically as the controlled, intentional exception.

The critical design fact: **`postMessage` does not enforce origin checking on the
receiving end automatically.** The API signature is:

```js
otherWindow.postMessage(message, targetOrigin, [transfer]);
```

- `message` — the data being sent, which can be a string or a structured-cloneable object.
- `targetOrigin` — restricts *outbound delivery*: the browser will only deliver the
  message if the target window's current origin matches this value (or `*` for "deliver
  regardless of the target's origin").
- This parameter only protects the **sender's** intent. It does nothing to restrict who is
  allowed to **send** messages to the receiver. Any window, on any origin, holding a
  reference to the target window (e.g., via an attacker-controlled iframe) can call
  `targetWindow.postMessage(payload, '*')` and have it received.

On the receiving side, the application registers a listener:

```js
window.addEventListener('message', function(e) {
  // handle e.data
});
```

The event object `e` exposes `e.origin` (the sender's origin), `e.data` (the message
payload), and `e.source` (a reference back to the sender's window) — but the browser does
**not** filter incoming messages by origin automatically. If the handler does not
explicitly check `e.origin` before trusting `e.data`, **any** page on the internet can
send it a message, simply by opening the target in an iframe and calling
`postMessage()` against it.

## Exploitation Pattern 1: No Origin Check at All

```js
window.addEventListener('message', function(e) {
  document.getElementById('ads').innerHTML = e.data;
});
```

- The handler never references `e.origin` anywhere — there is no validation step.
- `e.data` flows directly into `innerHTML`, a classic DOM XSS sink: any HTML/script
  content assigned here is parsed and rendered/executed by the browser.

Attack page hosted by the attacker:

```html
<iframe src="https://target.com/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"></iframe>
```

Piece by piece:

- `<iframe src="https://target.com/">` — loads the real target site in a hidden/visible
  iframe under the attacker's control. This gives the attacker page a JS reference to the
  target's `window` via `iframe.contentWindow`.
- `onload="..."` — waits until the iframe has finished loading the target page (so its
  message listener is already registered) before sending anything.
- `this.contentWindow.postMessage('<img src=1 onerror=print()>', '*')` — sends a string
  payload to the target window. The `'*'` targetOrigin means "deliver this regardless of
  what origin the target window currently has" — irrelevant here since the attacker
  already knows the target's origin, but it illustrates that the sender controls this, not
  the receiver.
- `<img src=1 onerror=print()>` — the payload itself: an `<img>` tag with a deliberately
  invalid `src` (`1` is not a valid image URL), guaranteeing the `onerror` handler fires,
  which calls `print()` (used in Academy labs as a safe, observable stand-in for
  `alert(document.cookie)` in a real attack).
- When the target's listener assigns this string to `innerHTML`, the browser parses it as
  HTML, the `<img>` fails to load, and `onerror` fires — script execution achieved with
  zero need to ever directly visit the malicious page; the victim just needs to have the
  attacker's page open (e.g., via a phishing link, malvertising, or an open redirect).

## Exploitation Pattern 2: JSON-Structured Messages with an Unsafe Sink

Real applications more often pass structured messages, parsed with `JSON.parse()`:

```js
window.addEventListener('message', function(e) {
  var data = JSON.parse(e.data);
  switch (data.type) {
    case 'load-channel':
      ACMEplayer.element.src = data.url;
      break;
  }
});
```

- `JSON.parse(e.data)` — converts the incoming string into a structured object. No origin
  check is performed before or after this parse.
- The `switch` dispatches based on an attacker-controlled `type` field.
- `ACMEplayer.element.src = data.url` — the sink. Setting `.src` on an iframe element to a
  `javascript:` URI causes the browser to execute that URI's code in the context of the
  page when the iframe navigates to it.

Attack payload:

```html
<iframe src="https://target.com/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

- The JSON string sent sets `type` to `"load-channel"` (matching the expected switch case)
  and `url` to `"javascript:print()"`.
- Because the second argument to `postMessage` (`targetOrigin`) is `"*"` and the receiving
  handler never checks `e.origin`, the message is accepted unconditionally, parsed, and
  its `url` is assigned straight to the iframe's `src` — executing the embedded JavaScript
  URI.

## Exploitation Pattern 3: Flawed Origin Validation, Not Missing Validation

Some applications *do* attempt origin checks, but implement them incorrectly. Two
documented flawed patterns:

**Substring check instead of exact match:**

```js
window.addEventListener('message', function(e) {
  if (e.origin.indexOf('normal-website.com') > -1) {
    eval(e.data);
  }
});
```

- `indexOf('normal-website.com') > -1` only confirms the substring appears *somewhere* in
  the origin string — it does not confirm the origin **is** `normal-website.com`.
- An attacker hosting their malicious page at
  `http://www.normal-website.com.evil.net` has an origin that contains the substring
  `normal-website.com` (as part of the longer hostname `www.normal-website.com.evil.net`),
  passing this check while being a completely different, attacker-controlled origin.

**`indexOf` checks against message content, applied to the wrong validation target:**
A related real-world flaw seen in the "DOM XSS using web messages and a JavaScript URL"
class of bug checks whether the *message data itself* contains the string `"http:"` or
`"https:"` anywhere, intending to ensure only "real URLs" are processed — but performs no
origin check at all, and the substring search can be satisfied by including the required
text anywhere, including inside a comment appended after the real payload:

```
javascript:print()//http:
```

- `javascript:print()` — the actual payload, assigned to a `location.href`-style sink.
- `//http:` — a JavaScript line comment containing the substring `http:`, included purely
  to satisfy the flawed `indexOf` check; it has no effect on the executed code because
  everything after `//` is treated as a comment by the JavaScript engine once the
  `javascript:` URI executes.

## The Correct Defense, for Context

The Academy-recommended fix is a strict equality check against a fixed, known-good origin,
combined with avoiding dangerous sinks for message data entirely where possible:

```js
window.addEventListener('message', function(e) {
  if (e.origin !== 'https://trusted-app.com') return;
  // safe to process e.data
});
```

Strict `!==` comparison against the full expected origin string closes both the substring
bypass and the missing-check case — this is the baseline every finding in this file should
be checked against before being reported as a false positive.

## PortSwigger Web Security Academy Lab Mapping

All three labs live under the **DOM-based vulnerabilities → Controlling the web message
source** section, in Academy order:

1. **DOM XSS using web messages** (Practitioner) — no origin check at all, `innerHTML`
   sink. Maps to Exploitation Pattern 1 above.
2. **DOM XSS using web messages and a JavaScript URL** (Practitioner) — flawed
   `indexOf('http:')` content check (not an origin check), `location.href`-style sink.
   Maps to the second flawed-validation example above.
3. **DOM XSS using web messages and `JSON.parse`** (Practitioner) — JSON-structured
   messages, `targetOrigin` of `*`, no `e.origin` check, sink is an iframe `src`
   assignment. Maps to Exploitation Pattern 2 above.

> All three labs are Practitioner difficulty; there is no Apprentice-level postMessage lab
> on the Academy, consistent with this requiring an understanding of both the
> `postMessage` API contract and a downstream DOM XSS sink simultaneously.

## Real-World Notes

- postMessage vulnerabilities are a recurring bug bounty category specifically because
  developers correctly recognize they need *some* origin check, implement one, and get the
  comparison logic subtly wrong (substring match, missing protocol/port consideration,
  regex anchoring mistakes) — reviewers should never accept "we check the origin" at face
  value; always read the actual comparison logic.
- **DOM Invader** (Burp's browser extension) has dedicated postMessage interception
  tooling: it logs every message sent on a page, flags whether the handler accesses
  `e.origin`/`e.data`/`e.source` at all, and can auto-spoof origins that both start and end
  with the real domain name to specifically catch `startsWith()`/`endsWith()`-style flawed
  validation, in addition to the `indexOf` flaw shown above.
- This class chains naturally into Prototype Pollution (file `01`): the Academy explicitly
  notes web messages as a legitimate prototype-pollution **source**, since `JSON.parse()`
  on message data has the same `__proto__`-as-real-key behavior covered in that file.
