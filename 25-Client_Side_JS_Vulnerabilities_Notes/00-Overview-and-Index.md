# 00 — Overview: Client-Side JavaScript Vulnerabilities

## Why This Is One Series, Not Five Unrelated Topics

Standard XSS (reflected, stored, DOM-based) is about getting attacker-controlled markup
or script to execute. The five vulnerabilities in this series are different: each one
abuses a specific, well-defined behavior of the JavaScript engine or browser platform —
behavior that is often *not* about injecting `<script>` tags at all. They frequently show
up as the missing link that turns "I found some HTML injection but the site has a strict
CSP" or "I found a postMessage handler but it doesn't look injectable" into a full
exploit chain.

| Sub-topic | What is actually being abused | Typical end impact |
|---|---|---|
| Prototype Pollution | JavaScript's prototype-chain inheritance model | DOM XSS (client) / RCE (server, Node.js) |
| DOM Clobbering | The browser's named-access rules for `id`/`name` attributes | Overwrite JS globals to redirect logic flow, often used to **bypass CSP** |
| postMessage vulnerabilities | The fact that `window.postMessage()` has no built-in origin enforcement | Data leakage, DOM XSS, session/account takeover |
| Client-Side Storage Issues | Developers treating `localStorage`/`sessionStorage` as safe-by-default storage | Sensitive data exposure, persistent XSS via storage-based sinks |
| Cross-Site WebSocket Hijacking | WebSocket handshakes are HTTP requests that **do not enforce Same-Origin Policy** the way `fetch()`/XHR do | Unauthorized actions, session/data theft over an authenticated channel |

## The Shared Mental Model: Source → Sink → (Gadget)

All five sub-topics can be reasoned about using the same DOM-XSS-style taint model that
PortSwigger uses for its broader DOM-based vulnerabilities topic:

- **Source** — anywhere attacker-controllable data enters: a URL fragment, a JSON body, a
  `postMessage()` call, an HTML attribute an attacker can inject, a WebSocket frame.
- **Sink** — a JavaScript function or browser behavior that does something dangerous with
  that data: `eval()`, `innerHTML`, `script.src`, a server-side `merge()`/`extend()` call,
  an authenticated WebSocket action.
- **Gadget** (Prototype Pollution and DOM Clobbering specifically) — an intermediate
  property or variable that the application trusts implicitly, which the attacker can
  reach indirectly even without a "normal" injection point.

Where this series differs from the standalone XSS series already in this library: in
Prototype Pollution and DOM Clobbering, the attacker frequently never injects executable
script at all. They corrupt *data structures* or *the DOM tree itself*, and the
application's own legitimate code does the dangerous part for them. This is also why
these techniques are the standard answer to "how do I get script execution on a site
protected by a strict CSP."

## How PortSwigger Organizes These Topics

Two of the five sub-topics (Prototype Pollution, DOM Clobbering) have dedicated top-level
Academy topics with their own lab pages. The other three are distributed differently:

- **postMessage vulnerabilities** live under the **DOM-based vulnerabilities** topic, in
  the "Controlling the web message source" section.
- **Client-Side Storage Issues** are documented under **DOM-based vulnerabilities** as
  "HTML5-storage manipulation" (sources and sinks), but — disclosed honestly here — the
  Academy does **not** currently offer a dedicated interactive lab built specifically
  around localStorage/sessionStorage exploitation as a standalone challenge. File `04`
  explains how to test for this manually and references the closest related lab.
- **Cross-Site WebSocket Hijacking** lives under the **WebSockets** topic, alongside two
  general WebSocket-manipulation labs that are useful prerequisite context.

This series reorganizes all five under one "Client-Side JavaScript Vulnerabilities"
umbrella because, in real engagements, they are usually hunted together — the same recon
pass (reviewing JS source, watching `postMessage` traffic, checking storage, fuzzing JSON
bodies) tends to surface candidates for more than one of these classes at once.

## Tooling Used Across This Series

- **Burp Suite (Community/Pro)** — Proxy, Repeater, and the embedded browser.
- **DOM Invader** (Burp's built-in browser extension) — purpose-built for Prototype
  Pollution, DOM Clobbering, and web-message (postMessage) detection. It is referenced in
  every relevant file, with manual (non-DOM-Invader) techniques given equal weight so the
  underlying mechanism is never skipped.
- **Browser DevTools** — Console, Elements, and Network/WS tabs for manual verification.
- **Node.js / a local REPL** — for safely reasoning about server-side prototype pollution
  gadgets before testing live.

## What This Series Does Not Cover

- Classic reflected/stored/DOM-based XSS mechanics — covered in the dedicated XSS series.
- CSRF and general WebSocket message-tampering without an origin-validation failure —
  covered in the dedicated CSRF series and briefly referenced (not duplicated) in file `05`.
- Server-side deserialization attacks unrelated to JavaScript prototypes — covered in the
  dedicated Insecure Deserialization series.
