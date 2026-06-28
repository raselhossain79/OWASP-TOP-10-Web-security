# Web Architecture Basics

> This file covers just enough about how modern web apps are built and how the browser 
> renders/executes things to make the client-side vulnerability notes (XSS, DOM 
> Clobbering, Prototype Pollution, postMessage) make sense. This is not a web 
> development course — it's the minimum mental model needed.

---

## 1. Client-Server Model (The Basics You Already Know, Stated Precisely)

```
Browser (client) ──HTTP request──► Server
Browser (client) ◄─HTTP response── Server
```
The server can respond with:
- **Server-rendered HTML** — the full page is built server-side, browser just displays it
- **An API response (JSON)** — the browser's JavaScript then builds the visible page 
  client-side (this is the Single Page Application / SPA model — React, Vue, Angular)

**Why this distinction matters:** in server-rendered apps, a lot of vulnerabilities 
(Reflected/Stored XSS) happen because the server inserts your input directly into HTML 
it generates. In SPA/API-driven apps, the vulnerability often shifts to the client-side 
JavaScript that takes API JSON data and inserts it into the DOM unsafely (DOM-based XSS, 
exactly the category that doesn't require the server to do anything wrong at all).

## 2. The DOM (Document Object Model)

The DOM is the browser's **live, in-memory representation** of the HTML page as a tree 
of objects that JavaScript can read and modify:
```javascript
document.getElementById("output").innerHTML = userInput;   // ⚠️ classic DOM XSS sink
```
The key idea: JavaScript can change what's on the page *after* the page has already 
loaded, without a new request to the server. This is exactly the mechanism DOM-based 
XSS exploits — the vulnerable code never touches the server at all; it's pure 
client-side JavaScript reading some attacker-controlled input (URL, `location.hash`, 
`postMessage` data) and writing it into the DOM unsafely.

## 3. "Sources" and "Sinks" — The Mental Model for Client-Side Vulnerabilities

This vocabulary gets used constantly in the XSS/DOM/Prototype Pollution notes:
- **Source** — anywhere attacker-controlled data enters client-side JavaScript: 
  `location.href`, `location.hash`, `document.referrer`, `window.name`, data received 
  via `postMessage`, URL parameters read by JS
- **Sink** — anywhere that data gets used in a dangerous way: `innerHTML`, 
  `document.write()`, `eval()`, `setTimeout()` with a string argument, `element.src`

**The entire DOM-based vulnerability hunting process is: find a source, trace whether it 
reaches a sink without being sanitized in between.** This exact framing is what you'll 
use repeatedly later.

## 4. AJAX / Fetch — How Pages Update Without Reloading

```javascript
fetch('/api/user/profile')
  .then(response => response.json())
  .then(data => {
    document.getElementById('username').innerText = data.username;  // safe (innerText)
    document.getElementById('bio').innerHTML = data.bio;             // ⚠️ unsafe (innerHTML)
  });
```
This is the mechanism behind nearly all modern "dynamic" page behavior — and the exact 
mechanism that creates DOM-based XSS when the response data lands in an unsafe sink like 
`innerHTML` instead of a safe one like `innerText`/`textContent`.

## 5. REST APIs — Just Enough to Understand Later Topics

A REST API exposes resources via URLs and HTTP methods:
```
GET    /api/users/123        → retrieve user 123
PUT    /api/users/123        → replace user 123's data entirely
PATCH  /api/users/123        → partially update user 123
DELETE /api/users/123        → delete user 123
```
This predictable structure is exactly why **IDOR** (changing `123` to `124` and seeing 
someone else's data) and **Mass Assignment** (sending extra JSON fields the API didn't 
expect, like `"role":"admin"`) are such common findings on API-driven apps — the 
predictable URL/JSON structure makes both bugs easy to spot once you know to look.

## 6. Real-World Notes
- Browser DevTools → Elements tab shows you the live DOM (after JS has run), while 
  "View Page Source" shows you the original server-sent HTML — these can be very 
  different on modern SPA-style sites, and you need to test against the live DOM for 
  DOM-based vulnerabilities, not the static source.
- DevTools → Network tab, filtered to "Fetch/XHR," is where you'll see the actual API 
  calls a modern frontend makes — this is often more revealing than the visible page UI, 
  since it shows you the real backend endpoints and parameters.
- When source code isn't available (the normal case in black-box bug bounty/pentest 
  work), browser DevTools' JS files (often unminified or source-mapped) are frequently 
  your best way to find sources/sinks and hidden API endpoints.

Continue to → `07_Burp_Suite_Fundamentals.md`
