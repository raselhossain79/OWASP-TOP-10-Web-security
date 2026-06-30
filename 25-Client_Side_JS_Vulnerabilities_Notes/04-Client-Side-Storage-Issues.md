# 04 — Client-Side Storage Issues

## Honest Gap Disclosure, Stated Up Front

Unlike the other four files in this series, the PortSwigger Web Security Academy does
**not** currently provide a dedicated, standalone interactive lab built specifically
around `localStorage`/`sessionStorage` exploitation as its own challenge category. The
Academy documents `localStorage` and `sessionStorage` as recognized **sources** and
**sinks** within its broader "DOM-based vulnerabilities" taint-flow model (see the
`DOM-based HTML5-storage manipulation` reference page), but there is no lab titled
specifically around storage manipulation the way there are dedicated labs for, say,
DOM Clobbering or postMessage.

This file is written to the same mechanism-first standard as the rest of the series
regardless, and identifies the closest related lab plus manual testing methodology so the
gap doesn't leave a hole in your practice routine.

## Mechanism: Two Distinct Problem Classes Under One Heading

"Client-Side Storage Issues" in practice covers two related but separate failure modes:

1. **Sensitive data exposure** — storing data in `localStorage`/`sessionStorage` that
   should never be readable by arbitrary JavaScript running on the page.
2. **Storage as an XSS source/sink** — using stored data unsafely on either the write side
   (storage-based persistence of attacker data) or the read side (unsafely rendering data
   pulled back out of storage).

### Why `localStorage`/`sessionStorage` Are Not a Privileged, Protected Channel

Both APIs are plain, synchronous key-value stores exposed directly on `window`. Critically:

- **Any JavaScript executing on the page's origin can read or write them** — there is no
  per-script or per-library isolation. If *any* XSS exists anywhere on the page, or any
  third-party script included via `<script src>` is later compromised (supply-chain
  attack), that script has full read/write access to everything in storage for that
  origin.
- Unlike cookies, storage values are **never sent automatically with HTTP requests** — this
  is sometimes (incorrectly) treated by developers as a security feature ("it can't be
  leaked via CSRF the way cookies can"), but it does nothing to protect against the much
  more common threat of in-page JavaScript reading it directly via `localStorage.getItem()`.
- `localStorage` persists **indefinitely** until explicitly cleared (no expiry), across
  browser restarts, which extends the exposure window for anything stored there compared
  to a session-scoped cookie.

### Problem Class 1: Sensitive Data Exposure

```js
localStorage.setItem('authToken', response.token);
localStorage.setItem('userProfile', JSON.stringify(response.user));
```

- `localStorage.setItem('authToken', ...)` — stores a bearer/session token in a location
  readable by **any** script context on the origin, with no `HttpOnly`-equivalent
  protection. Cookies support the `HttpOnly` flag specifically to prevent JavaScript from
  reading them even in the presence of XSS — `localStorage` has no equivalent mechanism at
  all. If an attacker achieves XSS anywhere on the page (even a low-severity-seeming DOM
  XSS elsewhere in the application), `localStorage.getItem('authToken')` hands them full,
  exfiltratable session credentials.
- This is why storing JWTs or session tokens in `localStorage` is widely considered an
  anti-pattern by the application security community despite being extremely common in
  single-page-application tutorials and boilerplate code — it converts what should be a
  contained, single-vulnerability XSS finding into full account takeover, by removing the
  `HttpOnly` barrier that would otherwise have limited the blast radius.
- `JSON.stringify(response.user)` storing a full user/profile object risks over-exposure
  of PII (email, internal IDs, role flags) to any script on the page, not just the
  intended application code.

### Problem Class 2: Storage as a DOM XSS Source

```js
// On page A: writes attacker-influenced data into storage
localStorage.setItem('lastSearch', location.search);

// On page B, loaded later: reads it back unsafely
document.getElementById('results').innerHTML =
  'Showing results for: ' + localStorage.getItem('lastSearch');
```

Piece by piece — this is functionally identical to a stored DOM XSS bug, just using
`localStorage` instead of a database as the persistence layer:

- `localStorage.setItem('lastSearch', location.search)` — the **source**. `location.search`
  is the URL's query string, fully attacker-controllable via a crafted link
  (`?<img src=1 onerror=alert(1)>`). This line persists that attacker-controlled string
  into storage with no sanitization.
- `localStorage.getItem('lastSearch')` on a **separate page load**, possibly a
  **different page entirely** within the same origin — the **sink path begins**. Because
  storage is shared across all pages of the same origin (not just the page that wrote it),
  the payload can be planted on one page and detonate on a completely different page of
  the application that happens to read the same key.
- `innerHTML = 'Showing results for: ' + ...` — the actual **sink**. The retrieved string
  is concatenated directly into HTML and parsed by the browser, executing any embedded
  markup/script the attacker planted in the first step.
- This pattern is more dangerous than a typical reflected DOM XSS because the "stored"
  nature means a single malicious link, visited once, can plant a payload that persists
  and fires on every subsequent page load — including potentially across browser sessions
  if `localStorage` (rather than `sessionStorage`) is used — until the value is overwritten
  or cleared.

## Manual Testing Methodology (No Dedicated Lab Available)

Because there is no purpose-built Academy lab, use this checklist against any target
(including DOM-based vulnerability labs that happen to use storage incidentally):

1. **Inventory storage usage.** In DevTools → Application tab → Local Storage / Session
   Storage, review every key currently stored after normal application use. Flag anything
   that looks like a token, session identifier, or PII.
2. **Trace the source of each value.** Use DevTools → Sources, set a "DOM breakpoint" or
   search the JS bundle for `.setItem(` calls, and trace backward to confirm whether the
   value being stored originates from attacker-influenceable input (URL, form field, API
   response that itself echoes user input).
3. **Trace the sink of each value.** Search for `.getItem(` calls and trace forward to see
   where the retrieved value is used — flag any path leading to `innerHTML`,
   `document.write()`, `eval()`, dynamic `<script src>` construction, or
   `dangerouslySetInnerHTML`-equivalent rendering in frontend frameworks.
4. **Test cross-page propagation.** Because storage is shared per-origin, plant a payload
   on one page/route and check whether *other* pages or components of the same application
   read and render it — this is the storage-equivalent of testing whether stored XSS
   appears on a different page than where it was submitted.
5. **Check token storage location as a standing finding.** Even without a working XSS
   chain, flag bearer tokens/session identifiers stored in `localStorage`/`sessionStorage`
   as a defense-in-depth weakness (removes the `HttpOnly` protection layer), worth
   reporting independently of whether you can currently demonstrate exploitation.

## Closest Related Academy Lab

**Stored DOM XSS** (under Cross-Site Scripting → DOM-based) is the closest available lab
for practicing the "plant now, detonate via unsafe rendering later" pattern that
storage-based XSS follows conceptually, even though that specific lab persists data
server-side (via the comment functionality) rather than via `localStorage`. The taint-flow
reasoning — untrusted data persisted now, retrieved and rendered unsafely later, on a
different page load — transfers directly.

## Real-World Notes

- The OWASP Top 10's A02:2021 (Cryptographic Failures) and general session-management
  guidance both flag client-side storage of authentication tokens as a recognized
  anti-pattern; the industry-standard alternative is `HttpOnly`, `Secure`,
  `SameSite`-attributed cookies for session tokens, reserving `localStorage` for genuinely
  non-sensitive UI state (theme preference, draft form data, etc.).
- Browser extension and supply-chain compromise research repeatedly demonstrates that
  `localStorage` is one of the first things attacker-controlled or compromised
  third-party scripts scan for, precisely because it so often contains tokens developers
  assumed were "client-side only" and therefore lower risk.
- Single-page application frameworks (React/Vue/Angular) that store auth state in
  `localStorage` for convenience (avoiding cookie/CORS complexity) are a frequent finding
  in bug bounty programs targeting modern SPA-based products — this is worth specifically
  flagging when reviewing JS bundles for any application built on these frameworks.
