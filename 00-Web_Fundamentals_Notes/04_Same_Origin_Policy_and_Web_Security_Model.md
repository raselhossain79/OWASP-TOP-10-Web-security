# Same-Origin Policy & The Web Security Model

> This is arguably the single most important concept in this entire prerequisite folder. 
> CORS, XSS impact, CSRF, clickjacking, and CSWSH are all either an enforcement of this 
> policy or an exploitation of a gap in how it's enforced. Understand this file 
> completely before reading any of those note series.

---

## 1. What an "Origin" Actually Is

An origin = **scheme + host + port**, all three together:
```
https://example.com:443
   │        │        │
 scheme    host      port
```
Two URLs are the **same origin** only if all three match exactly:
```
https://example.com         vs  http://example.com        → DIFFERENT (scheme differs)
https://example.com         vs  https://api.example.com   → DIFFERENT (host differs — 
                                                              subdomains are NOT the same origin)
https://example.com         vs  https://example.com:8080   → DIFFERENT (port differs)
```

## 2. What the Same-Origin Policy (SOP) Actually Restricts

SOP is a **browser-enforced rule** that says: a script running on origin A cannot read 
the response data of a request made to origin B, by default.

It does **not** stop origin A from *sending* a request to origin B (your browser can 
still send a cross-origin GET/POST) — it stops the JavaScript on origin A from *reading 
the response*. This distinction is the entire reason CSRF and CORS are different bugs:
- **CSRF** abuses the fact that the request still gets sent (with cookies attached) — 
  the attacker doesn't need to read the response, just needs the side-effect (the action) 
  to happen.
- **CORS misconfiguration** abuses a case where the server explicitly told the browser 
  "it's fine, let them read the response" when it shouldn't have.

## 3. How SOP Relates to Each Vulnerability You'll Study

| Vulnerability | Relationship to SOP |
|---|---|
| **CORS Misconfiguration** | The server opts OUT of SOP's protection (via `Access-Control-Allow-Origin`) for origins it shouldn't trust |
| **CSRF** | Exploits the fact that SOP never blocked the *request* in the first place, only reading the response |
| **XSS** | Once a script executes on the victim's origin, it's now treated as "same origin" by the browser — this is why XSS impact is so severe, it fully steps inside the trust boundary SOP was protecting |
| **Clickjacking** | A separate browser protection (`X-Frame-Options`/`frame-ancestors`) layered on top of SOP, specifically for framing |
| **CSWSH** | WebSocket connections aren't covered by SOP/CORS the same way HTTP requests are — the server itself must check the `Origin` header manually, and often doesn't |

## 4. Why This Matters Before You Study Any of Those Topics

If you don't have this model clear, CORS misconfiguration notes will feel like 
memorized header syntax instead of "the server is disabling a browser protection that 
exists for a reason." Same with CSRF — without understanding that SOP never blocked the 
request itself, the existence of CSRF as a "bug" (when the request was always going to 
be sent anyway) won't make logical sense.

## 5. A Concrete Mental Model

```
Browser tab on evil.com runs JavaScript:
  fetch("https://bank.com/transfer?amount=1000", {credentials: 'include'})

What happens:
  1. The request DOES get sent to bank.com, with bank.com's cookies attached 
     (the browser doesn't block this — this is the CSRF angle)
  2. If bank.com actually processes the transfer because it didn't check for a 
     CSRF token, the money moves — attacker doesn't even need to see the response
  3. If evil.com's JS tries to READ the response body, SOP blocks that — UNLESS 
     bank.com's CORS headers explicitly said evil.com is allowed to read it 
     (the CORS misconfiguration angle)
```

This single example contains the conceptual seed of both CSRF and CORS misconfiguration 
— the rest of those note series is just technique detail on top of this model.

## 6. Real-World Notes
- When testing CORS, always ask: "is the server reflecting my Origin header back, or 
  does it have an actual allowlist?" — reflecting any Origin back with credentials 
  enabled is the classic misconfiguration.
- When testing CSRF, always check `SameSite` cookie attributes first (file 03) — modern 
  browser defaults already block a lot of classic CSRF, so look for the gaps (GET-based 
  state changes, subdomain-related SameSite quirks) rather than assuming CSRF is dead.
- This model is also why JSONP (an older cross-origin data-sharing technique) and 
  `postMessage` exist — both are deliberate, controlled ways to punch a hole in SOP when 
  an app actually needs cross-origin communication. `postMessage` misuse is covered in 
  the Client-Side JS Vulnerabilities notes.

Continue to → `05_URL_Structure_and_Encoding.md`
