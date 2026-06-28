# Cookies & Session Management Fundamentals

---

## 1. Why Cookies Exist

HTTP is **stateless** — by default, the server has no memory of you between requests. 
Cookies are the original mechanism for fixing that: the server sets a value, the browser 
automatically sends it back on every subsequent request to that domain, and the server 
uses it to recognize "this is the same user as before."

## 2. Cookie Attributes — Each One Broken Down

```
Set-Cookie: session=abc123; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600
```

- **`session=abc123`** — the actual name/value pair; this is the data
- **`Domain=example.com`** — which domain(s) the cookie gets sent to (includes 
  subdomains unless scoped tighter) — relevant to Subdomain Takeover impact, since a 
  takeover on a subdomain can sometimes read cookies scoped to the parent domain
- **`Path=/`** — restricts the cookie to certain URL paths on that domain
- **`Secure`** — cookie is only sent over HTTPS connections; without this, the cookie 
  can leak over any accidental plain-HTTP request
- **`HttpOnly`** — JavaScript (`document.cookie`) cannot read this cookie at all; this 
  is the single most important defense against session-stealing via XSS — if this flag 
  is missing, a successful XSS can directly read and exfiltrate the session cookie
- **`SameSite`** — controls whether the cookie is sent on cross-site requests:
  - `Strict` — never sent cross-site, strongest CSRF protection
  - `Lax` — sent on top-level navigation (clicking a link) but not on cross-site POST/
    background requests — this is the modern browser default and the main reason CSRF 
    got less common, but it is NOT a complete CSRF fix (GET-based state changes still 
    work, and some edge cases bypass Lax)
  - `None` — sent on all cross-site requests (requires `Secure` to be set alongside it)
- **`Max-Age` / `Expires`** — how long the cookie persists; without either, it's a 
  session cookie that disappears when the browser closes

## 3. Session-Based vs Token-Based Authentication

| | Session-based (cookie) | Token-based (JWT, often in `Authorization` header) |
|---|---|---|
| Where state lives | Server-side (session store/database) | Self-contained in the token itself |
| Revocation | Easy — delete the server-side session | Hard — token is valid until it expires, unless you maintain a blocklist |
| Vulnerability focus | Session fixation, predictable session IDs, missing `HttpOnly`/`Secure`/`SameSite` | JWT-specific attacks (`alg:none`, weak signing secret, algorithm confusion) — covered fully in Cryptographic Failures and Auth Failures notes |

Modern apps frequently use both at once — a session cookie for the main web app, plus a 
JWT for API calls. Always identify which model (or both) a target uses before testing 
auth-related vulnerabilities, since the testing approach differs.

## 4. Real-World Notes
- The very first thing to check on any new target: open dev tools → Application/Storage 
  tab → look at every cookie's attributes. Missing `HttpOnly` or `Secure` on a session 
  cookie is a quick, real, reportable finding even before you find anything else.
- Session token randomness matters — a session ID that's predictable (sequential, 
  timestamp-based, weakly hashed) can be brute-forced or guessed; this is covered in the 
  Auth Failures notes under session management flaws.
- `SameSite=Lax` becoming the browser default (Chrome, Firefox) is exactly why CSRF was 
  removed from the OWASP Top 10's main list — but it's also exactly why the CSRF note 
  series in this repo specifically covers `SameSite` bypass techniques, since "less 
  common" doesn't mean "gone."

Continue to → `04_Same_Origin_Policy_and_Web_Security_Model.md`
