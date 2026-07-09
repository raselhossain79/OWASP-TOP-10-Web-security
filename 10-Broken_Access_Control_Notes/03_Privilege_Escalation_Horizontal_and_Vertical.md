# Privilege Escalation — Horizontal and Vertical

## 1. Definitions Recap

- **Horizontal privilege escalation** — accessing another user's data/functions at the *same* privilege level (peer-to-peer). Root cause is usually IDOR (file 2).
- **Vertical privilege escalation** — gaining access to functionality reserved for a *higher* privilege level (user → admin). Root cause is usually a missing or client-trusted authorization check.

This file focuses specifically on the **mechanisms used to escalate role/privilege**, as distinct from object-ownership IDOR. The overlap is real (the same parameter-tampering technique can produce either effect depending on what's being changed), but the *target* of the manipulation differs: IDOR targets a resource ID; privilege escalation targets a **role, permission, or capability flag**.

## 2. Parameter-Based Role Control

Some applications determine a user's role at login and then store that role in a location the client can read and **resubmit** — a hidden form field, a cookie, or a query-string parameter — instead of re-deriving it server-side from the authenticated session on every request.

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=wiener&password=peter

HTTP/1.1 302 Found
Set-Cookie: session=abc123; 
Set-Cookie: role=user
```

### Piece-by-piece breakdown

- `Set-Cookie: role=user` — the server is handing the **role decision back to the browser** as a plain, readable, writable cookie. This is the core mistake: role should be derived server-side from the session on each request, never trusted from client-supplied state.
- **Exploitation:**
```
GET /admin HTTP/1.1
Cookie: session=abc123; role=admin
```
  The attacker simply edits the cookie value from `user` to `admin` before the request reaches the server. If the server's authorization check is `if (request.cookies.role == "admin")` instead of `if (database.lookup(session).role == "admin")`, this single edit grants admin-level access with zero further effort.
- The same flaw appears as a hidden form field (`<input type="hidden" name="role" value="user">`) or a query parameter (`?admin=true`, `?role=1`) — the exploitation logic is identical: find where the client is trusted to assert its own privilege, and assert a higher one.

## 3. User Role Modifiable via Profile/Update Endpoints

A subtler variant: the role isn't sent on login, but a **profile update** endpoint accepts a `roleid` or similar field that the front-end form doesn't expose, but the back-end still processes if present in the raw request.

```
PUT /api/users/8821 HTTP/1.1
Content-Type: application/json
Cookie: session=<attacker session>

{"email":"attacker@example.com","roleid":1}
```

### Piece-by-piece breakdown

- The legitimate front-end form for "update my email" only submits `email`. The server-side handler, however, accepts the **entire JSON object** and applies every field present to the user's row — including `roleid`, which was never meant to be client-writable.
- `"roleid":1` — the attacker discovered (via API documentation, a leaked schema, JS bundle inspection, or simply guessing common field names) that role `1` corresponds to administrator in this system.
- This is a **mass assignment** vulnerability intersecting with access control: the endpoint correctly authenticates the caller and correctly scopes the update to *their own* user row (so it isn't IDOR), but it fails to restrict *which fields* of that row the caller may modify. Updating your own privilege level is still vertical privilege escalation, even though the object being modified is technically "yours."
- **Testing methodology:** always try submitting fields beyond what the UI exposes on any PUT/PATCH/POST that updates "your own" object — pull the field names from JS bundles, OpenAPI/Swagger docs, or by observing admin-facing requests (e.g. via Autorize/Burp history) and replaying the extra fields against your own lower-privileged account.

## 4. Unprotected Functionality (No Check At All)

The most basic form of vertical escalation: sensitive functionality exists at a predictable URL and the server applies **no authorization check whatsoever** — it relies entirely on the UI not showing a link to non-admin users.

```
GET /admin HTTP/1.1
Cookie: session=<ordinary user's session>
```

### Piece-by-piece breakdown

- There is no manipulation here at all beyond simply **navigating to the URL**. The vulnerability is the complete absence of a server-side role check on this route.
- The admin link is omitted from a normal user's rendered HTML, but omission from the UI is not the same as denial by the server. Any user who learns the URL — via `robots.txt`, a JS file that conditionally builds the link, an old support ticket, or a search engine cache — gets the same access an admin would.
- **Real-world note:** this is the single most common access control finding in internal/enterprise tools that were never expected to be internet-facing, then later got exposed (e.g. via a misconfigured load balancer or an accidental public deployment). The "nobody outside the company knows this URL" assumption fails constantly.

## 5. Unpredictable URL Used as the Only Protection

A step up in apparent sophistication: instead of `/admin`, the route is something like `/admin-9f8a3e21`. This is **security through obscurity**, and it fails the same way every time — the URL leaks.

### Where these URLs typically leak

- Client-side JavaScript that conditionally renders an admin link:
```html
<script>
  var isAdmin = false;
  if (isAdmin) {
    var adminPanelTag = document.createElement('a');
    adminPanelTag.setAttribute('href', '/admin-9f8a3e21');
    adminPanelTag.innerText = 'Admin panel';
    topLinksTag.append(adminPanelTag);
  }
</script>
```

### Piece-by-piece breakdown

- `var isAdmin = false;` — this variable is set client-side, meaning **the script itself is sent to every user**, admin or not. The `if (isAdmin)` branch never executes for a normal user *visually*, but the literal string `/admin-9f8a3e21` is still present in the page source they downloaded.
- **Exploitation:** view-source or inspect the network response — the URL is sitting in plaintext in the JS, regardless of whether the link was rendered to the DOM. No brute-forcing needed; the obfuscated path was disclosed by the very code meant to hide it.
- Other common leak vectors: `robots.txt` disallow entries (added so search engines don't index the admin panel — which paradoxically confirms it exists and reveals its path), sitemap.xml, error messages, and version-control artifacts (`.git`, `.svn`) accidentally left deployed.

## 6. Horizontal-to-Vertical Escalation in Practice

Tying back to the chaining concept from file 1, a concrete worked example:

```
GET /myaccount?id=746 HTTP/1.1
Cookie: session=<attacker session>
```

### Piece-by-piece breakdown

- `id=746` is swept the same way as a standard IDOR (file 2) — but the attacker's goal this time isn't "any other user," it's specifically finding the **administrator's** account ID.
- Once the admin's account page loads, the same page that would show a normal user's "change password" form now shows the admin's. If that form doesn't require the *current* password to set a new one (a common secondary flaw), the attacker sets a new password for the admin account directly.
- The result: a horizontal-class exploitation technique (ID substitution) is used to reach a vertical-class outcome (full admin account takeover). This is why **every IDOR should be tested against every reachable account type**, not just two equal-privilege test users — if you only test `wiener` against `carlos`, you may miss that the same flaw reaches `administrator`.

## 7. Real-World Notes

- Vertical privilege escalation findings are typically rated **Critical** in professional engagements when they reach administrative or "god mode" functionality, even if the initial step (a missing check on one endpoint) seems trivial.
- When writing up findings for a client report or bug bounty submission, always state explicitly *which* role boundary was crossed (e.g. "standard user → tenant admin", not just "privilege escalation") — reviewers and triagers need the exact before/after privilege levels to assess severity (CVSS Privileges Required and Scope metrics depend on it).
- Defense-in-depth against this entire category: never let the client assert its own role or permissions in any form (cookie, hidden field, JSON body, JWT claim that isn't signed/verified server-side); always re-derive the authenticated principal's actual privilege from a trusted server-side source on every single request.
