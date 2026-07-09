# Missing Function-Level Access Control

## 1. What This Category Covers

"Missing function-level access control" (the term used in the OWASP Top 10 2013/2017 editions, folded into A01:2021 today) refers to cases where a **specific function/endpoint/HTTP method** is reachable without the correct authorization check, even though *other* parts of the same application enforce access control correctly. The distinguishing trait versus file 3's "unprotected functionality" section is that here the failure is frequently about **inconsistency between enforcement layers** — a front-end router, a reverse proxy, or a URL-matching rule disagrees with the back-end application about what counts as "the same" endpoint.

## 2. Platform-Layer Misconfiguration

Some architectures enforce access control at the **infrastructure layer** (a reverse proxy, API gateway, or web server config) rather than in application code, using rules like:

```
DENY: POST, /admin/deleteUser, managers
```

This rule says: deny `POST` requests to `/admin/deleteUser` from anyone in the `managers` group. It looks reasonable, but it creates two independent attack surfaces: the **URL** and the **HTTP method**, both of which can be manipulated separately from how the back-end application actually defines the route.

### 2.1 Bypass via URL-Override Headers

```
POST / HTTP/1.1
Host: insecure-website.com
X-Original-URL: /admin/deleteUser
Cookie: session=<low-privilege session>

username=carlos
```

#### Piece-by-piece breakdown

- `POST /` — the request line targets the application **root**, a path the platform-layer rule has no reason to block.
- `X-Original-URL: /admin/deleteUser` — many frameworks (built-in support in some Symfony/Ruby setups, or via custom middleware) support this header (or `X-Rewrite-URL`) to let infrastructure components like load balancers tell the back-end "actually route this internally as if it were a request to this other path." This exists for legitimate reasons (CDN/edge rewriting), but if the **front-end access-control rule only inspects the literal request line's path** (`/`) while the **back-end application honors the header and internally routes to `/admin/deleteUser`**, the platform-layer deny rule never fires — it was checking the wrong path.
- The result: the platform layer sees and approves a harmless-looking request to `/`; the application layer, trusting the override header, actually executes the sensitive `deleteUser` action.
- **Testing methodology:** whenever a sensitive endpoint returns a `401`/`403`, always retry the exact same request while adding `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Path`, and similar headers set to the blocked path, with the request line itself pointed at an unrestricted path. This is a five-minute test with very high payoff when it works.

### 2.2 Bypass via HTTP Method Substitution

```
GET /admin/deleteUser?username=carlos HTTP/1.1
Cookie: session=<low-privilege session>
```

#### Piece-by-piece breakdown

- The platform rule from above only denies the **`POST`** method on this path. It says nothing about `GET`.
- If the back-end application is lenient enough to also accept the same action via `GET` (a common shortcut in frameworks that auto-route based on a function name regardless of verb, or that map both verbs to the same controller action for convenience), then simply changing the HTTP method **entirely sidesteps** the platform-layer restriction, because that restriction was verb-specific while the application's actual handler was not.
- **Why this is a recurring real-world issue:** infrastructure teams and application teams are often different people working from different documentation. The infra team writes a rule based on what the *current* front-end calls (`POST`), without verifying that the back-end controller *rejects* all other verbs for that action. Always test `GET`, `PUT`, `PATCH`, `DELETE`, and even unusual verbs like `HEAD`/`OPTIONS`/a fully invented verb against any endpoint that's blocked on its "expected" method.

## 3. URL-Matching Discrepancies

Different components in a request pipeline can disagree about whether two URLs are "the same" endpoint. Each discrepancy is a potential bypass.

### 3.1 Case-Sensitivity Mismatch

```
GET /ADMIN/DELETEUSER?username=carlos HTTP/1.1
```

#### Piece-by-piece breakdown

- If the front-end access-control rule does a case-sensitive string match against `/admin/deleteUser` (and therefore doesn't flag `/ADMIN/DELETEUSER`), but the back-end web server or framework normalizes case before routing (so `/ADMIN/DELETEUSER` still resolves to the same controller as `/admin/deleteUser`), the all-caps version sails through the access-control layer and still executes the privileged action on the back end.
- This is purely an artifact of two different pieces of software implementing "path matching" with different normalization rules — neither is "wrong" in isolation, the danger is in the **gap between them**.

### 3.2 Spring `useSuffixPatternMatch` File-Extension Mismatch

```
GET /admin/deleteUser.anything?username=carlos HTTP/1.1
```

#### Piece-by-piece breakdown

- Older Spring MVC configurations (prior to Spring 5.3, where this option defaulted to enabled) treat any path with an arbitrary trailing extension as equivalent to the same path with no extension — i.e. `/admin/deleteUser.anything`, `/admin/deleteUser.json`, and `/admin/deleteUser` are all routed to the same controller method.
- If the access-control rule (or a WAF signature) is written to match the literal string `/admin/deleteUser` only, appending essentially any suffix (`.anything`, `.json`, `.css`) produces a *different string* that evades the literal match while the framework still resolves it to the protected controller.
- **Why `.anything` specifically works:** Spring's suffix pattern matching doesn't validate that the suffix corresponds to a real, registered content type — it strips whatever comes after the final dot and matches on what remains, so any arbitrary suffix is accepted.

### 3.3 Trailing Slash Discrepancy

```
GET /admin/deleteUser/?username=carlos HTTP/1.1
```

#### Piece-by-piece breakdown

- Some systems treat `/admin/deleteUser` and `/admin/deleteUser/` (trailing slash) as **distinct** routes when matching access-control rules, while the underlying application framework treats them as identical for routing purposes.
- Adding (or removing) the trailing slash is often enough to step outside the literal string the access-control rule was written to match, while the application still serves the same functionality at the normalized path.

## 4. JavaScript-Disclosed Functionality

Covered briefly in file 3 for the URL-disclosure angle; worth restating here specifically as a *function-level* control failure: client-side **role gating in JavaScript is not access control** — it's UI convenience. Any conditional logic like `if (user.isAdmin) { showButton() }` only ever hides a button. The actual server-side handler for whatever that button calls must independently re-verify the caller's role; if it doesn't, calling that endpoint directly (via Burp Repeater, curl, or browser console `fetch()`) bypasses the entire restriction with zero effort, because the "restriction" never existed past the browser.

## 5. Real-World Notes

- Function-level access control bugs are extremely common in **microservice architectures** where an API gateway enforces *some* rules and individual services trust the gateway to have already filtered everything — but a service that's also reachable directly (misconfigured network segmentation, internal-only service accidentally exposed) has no authorization logic of its own at all.
- When testing a target with a WAF or reverse proxy in front of it, always assume the access-control "fix" might be a single rule bolted onto the edge rather than fixed in application code — these edge-only fixes are exactly the ones susceptible to the header/method/path-normalization tricks above.
- The professional remediation advice (per OWASP) is to **never rely on a single enforcement point**: the application itself should deny access by default and require an explicit grant for every sensitive route, independent of whatever the network edge does.
