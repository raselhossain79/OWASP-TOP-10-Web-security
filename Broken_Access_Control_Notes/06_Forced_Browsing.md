# Forced Browsing and Related Enumeration Techniques

## 1. What Forced Browsing Means

Forced browsing is the technique of directly requesting URLs, files, or endpoints that are **not linked** anywhere in the application's normal navigation, in order to reach functionality or data that the application intended to keep hidden behind obscurity rather than an actual server-side check. It's the *technique* behind several of the failure modes already described in files 3 and 4 — this file collects the **enumeration/discovery methodology** itself, plus two closely related access-control failures that depend on the same "skip the intended path" idea: multi-step process abuse and Referer-based access control.

## 2. Sources for Discovering Hidden Paths

### 2.1 robots.txt and sitemap.xml

```
GET /robots.txt HTTP/1.1
```

```
User-agent: *
Disallow: /administrator-panel-yb556
Disallow: /internal-api/
```

#### Piece-by-piece breakdown

- `robots.txt` exists to tell **search engine crawlers** which paths not to index. It is publicly fetchable by anyone, not just crawlers — it carries no authentication requirement at all.
- `Disallow: /administrator-panel-yb556` — a developer added this entry specifically *because* they didn't want the admin panel showing up in Google search results. The unintended side effect: this file is the single most reliable place an attacker checks first, because it directly hands over the "obscured" URL that platform-misconfiguration/unpredictable-URL techniques (file 3) rely on being secret.
- **Methodology takeaway:** always fetch `/robots.txt` and `/sitemap.xml` as the very first two requests against any new target — both are explicitly designed to disclose paths, just to the "wrong" audience.

### 2.2 JavaScript Bundle Inspection

Covered in detail in files 3 and 4 — any conditionally-rendered link or API call embedded in client-side JS is downloaded by every user regardless of role. Searching minified JS bundles for strings like `/admin`, `/api/internal`, `role`, `isAdmin`, or `permission` routinely surfaces entire hidden route trees.

### 2.3 Directory/Endpoint Brute-Forcing with Wordlists

```
GET /backup HTTP/1.1
GET /admin HTTP/1.1
GET /api/v1/users HTTP/1.1
GET /.git/config HTTP/1.1
GET /console HTTP/1.1
```

#### Piece-by-piece breakdown

- Each of these is a guess drawn from a **wordlist of common application paths** (e.g. SecLists' `raft-large-directories.txt`, or framework-specific lists for common admin/API route names).
- Tools like **ffuf**, **gobuster**, or Burp's own **Intruder/Content Discovery** module automate this: the wordlist entry is substituted into the path position of a base request, and the tool flags any response that **doesn't** return the application's standard 404 page (status code, response length, or response timing differences all serve as signals that a real resource was hit).
- `/.git/config` specifically targets a common deployment mistake: a `.git` directory accidentally left inside a publicly served web root, which can disclose source code, commit history, and sometimes hardcoded credentials.
- **Why this matters for access control specifically (not just recon):** many of these discovered endpoints, once found, turn out to have *no authorization check at all* — connecting straight back to the "missing function-level access control" pattern in file 4. Forced browsing is the discovery step; the actual vulnerability is what file 4 describes once you're standing in front of the endpoint.

## 3. Access Control Vulnerabilities in Multi-Step Processes

Many sensitive actions are implemented as a sequence of steps — for example, an admin "update user role" workflow:

1. `GET /admin/users/8821/edit` — load the edit form.
2. `POST /admin/users/8821/edit` — submit proposed changes.
3. `POST /admin/users/8821/confirm` — review and confirm; this final step actually applies the change.

A common implementation mistake: rigorous access-control checks are applied to steps 1 and 2 (correctly verifying the caller is an admin), but step 3 is treated as "internal" — the developer assumes nobody reaches step 3 without having legitimately passed through steps 1 and 2 first, so the authorization check on step 3 is skipped or weaker.

```
POST /admin/users/8821/confirm HTTP/1.1
Cookie: session=<low-privilege session>

confirmed=true&roleid=1
```

### Piece-by-piece breakdown

- The attacker never requests steps 1 or 2 at all. They go **directly** to the final, action-performing endpoint, supplying whatever parameters they've inferred it needs (`roleid=1`, observed earlier from JS, API docs, or by triggering this flow once as a legitimate admin and recording the exact request in Burp's history).
- `confirmed=true` — this parameter exists purely to satisfy the *application logic's* expectation that confirmation happened; it carries no actual security value because the server never independently verifies that steps 1 and 2 actually occurred in this session.
- **Why this is an access-control failure and not "just" a logic flaw:** the assumption that "users only reach step 3 via steps 1 and 2" is exactly the same category of mistake as the unpredictable-URL assumption in file 3 — trusting an expected *path through the application* instead of independently re-checking authorization at the point where the sensitive action actually executes.
- **Defense:** every step that performs a state-changing action needs its own authorization check, server-side validation that prerequisite steps were genuinely completed (e.g. via a server-side workflow/state token, not a client-supplied flag), not just steps 1 and 2.

## 4. Referer-Based Access Control

Some applications apply rigorous checks to a main administrative page, but rely on the **`Referer` HTTP header** to gate access to its sub-pages, assuming a sub-page is only ever reached by navigating *from* the protected main page.

```
GET /admin HTTP/1.1
Cookie: session=<admin session>

HTTP/1.1 200 OK
... (only accessible after the main /admin check passes)

GET /admin/deleteUser?username=carlos HTTP/1.1
Referer: https://insecure-website.com/admin
Cookie: session=<low-privilege session>
```

### Piece-by-piece breakdown

- `/admin/deleteUser` itself performs **no independent session/role check** — its only "protection" is inspecting the incoming `Referer` header and confirming it equals the `/admin` URL, on the theory that only someone who already passed the `/admin` page's real check could have a link to click that generates this Referer value.
- `Referer: https://insecure-website.com/admin` — this header is **entirely attacker-controlled**. Standard HTTP clients (browsers, curl, Burp Repeater) let you set or omit any header value you want on an outgoing request; nothing cryptographically ties this header to having actually visited `/admin` in a prior request.
- The attacker simply forges this header value on a direct request, with a session that was never authorized to view `/admin` in the first place, and the sub-page's flawed check is satisfied.
- **Why this control fails categorically, every time it's used:** the `Referer` header is **client-supplied metadata**, not a security boundary. Any value the server reads from a request header that the client fully controls is, by definition, not a valid substitute for an authenticated, server-derived authorization decision — the exact same root cause as the cookie/hidden-field role tampering described in file 3.

## 5. Combining Forced Browsing with Enumerated Identifiers

In practice, the most effective real-world recon combines this file's discovery techniques with file 2's IDOR sweeping: once forced browsing surfaces an endpoint pattern (e.g. `/api/v1/invoices/{id}`), immediately test that pattern against an ID range, and test it without authentication, with a low-privilege session, and with no session at all — three separate access-control questions answered from a single discovered route.

## 6. Real-World Notes

- Forced browsing is formally tracked under **CWE-425: Direct Request ('Forced Browsing')**.
- Automated content-discovery (ffuf/gobuster/Burp) should always be paired with **manual** review of JS bundles and `robots.txt`/`sitemap.xml` — wordlists only find what's already in the wordlist; leaked application-specific paths (custom admin panel names, internal tool names) are never in a generic wordlist.
- Multi-step process and Referer-based bypasses are particularly common in **legacy enterprise applications** built incrementally over many years, where access control was added to the "front door" of a workflow long after the back-end actions were already implemented and exposed.
