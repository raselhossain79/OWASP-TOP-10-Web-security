# Broken Access Control — Overview and Classification (OWASP A01:2021)

## 1. What Access Control Actually Means

Access control is the set of mechanisms that decide **who is allowed to do what, to which data, under what conditions.** It sits downstream of two other mechanisms that are often confused with it:

- **Authentication** — proves the user is who they claim to be (login, MFA, tokens).
- **Session management** — tracks which subsequent requests belong to that authenticated user (cookies, session IDs, JWTs).
- **Access control** — given a verified, tracked identity, decides whether *this specific action on this specific resource* is permitted.

A system can have flawless authentication and session management and still be completely broken if the access control layer never asks "but is this user actually allowed to do this?" This is why Broken Access Control has sat at or near the top of the OWASP Top 10 for years (A01:2021) — it is rarely a single bug. It's usually dozens of small, independent decisions made by different developers across different endpoints, and it only takes one missed check to break the whole model.

### Real-world framing

In an actual engagement, access control failures are the single most common **critical/high severity** finding in web and API assessments, ahead of injection. The reason is structural, not technical skill: access control logic has to be re-implemented (or re-checked) on every single endpoint, in every microservice, for every role. Authentication is built once. Access control decisions are scattered across the entire codebase. This is also why access control bugs are extremely common in **bug bounty programs** — they don't require any "creative" payload crafting like SQLi or XSS; they require systematic, patient enumeration of what happens when you change an ID, drop a parameter, or hit an endpoint you weren't given a link to.

## 2. The Three Models of Access Control

PortSwigger's own taxonomy (and the one this series follows) splits access control into three categories. Every technique in this series is an instance of one of these three failing.

### 2.1 Vertical Access Control

Vertical access control restricts access to **functionality** based on user *type* or *privilege level*. Different roles see different capabilities: a standard user sees their own dashboard; an admin sees a user-management panel that can delete accounts.

**Failure mode:** a lower-privileged user reaches functionality reserved for a higher-privileged role. This is called **vertical privilege escalation**. Example: a normal user discovering and successfully calling `/admin/deleteUser` because the server never checks the caller's role on that route — only the UI hides the link.

### 2.2 Horizontal Access Control

Horizontal access control restricts access to **resources** based on ownership, not role. Two users have the *same* privilege level, but each should only see their own data — their own invoices, their own messages, their own account page.

**Failure mode:** a user accesses another user's data of the same type. This is **horizontal privilege escalation**, and it is the textbook scenario for an **IDOR (Insecure Direct Object Reference)** — covered in depth in file 2. Example: `GET /account?id=1057` returning someone else's account just because you changed the number.

### 2.3 Context-Dependent Access Control

Context-dependent access control restricts actions based on the **state of the application or the user's prior interaction with it** — not role, not ownership, but sequence and state.

**Failure mode:** a user performs an action out of the intended order, or revisits a step that should only be reachable after an earlier step is satisfied. Example: a checkout flow where the "apply discount" step can be called directly via its API endpoint *after* payment has already been confirmed, because the server trusts the client to only call it at the right time.

## 3. Horizontal-to-Vertical Escalation Chaining

In real engagements, horizontal and vertical escalation are rarely separate findings — they chain. A classic chain looks like this:

1. Attacker finds a horizontal IDOR: `GET /myaccount?id=<n>` exposes any user's account data when `id` is changed.
2. Attacker iterates `id` values (or guesses based on creation order) until they land on an **administrator account's** ID.
3. The exposed account page for that administrator discloses a password-reset token, a current password, or a "change password" action with no re-authentication required.
4. Attacker takes over the admin account → now has **vertical** privilege.

This is why a "low-severity" IDOR that only leaks a username or email is still worth chasing further: the real impact often isn't in the first object you can read, it's in *which* object you eventually reach.

## 4. Why Access Control Breaks: Root Causes

Across every technique in this series, the underlying cause is almost always one of these:

| Root cause | Description | Covered in |
|---|---|---|
| **Missing check** | The endpoint exists and works; nobody added an authorization check to it at all. | File 4 |
| **Client-trusted state** | Role, user ID, or permission is read from a parameter, cookie, or hidden field the client controls. | Files 3, 4 |
| **Obscurity mistaken for security** | Sensitive functionality is "hidden" behind a non-obvious URL instead of actually being protected. | File 4, 6 |
| **Inconsistent enforcement across layers** | A reverse proxy, WAF, or front-end router enforces a rule the back-end application doesn't independently re-check (or vice versa). | File 4 |
| **State assumed, not verified** | The app assumes a multi-step process was followed in order, instead of checking server-side that each precondition was actually met. | File 6 |
| **Path/identifier left fully under user control** | The literal filesystem path or DB key used to fetch a resource is taken straight from user input with no ownership check. | Files 2, 5 |

## 5. Real-World Industry Note

In production environments, access control testing is the part of a pentest that benefits least from automated scanners and most from **methodical manual testing with a proxy** (Burp Suite). Scanners are good at finding injection because injection has detectable side effects (errors, timing, reflected payloads). Access control failures usually return a perfectly normal-looking `200 OK` with legitimate-looking data — the only way to know it's wrong is to know *whose* data it should have been. This is precisely why tools like **Autorize** and **AuthMatrix** exist (file 7): they don't detect vulnerabilities by pattern-matching responses, they detect them by **replaying the exact same request under a different, lower-privileged session** and diffing the result. That's the manual technique automated.

This series treats every technique the way you'd approach it on an actual engagement or bug bounty target: identify the access control model in use (vertical/horizontal/context-dependent), identify what the server is trusting that it shouldn't be, and manipulate exactly that trust point.

## 6. File Index for This Topic

- `02_IDOR_Techniques.md` — Insecure Direct Object References
- `03_Privilege_Escalation_Horizontal_and_Vertical.md` — role and ownership escalation
- `04_Missing_Function_Level_Access_Control.md` — unprotected/hidden functionality, platform-layer bypasses
- `05_Path_Traversal_as_Access_Control.md` — file-system level object reference failures
- `06_Forced_Browsing.md` — enumeration, multi-step process abuse, Referer-based control
- `07_Autorize_and_AuthMatrix_Automation.md` — tool-assisted testing
- `08_Cheatsheet_and_Lab_Mapping.md` — quick reference + full PortSwigger lab progression
