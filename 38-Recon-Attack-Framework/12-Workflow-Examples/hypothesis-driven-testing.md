# Hypothesis-Driven Testing — Choosing What to Test, Not Testing Everything Everywhere

## The Core Problem This Solves
Given enough time, you *could* run every vulnerability class in
`06-Vulnerability-Testing/` against every input on every endpoint. That's not
how experienced testers actually work — it's slow, noisy, and dilutes effort
away from the inputs most likely to actually be vulnerable. The real skill is
reading an endpoint's **shape** (method, parameter names, data type, context)
and forming a short, ranked list of plausible hypotheses before testing anything.

## The Full Lifecycle
```
Recon -> Endpoint discovery -> Request analysis -> Input mapping ->
Hypothesis creation -> Manual testing -> False-positive elimination ->
Impact validation -> Reporting
```
Each arrow is a real decision point, not just a sequence label:
- **Request analysis → Input mapping**: you're not just listing parameters, you're
  noting each one's apparent *type* and *role* (numeric ID? free text? boolean
  flag? URL? filename?) — this is what hypothesis creation actually uses.
- **Input mapping → Hypothesis creation**: for each input, ask "what would this
  parameter's role make it a natural candidate for, and why" — see the worked
  examples below for exactly how that reasoning goes.
- **Manual testing → False-positive elimination**: per `08-Validation-and-
  Evidence/`, every signal gets actively challenged before being trusted.

## How to Rank Hypotheses Per Input (General Rule)
| Input shape | Most likely hypotheses, roughly in priority order |
|---|---|
| Numeric/sequential ID in path or query | IDOR/BOLA (horizontal), then SQLi if it looks query-driven |
| Free-text search/filter field | Reflected XSS, then SQLi if it feeds a backend search query |
| URL/file-path value | SSRF (if server-side fetch is plausible) or path traversal/LFI (if it maps to a local file) |
| File upload field | File-upload validation bypass; XXE if the format is XML-based |
| Role/permission/boolean flag in a body | Broken access control / mass assignment (client-trusted field) |
| Redirect-target parameter | Open redirect |
| Template/formatting-aware text field | SSTI (only if the stack plausibly uses a template engine for that field) |

This table is a starting point for ranking, not a rule that other classes never
apply — but it's where to look first, rather than running all seven classes
against a numeric ID with equal priority.

## Worked Example 1 — A Search Endpoint
`GET /search?q=laptop`

**Input mapping**: `q` is free text, clearly feeds some kind of filtering/search
logic (results change based on it).

**Hypothesis ranking**:
1. Reflected XSS — search terms are very commonly echoed back into the results
   page ("Showing results for: laptop") without always being escaped.
2. SQLi — if the search is backed by a SQL `LIKE` query rather than a dedicated
   search index (Elasticsearch, etc.), free-text input reaching SQL directly is
   plausible; worth a quick error-based probe even without strong evidence yet.
3. SSRF/path traversal — not plausible here; a search term has no reason to be
   treated as a URL or filename, so these aren't worth prioritizing on this
   input.

**Action**: test XSS first (per `xss.md`, context-identification step), then a
single error-based SQLi probe (per `sqli.md`) if XSS testing doesn't resolve the
question quickly. Don't run SSRF/path-traversal probes here — the input shape
doesn't support that hypothesis.

## Worked Example 2 — A User Profile API
`GET /api/users/42/profile`, `PUT /api/users/42/profile`

**Input mapping**: `42` is a numeric, sequential-looking user ID in the path;
the `PUT` body likely contains editable profile fields.

**Hypothesis ranking**:
1. IDOR/BOLA on the `GET` — does requesting `43` as a different user return
   someone else's profile? This is the single highest-value test for this
   endpoint shape.
2. Broken access control / mass assignment on the `PUT` — does the body accept
   a field like `role` or `verified` that isn't shown in the normal UI form but
   is still processed server-side?
3. SQLi on the numeric ID — lower priority than IDOR here specifically because
   a profile-by-ID lookup is very commonly implemented via a parameterized
   ORM call rather than raw string-concatenated SQL, but still worth one quick
   probe if IDOR/mass-assignment testing doesn't resolve things.

**Action**: `idor.md` methodology first (requires a second test account per its
prerequisites), then `broken-access-control.md` for the `PUT` body.

## Worked Example 3 — An Order Management API
`GET /api/orders/{order_id}`, `POST /api/orders/{order_id}/cancel`

**Input mapping**: `order_id` is a resource identifier; the `cancel` action is a
state-changing, role-relevant action tied to ownership.

**Hypothesis ranking**:
1. IDOR/BOLA — can User B view or cancel User A's order? This is the central
   question for this endpoint shape and should be tested before anything else.
2. Business logic — can `cancel` be called twice, or on an order already in a
   terminal state (e.g. already shipped), producing an unintended effect (double
   refund, inconsistent state)?
3. CSRF on `cancel` — if it's cookie-session-authenticated with no token, a
   malicious page could trigger order cancellation for a logged-in victim.

**Action**: `idor.md` first (both read and the cancel action, per its
horizontal/vertical split), then `business-logic.md` for the replay/state
question, then `csrf.md` if cookie-based auth is confirmed with no visible
token.

## Worked Example 4 — A File Upload Feature
`POST /api/avatar` (multipart file upload)

**Input mapping**: a file field, likely validated by extension/content-type,
served back at some URL after upload.

**Hypothesis ranking**:
1. File-upload validation bypass leading to stored XSS (if SVG/HTML-adjacent
   types are accepted and served same-origin) — the most common realistic
   finding for this endpoint shape.
2. XXE — only relevant if the accepted format is XML-based (SVG counts; a plain
   JPEG/PNG upload doesn't warrant XXE testing at all).
3. Path traversal — only relevant if the *filename itself* (not just content)
   is later used to construct a server-side file path for retrieval/processing.

**Action**: `file-upload.md` methodology, branching into `xxe.md` specifically
if SVG/XML-based formats are accepted.

## Worked Example 5 — A Webhook / URL Import Feature
`POST /api/integrations/webhook` with a `callback_url` field

**Input mapping**: a URL value that the server will itself fetch or send
requests to — this is close to a textbook SSRF-shaped input.

**Hypothesis ranking**:
1. SSRF — by far the dominant hypothesis for this exact input shape; test per
   `ssrf.md`'s listener-based confirmation before anything else.
2. Open redirect — only relevant if there's a *separate* user-facing redirect
   behavior tied to the same or a related URL field (not automatically true
   just because a URL field exists).

**Action**: `ssrf.md` methodology first and almost exclusively — this endpoint
shape rarely benefits from broad testing across unrelated classes.

## The General Lesson From All Five Examples
In every case, 1–2 classes dominated the realistic hypothesis list, and the
input's *shape and role* — not a fixed checklist — determined which ones. Build
this same reasoning explicitly into the Hypothesis column of
`11-Testing-Management/Testing-Matrix.md` for every row, rather than testing
every class against every input out of habit.
