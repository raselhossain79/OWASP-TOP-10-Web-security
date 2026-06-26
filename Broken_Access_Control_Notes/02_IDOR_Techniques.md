# Insecure Direct Object References (IDOR)

## 1. What IDOR Actually Is

An IDOR vulnerability exists when an application uses a value supplied directly by the user — an ID, a filename, a key — to look up and return an object, **without independently verifying that the requesting user is allowed to access that specific object.**

The term "direct object reference" means the request literally contains a reference (an ID, a path, a key) that maps straight onto a server-side resource, with no indirection layer (such as a session-scoped lookup table) in between. The vulnerability isn't that an identifier exists in the request — almost every app needs that. The vulnerability is the **missing ownership check** on the server side after that identifier is read.

### Real-world framing

IDOR is consistently one of the highest-paying, highest-volume bug classes on bug bounty platforms (HackerOne, Bugcrowd), specifically because it requires no fuzzing skill — just patient, systematic parameter substitution across every endpoint that accepts an identifier: account IDs, order IDs, invoice numbers, document UUIDs, chat/message IDs, file storage keys, even support-ticket numbers. A single IDOR in an API used by a mobile app can expose every customer record in that company's database via simple integer iteration.

## 2. Direct References to Database Objects (Sequential IDs)

This is the simplest and most common form. A request like:

```
GET /myaccount?id=1057 HTTP/1.1
Host: insecure-website.com
Cookie: session=<wiener's session token>
```

### Piece-by-piece breakdown

- `GET /myaccount?id=1057` — the endpoint returns account details for whatever numeric `id` is supplied.
- `id=1057` — this is the direct object reference. It is not a hash, not a session-derived value, just a raw row identifier, most likely an auto-incrementing primary key in the `users` table.
- `Cookie: session=...` — proves *who is asking*, but if the server's query is effectively `SELECT * FROM accounts WHERE id = :id` with no added `AND owner_session_user = :current_user`, the cookie is irrelevant to the actual data lookup.

**Why changing `id` works:** the server trusts the client to only ever send its own ID. There is no second check comparing the `id` in the URL against the identity derived from the session. Changing `1057` to `1056` or `1058` returns a different user's account because the underlying query has no `WHERE owner = current_session_user` clause — only `WHERE id = <whatever the client sent>`.

**Exploitation in practice:** because the IDs are sequential, an attacker doesn't need to guess — they enumerate. In Burp, this means sending the request to **Intruder**, marking `id` as the payload position, and sweeping a numeric range. Each response is compared for differing account data, confirming the lack of an authorization check at scale rather than for a single victim.

## 3. Direct References Using Non-Sequential / GUID Identifiers

Some applications anticipate the sequential-ID problem and switch to a GUID (e.g. `7c9e6679-7425-40de-944b-e07fc1f90ae7`) so the value can't be guessed or brute-forced in a reasonable timeframe.

**Why this is not actually a fix:** the underlying flaw — no server-side ownership check — is unchanged. The GUID only raises the cost of *finding* a valid identifier; it does nothing once one is found. GUIDs leak constantly through:

- Other users' public profile pages, comments, or reviews that embed their own object IDs in visible HTML or in API responses.
- Notification emails or webhooks that include the GUID in a link.
- Client-side JavaScript or JSON responses that include sibling objects' IDs (e.g. a "related documents" list that discloses GUIDs the current user shouldn't be able to open directly).

### Piece-by-piece breakdown of exploitation

```
GET /api/documents/7c9e6679-7425-40de-944b-e07fc1f90ae7 HTTP/1.1
Cookie: session=<attacker session>
```

- The GUID itself was harvested from a different, *legitimately accessible* response (e.g. a public comment thread that displays `documentId` in its JSON payload for a different reason — like letting the comment link back to the source document).
- The request above isn't guessing; it's reusing a leaked, real reference. The check that's missing is identical to the sequential-ID case: the server resolves the GUID to a row and returns it without asking "does the current session own this row?"
- **Takeaway for testing:** never dismiss GUID/UUID-based systems as "not vulnerable to IDOR" — the question is always *can a valid foreign ID be obtained*, not *can it be brute-forced*.

## 4. IDOR via Static File / Object Storage References

A second IDOR sub-category targets static resources — uploaded files, exported reports, chat transcripts, invoices — referenced by predictable filenames rather than database rows.

```
GET /download-transcript/3.txt HTTP/1.1
Host: insecure-website.com
Cookie: session=<wiener's session token>
```

### Piece-by-piece breakdown

- `/download-transcript/3.txt` — the file is fetched purely by an incrementing numeric filename. There is no per-file access-control list checked against the session.
- `Cookie: session=...` is again present but unused for authorization — it identifies the requester, but the file-serving logic just opens whatever path the URL resolves to.
- **Exploitation:** sweep the numeric portion with Intruder (`1.txt`, `2.txt`, `3.txt`, …) and inspect each response for sensitive content (e.g. a support chat transcript in which a victim discloses their password to a support agent who asked for "confirmation"). This is a direct illustration of why even "low value" exposed objects (chat logs) can cascade into full account compromise.

## 5. IDOR with Data Leakage via Redirect

Some applications correctly detect that the requesting user shouldn't see a given object and issue a `3xx` redirect back to a login or "access denied" page — but the **original response body still contains the sensitive data** before or alongside the redirect, because the redirect was added as an afterthought rather than the access-control logic gating the data fetch itself.

### Piece-by-piece breakdown

```
GET /user/profile?id=2362 HTTP/1.1
Cookie: session=<low-privilege session>

HTTP/1.1 302 Found
Location: /login
Set-Cookie: ...
<html>...victim's full profile, including email and password reset token, embedded in the body...</html>
```

- The `302 Found` and `Location: /login` headers look, at a glance, like the access control worked — a normal browser would simply follow the redirect and never show the user the body.
- The body of the same HTTP response, however, was **already rendered with the victim's data** before the redirect instruction was attached. The access-control check ran too late: after the data was fetched and serialized, not before.
- **Exploitation:** intercept the raw response in Burp (or with `curl -v`/`curl -i`) instead of letting a browser auto-follow the redirect, and read the body directly. This is a frequent finding in apps that bolt access control onto an existing rendering pipeline rather than gating the data layer itself.

## 6. Blind / Confirmatory IDOR (No Data Returned, but Action Still Executes)

Not every IDOR returns visible data. Some only let you **perform an action** on someone else's object — change a setting, delete a record, mark something as read — even though the response gives no direct read access. This is sometimes called a "blind" IDOR or an action-based IDOR.

```
POST /api/notifications/4471/mark-read HTTP/1.1
Cookie: session=<attacker session>

{"read": true}
```

- `4471` is another user's notification ID, obtained from timing/enumeration or leaked elsewhere.
- The response might just be `{"status":"ok"}` with no victim data disclosed — but the side effect (their notification state changed, or worse, a record was deleted) is still a real, provable impact.
- **Why this matters for reporting:** when documenting IDOR findings professionally, don't limit testing to `GET` requests that leak data. Test every `POST`/`PUT`/`PATCH`/`DELETE` endpoint that accepts an object ID, because write-IDOR is often rated more severely than read-IDOR (data integrity and availability impact, not just confidentiality).

## 7. Practical Methodology for Finding IDOR

1. Map every endpoint that takes an identifier — in the path, a query string, a JSON body field, or a header.
2. For each one, capture two authenticated sessions for two different low-privilege accounts (e.g. PortSwigger's `wiener` and `carlos`).
3. Take a request that legitimately belongs to account A, and replay it using account B's session/cookie, unmodified except for swapping in account A's object ID.
4. If the response returns account A's data (or successfully performs the action) while authenticated as B, the endpoint has no ownership check — this is exactly what tools like Autorize automate at scale (see file 7).

## 8. Real-World Notes

- IDOR is rated by OWASP and CWE under **CWE-639: Authorization Bypass Through User-Controlled Key** — this is the formal name worth knowing for report-writing.
- In mobile and API-first products, IDOR is *more* common than in traditional web apps, because mobile clients frequently pass raw database IDs to "thin" backend APIs that skip ownership checks the web UI happens to enforce elsewhere.
- GraphQL APIs introduce their own IDOR variant: a single query can request multiple object types by ID in one call, multiplying the number of objects an attacker can probe per request.
