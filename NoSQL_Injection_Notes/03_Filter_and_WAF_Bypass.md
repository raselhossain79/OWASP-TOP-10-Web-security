# NoSQL Injection — Filter and WAF Bypass

This file assumes the basic techniques from `02_Exploitation_Techniques.md` got blocked, stripped, or sanitized in some way. Every bypass below explains *what the filter is likely doing* and *why the bypass defeats that specific logic* — not just "try this instead."

---

## 1. Understand What You're Actually Bypassing

Before throwing bypass payloads at a wall, identify which of these defensive layers you're up against, because the bypass strategy is completely different for each:

1. **Key-stripping sanitizer** — middleware that recursively walks the parsed request body/query and deletes any object key starting with `$` (common libraries: `mongo-sanitize`, `express-mongo-sanitize`).
2. **Type enforcement** — application code (or schema validation, e.g., Mongoose schemas, Joi/Zod validators) that rejects the request outright if a field isn't a primitive string/number.
3. **WAF/regex-based filtering** — a network-layer or middleware-layer regex blocklist looking for literal strings like `$where`, `$ne`, `{$`, etc. in the raw request body.
4. **Operator allowlisting** — the most robust defense: explicitly permitting only certain operators (or none) on certain fields.

Test which one you're facing by submitting a harmless probe and watching *how* it fails: a 400 with a validation error message points to type enforcement; a request that silently "just doesn't work" (operator seems stripped, not rejected) points to key-stripping; an outright connection drop or generic 403 from an edge device points to a WAF.

---

## 2. Bypassing Key-Stripping Sanitizers (`$`-prefix removal)

### 2.1 Why this filter exists and how it usually works

Libraries like `express-mongo-sanitize` recursively scan `req.body`, `req.query`, and `req.params`, and delete (or rename) any key that starts with `$` or contains a `.` (dot notation is also dangerous — it can be used to target nested fields). This neutralizes the textbook `{"$ne": "..."}` payload by deleting the `$ne` key entirely before the object reaches your application's database call.

### 2.2 Bypass: target an unsanitized input path

The single most reliable bypass in real engagements: **the sanitizer is often only wired into one middleware position, not every parsing path.** Common gaps:
- Sanitizer applied to `req.body` but not `req.query` (or vice versa) — submit the operator via the *other* path:
  ```
  GET /login?username[$ne]=invalid&password[$ne]=invalid
  ```
- Sanitizer applied globally but the vulnerable route is registered *before* the sanitizer middleware in the Express middleware chain (middleware order matters — anything before `app.use(mongoSanitize())` in the chain never gets sanitized).
- Sanitizer applied to top-level keys only, not deeply nested ones, in custom/home-rolled sanitization code — wrap your operator one level deeper than the sanitizer's recursion depth, if you can identify or infer that depth from error behavior.
- Multipart/form-data bodies, file upload metadata fields, or alternate content types that bypass the JSON-body-specific sanitizer entirely.

### 2.3 Bypass: case and encoding tricks against naive string-match stripping

Some home-rolled sanitizers do a literal string `.replace('$', '')` or a regex like `/^\$/` against keys, rather than using a battle-tested library. Test:
- **Unicode look-alike characters**: some MongoDB driver/BSON parsers historically had quirks around how dollar-prefixed keys were validated depending on encoding — this is increasingly patched, but worth a quick test against custom (non-library) filters.
- **Double-encoding the key in URL-based bracket notation**: `username[%24ne]=invalid` (`%24` is URL-encoded `$`). If the framework's query-string parser URL-decodes *before* your sanitizer runs but the sanitizer's regex check happens to run on the raw (still-encoded) string for some reason, this can slip through. This is inconsistent across stacks — always verify empirically rather than assuming.
- **Nested operator wrapping**: if the sanitizer only strips top-level `$`-prefixed keys and doesn't recurse into arrays, try wrapping inside `$or`/`$and` arrays (if those particular operators weren't stripped) to smuggle a second-level operator past a shallow recursive check:
  ```json
  {"username": {"$or": [{"$ne": "invalid"}]}}
  ```
  This only works if the sanitizer's recursion has a bug/gap — test empirically, don't assume.

---

## 3. Bypassing Type Enforcement

### 3.1 The defense

```javascript
if (typeof req.body.password !== 'string') {
  return res.status(400).send('Invalid input');
}
```
This is the **correct, robust fix** for operator injection — and when implemented properly on every field, it genuinely closes the hole. Don't expect a clean bypass here; instead, look for **coverage gaps**:

### 3.2 Bypass: fields the developer forgot

Type checks are almost always written by hand, field by field, which means coverage is frequently incomplete. Systematically re-test **every** parameter on **every** endpoint, not just the obviously security-critical login fields:
- Search/filter parameters (`?category=...`, `?sort=...`)
- Pagination parameters that get passed into a query filter object
- "Remember me" tokens, password-reset tokens, API key lookup fields
- Any parameter that feeds into a `findOne()`/`find()`/`update()`/`deleteOne()` call — update and delete operations are just as exploitable as reads, and are checked far less often by developers and testers alike

### 3.3 Bypass: nested object fields

A type check on the top-level field doesn't protect nested fields inside it if the application later destructures or merges the object further down the call stack:
```json
{"filter": {"category": {"$ne": null}}}
```
If `typeof req.body.filter === 'object'` is accepted as valid (because `filter` is *supposed* to be an object containing multiple search criteria), but the inner `category` value isn't independently type-checked before being merged into the actual database query, the operator survives. This is a common gap in apps with "flexible filter" or "advanced search" features that intentionally accept structured query objects from the client — a feature that is inherently dangerous unless every leaf value is strictly validated.

---

## 4. Bypassing Regex/WAF Blocklists

### 4.1 The defense

A WAF or middleware regex scanning raw request bodies for patterns like `\$where`, `\$ne`, `\$regex`, or generally `\$[a-z]+` before the request reaches the application.

### 4.2 Bypass: operator variety the blocklist didn't anticipate

Blocklists are enumerable and therefore always incomplete. If `$ne` and `$regex` are blocked, try less commonly-blocklisted operators that achieve similar outcomes:
- `$gt: ""` — "greater than empty string" — true for almost any non-empty string value, achieving a similar always-true effect to `$ne` for many practical purposes.
- `$exists: true` — matches if the field exists at all, regardless of value — useful for confirming field presence and, in some logic flows, for bypassing checks that only verify a field was supplied.
- `$nin` (not in array) as an alternative shape to `$ne`/`$in`.
- `$where` alternatives explained in §7 of File 02 (`mapReduce()`) if `$where` specifically is blocklisted but JS evaluation elsewhere isn't.

### 4.3 Bypass: whitespace, casing, and JSON structure obfuscation

Many regex blocklists are written against a specific expected formatting and miss structurally-equivalent variants:
- Extra whitespace inside the JSON: `{"password": { "$ne" : "invalid" }}` — a naive regex like `\{"?\$ne"?:` (no internal whitespace tolerance) can miss this.
- Key order doesn't matter to MongoDB but might matter to a positional regex — test reordering keys.
- Unicode-escaped JSON keys: `{"password": {"\u0024ne": "invalid"}}` — `\u0024` is the JSON Unicode escape for `$`. A compliant JSON parser decodes this to a literal `$` before your application ever sees it, but a WAF inspecting the raw byte stream for a literal `$` character may not normalize Unicode escapes before matching, letting the payload through the network-layer filter while still parsing correctly as `$ne` once it reaches the application's JSON parser.

### 4.4 Bypass: splitting the payload across the request

If the WAF inspects the body as a whole but the application reconstructs query logic from multiple separate parameters server-side, test whether you can spread an effective operator injection across fields the WAF evaluates independently and doesn't correlate (this is highly application-specific and requires understanding the backend's query-building logic — usually inferred through behavioral testing rather than source review in a black-box assessment).

---

## 5. Bypassing Operator Allowlisting

This is the strongest defense (explicitly permitting only a small set of safe operators, e.g., only allowing `$eq` on specific fields). Direct bypass is often not possible if implemented correctly. Your approach shifts from "defeat the filter" to "find the field/endpoint where the allowlist wasn't applied":

- Test administrative/internal API endpoints separately from public-facing ones — allowlisting is often only applied to the public auth flow and forgotten on internal admin search/reporting endpoints.
- Test GraphQL resolvers and REST endpoints serving the *same underlying data* — it's common for one interface to have the hardened filter and a parallel legacy interface to lack it entirely.
- Check API versioning — `/api/v1/login` may have the fix; `/api/v2/login` (or vice versa) may not, especially right after a security patch that didn't get backported.

---

## 6. Null Byte and Comment-Style Truncation (Syntax Injection Context)

For syntax-injection contexts specifically (not operator injection), a null byte can truncate the rest of a concatenated query if the underlying JS-evaluation engine stops processing at the null character:

```
https://target.com/product/lookup?category=fizzy'%00
```

Mechanism: this becomes, server-side, something like `this.category == 'fizzy'\u0000' && this.released == 1`. If MongoDB's JS evaluation context ignores everything after the embedded null character, the trailing `&& this.released == 1` restriction (which filters out unreleased/hidden products) never gets evaluated, and the query effectively becomes just `this.category == 'fizzy'`, returning all matching products regardless of release status. This specifically defeats applications that append additional security-relevant conditions (release flags, ownership checks, soft-delete flags) onto a query *after* the user-controlled portion — a pattern worth specifically hunting for, since "append a security check after the user's filter" is a common but fragile design.

---

## 7. General Bypass Methodology When Nothing Above Works

1. **Differential testing**: send the same logical payload through every available input path (JSON body, query string bracket notation, form-encoded body, headers if applicable) — defenses are rarely applied with perfect consistency across all of them.
2. **Error-message archaeology**: a verbose 500 error (even a generic one) versus a clean 400 validation error tells you whether you're hitting type-validation (clean 400, structured message) or something failing deeper in actual query execution (500, often less filtered).
3. **Operator substitution sweep**: maintain a working list of operators (`$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$in`, `$nin`, `$exists`, `$regex`, `$where`, `$or`, `$and`, `$expr`) and sweep through all of them systematically rather than giving up after one or two are blocked — blocklists are very rarely complete.
4. **Re-test after time**: WAF rules and sanitization libraries get updated; a payload blocked today during a long-running engagement may not be blocked next week if a deployment rolled back a security middleware version, or vice versa — don't assume a single negative test result is permanent across a multi-day assessment.

Continue to `04_NoSQLMap_Automation_Tool.md` to automate discovery and exploitation of these patterns at scale.
