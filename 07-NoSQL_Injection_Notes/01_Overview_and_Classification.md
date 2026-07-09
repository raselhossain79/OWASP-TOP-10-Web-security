# NoSQL Injection — Overview and Classification

**OWASP Category:** A03:2021 - Injection
**Primary target database for this series:** MongoDB (most widely deployed NoSQL database in production web apps)
**Academy reference:** https://portswigger.net/web-security/nosql-injection

---

## 1. Why NoSQL Injection Is a Different Animal From SQLi

This is the single most important mental shift to make before touching a single payload. If you carry over SQLi instincts unchanged, you will misdiagnose half of what you see.

### 1.1 SQLi recap (the baseline you already know)

In SQL injection, user input gets concatenated into a **string-based query language** with fixed, universal syntax:

```sql
SELECT * FROM users WHERE username = '$input' AND password = '$pass'
```

Every database (MySQL, PostgreSQL, MSSQL, Oracle) speaks dialects of the same SQL standard. A `'`, a `--`, a `UNION SELECT` — these all exploit the fact that the backend is parsing a **textual query string**, and you're injecting characters that escape the intended string literal and inject new SQL grammar.

### 1.2 What changes in NoSQL

MongoDB (and most NoSQL databases) do **not** build queries by parsing a string of database-specific syntax. Instead, the application constructs a **query object** — typically a JSON/BSON document — and passes that object directly to a driver function.

A normal MongoDB login lookup, conceptually, looks like this in the application's backend code:

```javascript
db.users.findOne({ username: username, password: password })
```

There is no SQL grammar here at all. `username` and `password` are just JavaScript/JSON keys whose values come straight from user input. The "injection" isn't about breaking string syntax to add new grammar — it's about **substituting a different data type or structure** for a value the application expected to be a plain string.

This is the core conceptual difference:

| | SQL Injection | NoSQL Injection (operator-based) |
|---|---|---|
| What you inject | Characters that escape a string literal and add new SQL grammar | A JSON object/operator that replaces an expected scalar value |
| Why it works | The query is built by string concatenation, then parsed as SQL text | The query is built as a data structure; the driver blindly trusts the *type* and *shape* of the input |
| Example exploit | `' OR '1'='1` | `{"$ne": "invalid"}` submitted where a plain string was expected |
| Underlying flaw | Lack of parameterization / improper escaping | Lack of type enforcement and lack of an operator allowlist |

If you remember nothing else from this file, remember this: **SQLi breaks syntax to inject new commands. Operator-based NoSQLi doesn't break syntax at all — it abuses the fact that the application accepts attacker-controlled *structure* (objects, arrays, operators) where it expected a simple string.** That's why classic SQLi detection methods (looking for SQL error messages, trying `UNION SELECT`) are frequently useless against MongoDB targets, and why you need a different detection methodology entirely (covered in File 02).

There is a second category — **syntax injection** — that *does* resemble SQLi mechanically (breaking out of a string context inside a server-side JavaScript expression). Both categories exist in MongoDB applications and are covered separately below.

### 1.3 Why this matters in real engagements

In real-world assessments, NoSQL backends show up constantly in:
- Node.js/Express + MongoDB stacks (the MEAN/MERN stack is extremely common)
- Modern SPA backends using Mongoose as an ODM
- Microservices using MongoDB for session storage, user profiles, or product catalogs
- Mobile app backends (Firebase/Firestore, MongoDB Atlas) where the client sends structured JSON directly

A huge number of real bug bounty NoSQLi findings come from APIs that accept raw JSON bodies and pass fields almost directly into Mongoose `.find()` or `.findOne()` calls without an explicit schema-level type check. This is not a theoretical lab-only bug class — it is one of the most common high-impact authentication bypasses found in modern JSON-API pentests, precisely because developers trust "if it came from `req.body.password`, it must be a string" — and that assumption is false unless explicitly enforced.

---

## 2. NoSQL Database Models (Why MongoDB Specifically)

NoSQL is an umbrella term covering several distinct data models, each with very different injection surfaces:

| Model | Examples | Query Mechanism |
|---|---|---|
| Document store | **MongoDB**, CouchDB | JSON/BSON objects, operators (`$ne`, `$where`, etc.) |
| Key-value store | Redis, DynamoDB | Mostly key lookups; injection surface is narrower |
| Wide-column store | Cassandra | CQL (Cassandra Query Language) — actually closer to SQL syntax injection |
| Graph database | Neo4j | Cypher query language — its own syntax-injection class (similar shape to SQLi) |

MongoDB dominates real-world web app usage among these, which is why this note series — and the PortSwigger Web Security Academy's NoSQL injection module — focuses on it almost exclusively. The concepts (operator abuse, JS evaluation contexts, type confusion) generalize to other document stores, but the specific operator names (`$ne`, `$where`, `$regex`) are MongoDB's query language (MQL).

---

## 3. The Two Fundamental Types of NoSQL Injection

PortSwigger's Academy formally splits NoSQL injection into two categories. Keep this classification in your head throughout this entire series — every technique in File 02 falls into one of these two buckets.

### 3.1 Syntax Injection

**Definition:** You break the syntax of a query that is built by *string concatenation* into a context that MongoDB evaluates as JavaScript (most commonly inside a `$where` clause or similar JS-evaluation context). This is mechanically closest to classic SQLi — you're injecting characters to escape a string literal and append new logic.

**Why it exists at all in a "schemaless JSON" database:** Some application code paths still build a partial query as a string before handing it to MongoDB's JavaScript evaluation engine, e.g.:

```javascript
db.products.find({ $where: "this.category == '" + category + "'" })
```

Here `category` is concatenated directly into a string that MongoDB will execute as JavaScript. This is structurally identical to classic SQLi — and just as exploitable with quote-breaking and boolean-logic injection.

**Detection fuzz string** (from PortSwigger, designed to trip multiple possible escape contexts at once):

```
'"`{
;$Foo}
$Foo \xYZ
```

Mechanism breakdown of this fuzz string — each fragment targets a different possible escape context:
- `'` and `` ` `` — closes single-quote or backtick string literals (JS allows both)
- `"` — closes double-quote string literals
- `{` and `}` — attempts to break out of a JSON object literal context
- `;` — terminates a JavaScript statement, in case the input lands inside a `$where` JS body
- `$Foo` — tests whether a bare `$`-prefixed token is parsed as a (nonexistent) operator/variable, which can surface a distinct error class
- `\xYZ` — an invalid escape sequence, included to trip up any naive regex-based input sanitizer that doesn't validate escape sequences strictly
- Embedded newlines — tests whether the input is reflected into a context where newlines have syntactic meaning (e.g., terminating a single-line JS statement)

You send each character individually in follow-up requests once you get an anomalous response, to isolate exactly *which* character broke the query (covered in depth, with full payload walkthroughs, in File 02).

### 3.2 Operator Injection

**Definition:** You submit MongoDB query operators (`$ne`, `$gt`, `$regex`, `$in`, `$where`, etc.) as **structured JSON values** in place of the plain string the application expected. No string-breaking is involved — this exploits a type-confusion / missing-allowlist flaw, not a parsing flaw.

Example — the application expects:

```json
{"username": "wiener", "password": "peter"}
```

You instead submit:

```json
{"username": "wiener", "password": {"$ne": "invalid"}}
```

The `password` field, instead of being the string `"peter"`, is now an **object** containing the `$ne` ("not equal") operator. If the backend code does something like:

```javascript
db.users.findOne({ username: req.body.username, password: req.body.password })
```

MongoDB's query engine sees `password: {$ne: "invalid"}` and happily interprets it as "match any document where password is not equal to the string `invalid`" — which is true for essentially every real password. No syntax was broken. The application's own JSON-parsing pipeline delivered the operator straight into the query object because nothing validated that `password` must be a primitive string before reaching the database call.

This is the dominant, most common, and most *real-world-relevant* category of NoSQL injection. It's covered exhaustively, operator by operator, in File 02.

---

## 4. Where Injection Points Show Up

NoSQL operator injection isn't limited to JSON request bodies. Be alert for it in:

- **JSON POST bodies** — the most direct case: `{"username": {...}}`
- **URL query parameters using bracket notation** — many frameworks (Express + `qs`/`body-parser`, PHP) auto-parse `username[$ne]=invalid` into a nested object `{username: {$ne: "invalid"}}` *before the application code ever runs*. This means operator injection can be performed without ever touching the Content-Type or sending raw JSON — a plain GET request can trigger it.
- **Form-encoded bodies** that get parsed into nested structures the same way
- **GraphQL resolvers** that pass arguments straight into a Mongoose query
- **Headers and cookies** that get parsed as JSON and merged into a filter object (less common, but seen in custom auth middleware)

Real-world pentest note: always test both the JSON-body path *and* the bracket-notation query-string path for every parameter, because some frameworks/validation middleware only sanitize one of the two input-parsing paths and forget the other — `username[$ne]=x` getting through a filter that only checks `req.body` for object types is a recurring real bug pattern.

---

## 5. Impact Categories

NoSQL injection, when successfully exploited, can lead to:

1. **Authentication bypass** — operator injection on login fields (File 02, §2)
2. **Data extraction / exfiltration** — blind boolean or JS-based character-by-character extraction (File 02, §3–4)
3. **Denial of service** — abusing `$where` or `mapReduce()` with expensive/infinite JS loops to exhaust server CPU
4. **Server-side code execution** — in older or misconfigured MongoDB deployments, `$where`/`mapReduce()` JS execution can sometimes be escalated further depending on server config (rare in modern hardened deployments, but historically significant — `server-side JS execution` was disabled by default starting MongoDB 4.4 for this exact reason)

---

## 6. PortSwigger Academy Lab Map for This Topic (Full Sequence)

The Academy's NoSQL injection learning path, in the exact order it is presented (confirmed against the live Academy structure as of this writing):

| Order | Lab | Difficulty | Maps to |
|---|---|---|---|
| 1 | Detecting NoSQL injection | Apprentice | File 02, §1 (Syntax injection detection) |
| 2 | Exploiting NoSQL operator injection to bypass authentication | Apprentice | File 02, §2 (Operator injection — auth bypass) |
| 3 | Exploiting NoSQL injection to extract data | Practitioner | File 02, §3 (Syntax/JS injection — data extraction) |
| 4 | Exploiting NoSQL operator injection to extract unknown fields | Practitioner | File 02, §4 (Operator injection — blind field/data extraction) |

Do them in this order. Each one builds a prerequisite skill for the next — you cannot efficiently solve lab 4 without the field-enumeration logic you build in lab 3, and you cannot reliably solve lab 2 without the detection instinct from lab 1.

---

## 7. What's Next

- **File 02 — Exploitation Techniques**: full payload-by-payload breakdown of every technique above, mapped to the labs in §6, including blind/boolean extraction, `$where`/`mapReduce()` JS injection, and timing-based blind injection.
- **File 03 — Filter and WAF Bypass**: what to do when `$`, `{`, `}`, or specific operators get stripped or blocked.
- **File 04 — NoSQLMap**: automating discovery and exploitation, and an honest comparison against sqlmap's maturity.
- **File 05 — Cheatsheet**: fast lookup table for live engagements.
