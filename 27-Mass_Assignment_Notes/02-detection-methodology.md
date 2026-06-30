# 02 — Detection Methodology

Mass assignment is fundamentally invisible from the UI — by definition, the
exploitable field is never rendered on a form. Detection is therefore a recon
problem: you are trying to reconstruct the **full shape of the internal object**
from whatever signals the API leaks, then testing whether each undocumented field
is bindable.

## 1. Core Technique: Diffing What the API Returns Against What the UI Sends

This is the single most reliable technique for finding mass assignment candidates,
and it's the exact technique the PortSwigger Academy lab is built around.

### 1.1 The Logic

A typical object lifecycle looks like this:

1. The client performs a `GET` request to fetch a resource (e.g. a user profile, a
   checkout summary, a product).
2. The server's `GET` response is built by **serializing the entire internal
   object** — every column/property on the model — because it's convenient for the
   backend developer to just return `user.to_json()` rather than hand-pick fields.
3. The client's corresponding `POST`/`PUT`/`PATCH` request, by contrast, is built by
   the **front-end form**, which only includes the fields a human is meant to edit.

That asymmetry is the signal. The `GET` response is a leak of the object's true
schema; the `POST`/`PATCH` request is an artificially narrowed subset of it.

### 1.2 Step-by-Step Workflow

1. Authenticate as a normal/low-privilege user and proxy all traffic through Burp.
2. Locate a `GET` (or any read) request that returns a JSON representation of the
   target object — profile fetch, checkout summary, cart contents, order details.
3. Send it to Repeater. Record every key in the response body, including nested
   objects.
4. Locate the corresponding write request (`POST register`, `PATCH update`, the
   checkout submission) and record every key in **that** body.
5. **Diff the two key sets.** Any key present in the `GET` response but absent from
   the write request body is a candidate hidden field.
6. For each candidate, add it to the write request body with an attacker-favorable
   value and resend.
7. Observe the response and, if possible, re-fetch the object with `GET` to confirm
   whether the value was actually persisted (not just accepted) — this proves
   binding, not just lack of a 400 error.

### 1.3 Worked Example (matches the PortSwigger Academy lab scenario)

`GET /api/checkout` response:

```json
{
  "chosen_discount": { "percentage": 0 },
  "chosen_products": [
    { "product_id": "1", "name": "Lightweight \"l33t\" Leather Jacket", "quantity": 1, "item_price": 133700 }
  ]
}
```

The legitimate `POST /api/checkout` request the front-end actually sends:

```json
{
  "chosen_products": [
    { "product_id": "1", "quantity": 1 }
  ]
}
```

**Diff:** `chosen_discount.percentage` exists in the `GET` response but is never
sent by the front-end in the `POST` body. That asymmetry is the detection signal —
it tells you the `chosen_discount` object exists on the server-side model and is a
candidate for client-side injection, which is confirmed in the exploitation phase
(see `03-exploitation-privilege-escalation.md`).

## 2. Automated/Semi-Automated Discovery When No GET Leak Exists

Not every endpoint conveniently leaks its full schema via `GET`. When the object
isn't readable, or the readable version is already filtered, fall back to brute
discovery:

### 2.1 Burp Intruder — Parameter Name Brute-Forcing

- Take a known-good write request (e.g. `POST /api/register`).
- Add a new JSON key with a placeholder value and mark it as the Intruder payload
  position: `"§param§": true`.
- Load a wordlist of common sensitive property names (see
  `05-cheatsheet.md` for the starter wordlist: `isAdmin`, `role`, `admin`,
  `is_staff`, `permissions`, `verified`, `accountType`, etc.).
- Run a Sniper attack and sort by response length/status code. A response that
  differs from the baseline (different length, different status, or a follow-up
  `GET` showing the value persisted) indicates the field is bound.

### 2.2 Param Miner (Burp BApp)

Param Miner automates the same idea at scale — it can guess up to 65,536 parameter
names per request using built-in wordlists plus terms scraped from the
application's own JS/HTML. For JSON body mass assignment specifically:

- Configure Param Miner to target the body (not just query string/headers).
- Run "Guess JSON parameters" against the candidate write endpoint.
- Cross-reference any discovered parameter against the object you're trying to
  escalate (user, order, account) rather than treating every hit as exploitable —
  Param Miner finds *accepted* parameters, not necessarily *security-impactful*
  ones; you still need to manually assess impact.

### 2.3 API Documentation / Schema Leakage

ORMs and API frameworks frequently auto-generate documentation (Swagger/OpenAPI,
DRF's browsable API, GraphQL introspection) that documents the **full** model
schema, including admin-only fields, because the documentation generator reflects
over the same model class the binder uses. If you can reach:

- `/api/docs`, `/swagger.json`, `/openapi.json`, `/api-docs`
- A framework's auto-browsable API root (Django REST Framework exposes this by
  default in `DEBUG` or unauthenticated-misconfigured environments)

...read the full field list directly rather than inferring it from diffing. This is
the same instinct used in the API Testing topic's "Exploiting an API endpoint using
documentation" technique — exposed documentation is a direct source of the object's
true property list, removing the guesswork.

### 2.4 Client-Side Source Review

Front-end JavaScript bundles often contain the full model interface even if the
rendered form doesn't show every field — for example, a TypeScript interface
compiled into the bundle, or a disabled/hidden form field stripped by CSS but still
present in the DOM/JS. Search bundled JS for the object's class name (`User`,
`Account`, `Order`) and grep for property assignments.

## 3. Confirming Binding vs. Confirming Impact

Two distinct checks matter, and conflating them produces false positives/negatives
in reports:

- **Binding confirmed**: the server accepted the field without error and a
  subsequent `GET` shows the value was actually written to the object. This proves
  mass assignment exists.
- **Impact confirmed**: the bound field has a security-relevant effect — it
  elevates privilege, bypasses payment logic, or crosses a tenant/ownership
  boundary. This is what determines severity for a report.

A field can be bindable but harmless (e.g. a cosmetic `displayName` field bound
without restriction is not a vulnerability worth reporting on its own). Always
chain detection into the exploitation workflow in `03` before treating a finding as
reportable.

## 4. Tooling Summary

| Tool | Role in detection |
|---|---|
| Burp Proxy/Repeater | Manual diffing of GET vs write request bodies |
| Burp Intruder | Brute-force candidate field names into the write request |
| Param Miner (BApp) | Automated large-scale JSON parameter guessing |
| Autorize (BApp) | Useful as a follow-up — confirms whether a low-privilege session can write fields meant for higher-privilege roles |
| Browser DevTools / bundled JS | Reveals model fields referenced in front-end code but not rendered in the form |
| Swagger/OpenAPI/DRF browsable API | Direct schema leak when documentation is exposed |

## 5. Real-World Note

In production bug bounty engagements, the GET/write diffing technique (Section 1)
accounts for the overwhelming majority of real mass assignment findings, because
most APIs are built with a "return everything, accept only what the form sends"
pattern by default — it's less work for the backend developer than hand-curating
both directions. Security teams that adopt **schema-first API design** (defining
request/response schemas explicitly and validating both directions against them,
e.g. via OpenAPI-driven codegen) close this gap structurally rather than relying on
manual review per endpoint.
