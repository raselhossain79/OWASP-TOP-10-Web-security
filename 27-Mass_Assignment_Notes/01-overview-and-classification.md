# 01 — Overview and Classification

## 1. What Mass Assignment Actually Is

Mass assignment (also called **auto-binding** or **over-posting**) is not a flaw in
a single function — it is a *side effect of a convenience feature*. Most modern web
frameworks let a developer write something like:

```ruby
# Rails
@user = User.new(params[:user])
@user.save
```

```python
# Django REST Framework
serializer = UserSerializer(data=request.data)
serializer.save()
```

```java
// Spring Boot
@PostMapping("/users")
public User createUser(@RequestBody User user) {
    return userRepository.save(user);
}
```

```php
// Laravel
$user = User::create($request->all());
```

In every one of these examples, the framework takes the **entire incoming
request body** and maps each key in the JSON/form data directly onto a matching
property of the internal object (`User`, `UserSerializer`, etc.), then persists
that object. This is what "auto-binding" means: the framework automatically
*assigns* values to *mass* (all, or unfiltered) properties of the object, hence
**mass assignment**.

The vulnerability appears the moment that internal object has **any property that
should not be directly settable by the client**, such as:

- `isAdmin`, `role`, `permissions`, `isVerified`
- `accountBalance`, `creditLimit`, `discountPercentage`
- `userId`, `ownerId` (when used to reassign ownership of a resource)
- `createdAt`, `approvedBy` (audit/integrity fields)

If the developer did not explicitly restrict which fields the binder is allowed to
touch, the client can add any of these keys to the request body and the ORM/binder
will write them straight into the database — no business logic, no authorization
check, no validation layer is necessarily involved at all.

## 2. Why This Happens: The Mechanism

The root mechanism is always the same shape, regardless of language or framework:

1. The framework receives a request body (JSON, form-encoded, multipart).
2. A **binder/serializer/deserializer** component reflects over the incoming keys
   and matches them against the properties or columns of a target model class.
3. For every key that matches a property name, the binder calls the corresponding
   setter (or assigns the attribute directly via reflection).
4. The object is persisted (ORM `save()`/`create()`/`update()`).

The vulnerability exists because step 2 is **permissive by default** in many
frameworks and ORMs — they are designed to reduce boilerplate, not to enforce a
security boundary. Security only enters the picture when the developer explicitly
adds an allow-list (Rails strong parameters, DRF explicit serializer fields,
Spring DTOs, Laravel `$fillable`). If that allow-list step is skipped, forgotten on
one model, or implemented as a deny-list instead of an allow-list, the endpoint is
exploitable.

This is the same trust-boundary failure pattern seen in classic web vulnerabilities:
SQL injection happens because user input crosses into the query-construction layer
unfiltered; mass assignment happens because user input crosses into the
object-construction layer unfiltered.

## 3. Classification

### 3.1 CWE Mapping

- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object
  Attributes — the precise CWE for this class.
- Related: **CWE-862** (Missing Authorization) and **CWE-863** (Incorrect
  Authorization), since the *impact* of mass assignment is almost always an
  authorization bypass.

### 3.2 OWASP Mapping

- **OWASP API Security Top 10 (2023): API3:2023 — Broken Object Property Level
  Authorization**, which explicitly merged the older "Excessive Data Exposure" and
  "Mass Assignment" categories from the 2019 list into a single property-level
  authorization issue: the API fails to enforce which object properties a given
  client is allowed to read or write.
- **OWASP Top 10 (web, general)**: falls under **A01:2021 — Broken Access Control**
  when viewed from the web application perspective, since the impact is unauthorized
  modification of object state.

### 3.3 Where It Differs From Adjacent Vulnerabilities

It's worth being precise about boundaries, since these get confused in writeups:

| Vulnerability | What's being abused |
|---|---|
| **Mass assignment** | Extra/unexpected *properties* bound onto an object during create/update |
| **IDOR** | A *valid* parameter (e.g. `id`) referencing a resource the user shouldn't access |
| **Hidden/undocumented parameters** | Parameters not shown in the UI, but not necessarily auto-bound to an object (could be a feature flag read directly in code) |
| **Server-side parameter pollution** | Duplicate/injected parameters altering an internal API request, often unrelated to object binding |

Mass assignment frequently **overlaps** with hidden parameter discovery (the hidden
parameter you find often turns out to be auto-bound), and can **combine** with IDOR
(injecting `userId` or `ownerId` to reassign a resource is mass assignment used to
achieve an IDOR-like effect). These distinctions matter for accurate bug bounty
report classification.

## 4. Where It Commonly Appears

Mass assignment is overwhelmingly a problem in **API-backed, ORM-driven
applications**, because:

- ORMs make object-to-database mapping nearly free, which encourages developers to
  pass entire request payloads straight into the ORM constructor/update call.
- REST/JSON APIs expose model structure more directly than traditional server-rendered
  HTML forms, where only the fields actually rendered in the form get submitted.
- Frameworks evolve allow-list mechanisms (strong params, fillable, DTOs) as
  **opt-in** features, not defaults, so legacy code and rushed endpoints frequently
  skip them.

Typical hotspots:

- **User registration / profile update endpoints** (`POST /api/users`,
  `PATCH /api/users/{id}`) — classic target for injecting `role` or `isAdmin`.
- **E-commerce checkout/cart endpoints** — injecting `price`, `discount`, or
  `chosen_discount` fields (this is exactly the PortSwigger Academy lab scenario).
- **Internal admin panels exposed via the same API as the public app** — if the
  admin and user models share a serializer, the public endpoint may accidentally
  accept admin-only fields.
- **Multi-tenant SaaS applications** — injecting `tenantId`/`organizationId` to
  cross tenant boundaries.

## 5. Real-World Industry Framing

Mass assignment is not a theoretical lab issue — it has a long disclosed history:

- The 2012 **GitHub public key mass assignment incident** is the canonical
  industry example: a researcher demonstrated that GitHub's Rails-based API allowed
  adding an SSH public key to *any* user's account by including a `public_key`
  parameter that was unintentionally mass-assignable, due to a strong-parameters
  gap. This incident is widely credited with pushing Rails toward making strong
  parameters effectively mandatory in framework defaults from Rails 4 onward.
- Mass assignment is consistently listed in API security vendor reports (e.g.
  Salt Security, Wallarm API threat reports) as a top-five cause of API-specific
  privilege escalation findings in production environments, because API endpoints
  are tested far less thoroughly than browser-rendered forms — the "hidden"
  property never appears in any UI for a manual tester to notice.
- It is a recurring category in HackerOne and Bugcrowd public disclosures under
  labels like "Privilege Escalation via Mass Assignment" or "Improper Access
  Control — API3:2023," frequently paid as Critical/High severity when it leads to
  admin takeover.

## 6. Summary

Mass assignment is what happens when convenience (auto-binding request data to
objects) is implemented without a corresponding allow-list boundary. It is a
property-level authorization failure, classified today under OWASP API3:2023, and
it is most exploitable in REST/JSON APIs backed by ORMs where the entire object
graph — including internal-only fields — can be reached through a single bound
input. The remaining files in this series cover how to *find* these bindable
hidden fields (`02`), how to *exploit* them for privilege escalation (`03`), how
the binding mechanism differs across major frameworks (`04`), and a consolidated
quick-reference (`05`).
