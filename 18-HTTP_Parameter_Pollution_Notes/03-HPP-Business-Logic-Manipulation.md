# 03 — HPP for Business Logic Manipulation

## 1. The core mechanism

Business logic HPP is not a different parsing trick from files `01`/`02` — it's the same
duplicate-parameter primitive, pointed at a parameter that controls **money, quantity,
authorization level, or a discount/coupon rule** instead of something purely technical like a
search string. The vulnerability condition is the same one from the parsing table in file `01`:
two components in the request path resolve the same duplicated parameter to two different
values. The only thing that changes here is the *blast radius* — instead of a reflected script
tag, you get an order placed at the wrong price.

## 2. Pattern A — price override via mismatched first/last resolution between cart and pricing logic

**Scenario:** An e-commerce checkout submits a price parameter that the front-end JavaScript
calculated, as a defense-in-depth measure the server is supposed to re-validate it against the
catalog — but the re-validation code and the order-creation code read the parameter through two
different access methods.

**Request:**

```
POST /checkout/confirm HTTP/1.1
Host: shop.example
Content-Type: application/x-www-form-urlencoded

product_id=8841&price=499.00&price=4.99&quantity=1
```

**Breakdown:**

- `product_id=8841` — identifies the item; not duplicated, not part of the attack.
- `price=499.00` — first instance, the genuine catalog price.
- `price=4.99` — second instance, the attacker's intended price.
- **Why this works:** suppose the validation step (a fraud-check or price-sanity middleware)
  is written in Java using `request.getParameter("price")`, which per the parsing table in
  file `01` returns the **first** value — `499.00`. That passes validation cleanly; nothing
  looks suspicious. But the actual order-creation code, deeper in the stack, might be a
  different service — say a Node.js order microservice using `req.query.price` through a
  parser that, depending on configuration, resolves to the **last** value, or even simply uses
  `req.body.price` after an upstream proxy step that itself only forwards the last duplicate.
  Whichever value the order-creation code resolves to is the price actually charged. If that
  resolution disagrees with the validation step's resolution, the fraud check approved a price
  that was never the price actually billed.
- **The generalizable rule:** any time price/quantity validation and price/quantity persistence
  happen in *different code paths, different services, or different frameworks*, this pattern
  is worth testing — because "different code paths" almost always means "different default
  duplicate-parameter resolution," per the parsing table.

## 3. Pattern B — quantity/discount stacking via array-style duplication

**Scenario:** A coupon-application endpoint built on Node.js/Express, where `req.query`
resolves duplicates into an **array** (per the parsing table), and a downstream discount-
calculation function naively iterates that array and sums every discount it finds, instead of
applying only one.

**Request:**

```
GET /cart/apply-discount?code=WELCOME10&code=WELCOME10&code=WELCOME10 HTTP/1.1
```

**Breakdown:**

- Three identical instances of `code=WELCOME10`.
- Express's default query parser (`qs`) resolves `req.query.code` to
  `['WELCOME10', 'WELCOME10', 'WELCOME10']` — an array of three entries, exactly per the
  "Node.js/Express → all, as array" row in file `01`'s parsing table.
- If the discount-calculation code does something naive like:
  ```js
  let total = 0;
  for (const c of req.query.code) {
    total += getDiscountValue(c); // no dedup, no single-use enforcement
  }
  ```
  then a single-use 10% coupon gets applied three times, because the developer assumed
  `req.query.code` would always be a single string (the shape it has in the overwhelming
  majority of legitimate requests) and never coded a guard for the array case the framework
  silently supports.
- **Why this is a business logic bug and not a parsing bug per se:** the framework did exactly
  what it documents. The vulnerability is entirely in application code that didn't anticipate
  the documented behavior of its own framework's duplicate-parameter handling — which is the
  most common real-world manifestation of this entire technique family.

## 4. Pattern C — role/permission override via inconsistent duplicate resolution across auth middleware vs. handler

**Scenario:** An internal admin panel where authentication middleware checks a `role` parameter
using one access method, and the route handler that actually executes the privileged action
reads `role` using a different one.

**Request:**

```
POST /admin/users/promote HTTP/1.1
Host: internal.example

target_user=carlos&role=support&role=superadmin
```

**Breakdown:**

- `role=support` — first instance. If the authorization middleware is built in a stack that
  resolves duplicates as **first value wins** (Flask `.get()`, Java servlets — per the parsing
  table), the middleware sees `support`, decides this is a low-privilege role change, and
  allows the request through without requiring extra approval/MFA that a `superadmin`
  promotion would normally trigger.
- `role=superadmin` — second instance. If the handler that actually performs the database
  write uses a different access pattern — explicit `.getlist()`/`getParameterValues()` taking
  the last element, or simply a different framework layer downstream that resolves duplicates
  as **last value wins** — the privilege actually granted is `superadmin`, not the `support`
  role the security gate approved.
- This is the same parsing-mismatch mechanism as Pattern A, applied to an authorization
  decision instead of a price.

## 5. Why this sub-class is specifically dangerous in microservice architectures

Business logic HPP gets *more* likely, not less, as systems modernize into microservices,
because:

- Validation and execution are now frequently **different services**, often written in
  **different languages**, by **different teams**, with **different default frameworks** —
  exactly the condition the parsing table in file `01` says produces divergent duplicate-
  parameter resolution.
- API gateways frequently strip, rewrite, or partially normalize query strings before
  forwarding — but "partially" is the operative word; gateways rarely guarantee full
  normalization of every duplicate key across every backend they route to.
- Mass-assignment-style parameter binding (mentioned in PortSwigger's own API testing material)
  compounds this: frameworks that auto-bind request parameters to object fields can silently
  accept whichever duplicate value the binder's internal resolution order favors, without any
  explicit code ever calling it out.

## 6. PortSwigger Web Security Academy lab coverage for this sub-class

**Honest disclosure:** there is no PortSwigger Academy lab that targets price, quantity, or role
override specifically *through duplicate parameters*. The Academy's business-logic-vulnerability
topic covers price/quantity manipulation extensively, but through other mechanisms (negative
quantities, race conditions, client-side validation bypass, integer overflow) — not via HPP.
Likewise, the Academy's **access control** topic covers role/privilege escalation, but again not
specifically via duplicate-parameter precedence mismatches.

This is a genuine coverage gap in the Academy relative to this specific technique, and it's
worth being direct about it: business logic HPP is something you will only get real practice on
through actual bug bounty targets or engagement work, or by deliberately building a small local
test harness that mimics the validation/execution split described in Pattern A above. If you
want a starting point for that kind of self-built lab, a two-service local setup (a Flask
"validation" service in front of an Express "order" service, both reading the same duplicated
`price` parameter) reproduces Pattern A exactly and is a reasonable weekend project to internalize
the mechanism hands-on.

## 7. Real-world note

This category of bug is consistently among the highest-paying bug bounty findings in retail/
e-commerce programs specifically because the financial impact is trivial for a triager to
verify (an attacker placed a real order at a price that doesn't exist in the catalog) and
because it requires zero special tooling beyond Burp Repeater — which makes it a favorite
technique among bounty hunters working e-commerce-heavy programs.
