# 02 — HPP for WAF and Filter Bypass

## 1. The core mechanism

This sub-class exploits exactly one gap from the parsing table in file `01`: **the security
control (WAF, input filter, sanitization layer) and the application server resolve a duplicated
parameter to two different values.** The attacker crafts a request where:

- The value the **filter inspects** looks clean.
- The value the **application executes** is malicious.

This is a desynchronization attack at the parameter level — conceptually the same family of bug
as HTTP request smuggling, just one layer up the stack (parameter values instead of
request boundaries).

## 2. Pattern A — "poison value first, real payload second" (defeats first-value-wins filters)

**Target profile:** A WAF or filter that only inspects the *first* occurrence of a parameter
name (a common default rule-set behavior — see the parsing table in file `01`), sitting in
front of an application server that resolves duplicates as **last value wins** (PHP, Django,
Rails — see same table).

**Request:**

```
GET /search?q=hello&q=<script>alert(1)</script> HTTP/1.1
Host: vulnerable-app.example
```

**Breakdown, parameter by parameter:**

- `q=hello` — the **first** `q` parameter. This is the value the WAF's signature engine reads,
  because the WAF is only checking the first instance of any duplicated key. `hello` contains
  no attack syntax, so the WAF's signature match fails to trigger and the request is forwarded.
- `q=<script>alert(1)</script>` — the **second** `q` parameter. The WAF never inspected this
  value. If the backend is, say, a PHP application (last-value-wins per the parsing table),
  `$_GET['q']` resolves to this second value — the payload — and that's what gets reflected
  into the page or used in application logic.
- **Why this works:** the WAF's "first value" assumption and PHP's "last value wins" default
  are simply two unrelated decisions made by two unrelated engineering teams. The attacker
  isn't breaking either parser — both parsers are working exactly as designed. The
  vulnerability lives entirely in the *gap* between the two designs.

## 3. Pattern B — fragmenting a blocked keyword across duplicate parameters

**Target profile:** A filter that performs string matching against the **concatenated** value
of all instances of a parameter (some WAFs do this — comma-join the duplicates before
inspection, mirroring ASP.NET's native behavior), but the backend evaluates only one specific
instance directly.

**Request:**

```
POST /api/update HTTP/1.1
Host: vulnerable-app.example
Content-Type: application/x-www-form-urlencoded

role=user&role=admin
```

**Breakdown:**

- `role=user` — first instance. If the backend is built on a framework that resolves duplicates
  as **first value wins** (Flask via `.get()`, Java servlets via `getParameter()` — see parsing
  table), a permissive logging/audit filter that only checks the first instance sees `user` and
  passes it as benign.
- `role=admin` — second instance, never inspected by a first-value filter.
- The actual exploit direction here depends on which value the **business logic** resolves to.
  This pattern bridges directly into file `03` (business logic manipulation) — the WAF-bypass
  framing and the business-logic framing are often the same request; they just describe
  different *consequences* of identical duplicate-parameter behavior. This is intentional and
  is the most important conceptual overlap in the whole series.

## 4. Pattern C — exploiting comma-join behavior against array-unaware filters

**Target profile:** ASP.NET / IIS backend (comma-joins all values per the parsing table) behind
a filter written to validate a single scalar value with a strict allowlist regex.

**Request:**

```
GET /products?category=electronics&category=1%3bDROP+TABLE+products HTTP/1.1
```

**Breakdown:**

- `category=electronics` — first instance. A naive filter that grabs `Request.QueryString["category"]`
  *might* be doing exactly what the application does (ASP.NET comma-joins everything under that
  key into one string) — but if the filter instead pulls the value from a different access
  point or library that returns only the first instance, it sees `electronics`, validates it
  against an allowlist of category names, and lets it through.
- `category=1;DROP TABLE products` — second instance.
- Because ASP.NET's native `Request.QueryString["category"]` behavior is **comma-join all
  values**, the application layer that actually uses this parameter (for example, feeding it
  into a dynamically built SQL `IN (...)` clause) receives `electronics,1;DROP TABLE products`
  — the full polluted string, including the part the filter never independently validated.
- **Why this matters specifically for ASP.NET:** comma-joining is unique to this stack among
  the technologies in the parsing table. Any allowlist-style filter that assumes "one parameter
  name = one value" breaks specifically on ASP.NET targets in a way it would not break on, say,
  a Flask target (which would simply drop everything after the first value at the filter layer
  *and* the app layer alike, with no extra string getting through).

## 5. Why WAF vendors' default rule sets are structurally exposed to this

Modern WAF products (cloud and on-prem alike) commonly ship signature rules written against a
single canonical value per parameter name, for performance reasons — comma-joining or array-
expanding every duplicated parameter before running every signature against every value is
expensive at scale, so "check the first occurrence" is a common pragmatic default. This is not
a flaw unique to one vendor; it is a direct, structural consequence of the parsing-inconsistency
root cause described in file `01`. Penetration testers should treat **"does this WAF inspect
duplicate parameters the same way the origin server resolves them?"** as a standing test case
for every parameter on every engagement that has a WAF or CDN-layer security product in front
of the target, regardless of vendor.

## 6. PortSwigger Web Security Academy lab coverage for this sub-class

**Honest disclosure:** PortSwigger Web Security Academy does **not** have a dedicated,
standalone lab for the classic "duplicate parameter bypasses a WAF/filter" technique shown in
this file. The Academy's own documentation explicitly notes that the term "HTTP parameter
pollution" is sometimes used in the wider security industry for exactly this WAF-bypass
technique, but the Academy chose to scope its own labs to **server-side parameter pollution**
instead (covered fully in file `04`, with two real, working labs).

This gap is consistent with the Academy's general design philosophy — they build interactive
labs around server state changes that can be programmatically verified (you either deleted
`carlos` or you didn't), and classic WAF-bypass HPP is inherently a property of a filter
sitting *in front of* a lab, which the Academy's lab architecture doesn't model. If you want
hands-on practice specifically for the patterns in this file, that practice has to come from a
real engagement, a personal lab setup (e.g., a basic WAF like ModSecurity's OWASP Core Rule Set
in front of a deliberately mismatched backend), or bug bounty programs that publish a known WAF
vendor in scope.

## 7. Real-world note

This exact technique — duplicate parameters to bypass first-occurrence WAF inspection — is one
of the oldest documented HPP techniques in the industry, going back to early-2010s research, and
it remains relevant precisely because WAF rule-engine performance trade-offs haven't
fundamentally changed. It is a standard item on most professional web-app pentest methodology
checklists (including OWASP's own WSTG, under input validation testing) specifically *because*
it costs almost nothing to test for and the underlying architectural gap is still present in
many production WAF deployments today.
