# 01 — CORS Overview and Classification

## 1. What Problem CORS Was Built to Solve

Before CORS existed, browsers enforced the **Same-Origin Policy (SOP)**: a script
running on `https://a.com` could not read the response of a request made to
`https://b.com`. SOP doesn't stop the *request* from being sent — it stops the
*response* from being readable by the calling page's JavaScript. This single fact
is the foundation of nearly every CORS bug, so it's worth stating precisely:

> SOP and CORS are about whether **JavaScript on the requesting page can read the
> response**, not about whether the request itself reaches the server.

A plain `<form>` POST or an `<img src="...">` request still fires cross-origin with
no restriction at all — that's the basis of CSRF. CORS exists because the modern
web legitimately needs cross-origin *reading* sometimes: a frontend on
`app.example.com` calling an API on `api.example.com`, a third-party widget calling
its own backend, a SPA calling a separate auth service. CORS is the mechanism that
lets a server explicitly say "this other origin is allowed to read my response."

The critical design fact that makes CORS exploitable: **CORS is enforced entirely
client-side, by the browser, based on headers the server sends.** The server has
to actively decide, per request, what to put in those headers. If the server's
decision logic is sloppy, the browser will faithfully enforce a policy that is
wrong — and hand a stranger's JavaScript your authenticated data.

## 2. What "Origin" Actually Means

An origin is the triplet: **scheme + host + port**. Two URLs are same-origin only
if all three match exactly.

```
https://example.com:443/page1   and   https://example.com:443/page2
```
Same origin (path is irrelevant).

```
https://example.com   vs   http://example.com     -> different (scheme)
https://example.com   vs   https://api.example.com -> different (host)
https://example.com   vs   https://example.com:8443 -> different (port)
```

This matters because every misconfiguration technique in file `02` is, at root,
a server failing to correctly check one of these three components before trusting
an `Origin` value.

## 3. The Core Header Pair (and Why Both Matter Together)

### `Access-Control-Allow-Origin` (response header, set by server)

Tells the browser which origin is allowed to read the response. Two legitimate
forms exist:

- `Access-Control-Allow-Origin: *` — any origin may read the response, but **only
  for non-credentialed requests** (no cookies, no `Authorization` header sent with
  the request, and the browser will not expose cookies on the response either).
- `Access-Control-Allow-Origin: https://specific-trusted-origin.com` — that exact
  origin, and only that origin, may read the response.

There is no such thing as a legitimate multi-value wildcard like
`Access-Control-Allow-Origin: https://*.example.com` — the spec does not support
wildcard subdomains in this header. If a server appears to allow arbitrary
subdomains, it's doing so through application logic that reflects/echoes a value
it received, not through native wildcard syntax. That distinction matters for
diagnosis, covered in file `02`.

### `Access-Control-Allow-Credentials` (response header, set by server)

Tells the browser that it's safe to expose the response **and to have sent
cookies/HTTP auth with the request in the first place** for credentialed
cross-origin calls (i.e., requests made with `fetch(url, {credentials: 'include'})`
or `XMLHttpRequest.withCredentials = true`).

```
Access-Control-Allow-Credentials: true
```

This is the header that turns a CORS misconfiguration from "mildly annoying" into
"full account takeover via session theft." Without it, even a fully wildcarded
`Access-Control-Allow-Origin: *` only exposes whatever an unauthenticated visitor
could already see by browsing the site directly — there's no session to steal.
**`Access-Control-Allow-Credentials: true` is the header that makes the attack
worth building.**

### The Spec Rule That Misconfigurations Routinely Violate

Per the Fetch/CORS specification, a server is **not allowed** to combine
`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.
Browsers enforce this: if both are literally present together, modern browsers
will refuse to expose the response. This is exactly why vulnerable applications
don't actually send `*` — they reflect the literal `Origin` value from the
request back into `Access-Control-Allow-Origin`, producing a response that looks
to the developer like "wildcard behavior" while staying spec-legal and credential
-bearing. That reflection behavior is the single most common real-world CORS
misconfiguration and is covered in depth in file `02`, section 1.

### Supporting Headers (set during preflight)

- `Access-Control-Allow-Methods` — which HTTP methods (`GET`, `POST`, `PUT`,
  `DELETE`, etc.) the actual request is allowed to use.
- `Access-Control-Allow-Headers` — which custom request headers (e.g.
  `X-Custom-Auth`) the actual request is allowed to send.
- `Access-Control-Max-Age` — how long (in seconds) the browser may cache the
  preflight result before asking again.
- `Vary: Origin` — tells caches (CDNs, reverse proxies) that the response content
  differs depending on the `Origin` request header, so a cached response for one
  origin must not be served to another. Its **absence** in a reflection-based
  setup is itself a secondary issue: shared caches can serve one attacker's
  CORS-approved response to a different visitor.

## 4. Simple Requests vs Preflighted Requests

The browser decides whether to send a "preflight" — an `OPTIONS` request asking
permission before the real request — based on the real request's method and
headers.

**Simple request** (no preflight) conditions, ALL must hold:
- Method is `GET`, `HEAD`, or `POST`
- Only "simple" headers are set (`Accept`, `Accept-Language`,
  `Content-Language`, `Content-Type` limited to
  `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`)
- No `ReadableStream` body, no custom headers like `Authorization` or
  `X-Requested-With`

If all conditions hold, the browser sends the real request directly and just
checks the response's `Access-Control-Allow-Origin` (and `-Credentials` if
applicable) before deciding whether JavaScript may read the response.

**Preflighted request**: anything that doesn't qualify as simple — most JSON APIs
(`Content-Type: application/json`), anything sending `Authorization`, any method
other than GET/HEAD/POST — triggers an `OPTIONS` preflight first. The browser
asks "if I sent this real request, would it be allowed?" via the
`Access-Control-Request-Method` and `Access-Control-Request-Headers` request
headers, and only proceeds to send the real request if the server's `OPTIONS`
response approves it.

**Why this matters offensively:** a simple `GET /accountDetails` request to a
JSON-returning endpoint that doesn't require custom headers is often a *simple*
request — no preflight required, attacker JS can fire it directly with one
`XMLHttpRequest`/`fetch` call. This is exactly why `/accountDetails`-style
endpoints are the canonical CORS PoC target in every Academy lab: they're
GET, credentialed, and unpreflighted.

## 5. Classification of CORS Misconfiguration Patterns

Every real-world CORS bug reduces to one of these five root causes. File `02`
covers each in full exploitation depth; this section establishes the taxonomy.

| # | Pattern | Root Cause | Severity Driver |
|---|---|---|---|
| 1 | **Origin reflection** | Server echoes whatever `Origin` header it received, verbatim, into `Access-Control-Allow-Origin` | Combined with `Allow-Credentials: true`, any site can read any authenticated response |
| 2 | **Null origin trust** | Server explicitly allows the literal string `Origin: null` | Attacker can produce a `null` origin from a sandboxed iframe or a local file context, with no need to control a domain |
| 3 | **Wildcard + credentials misconfiguration** | Server combines `*` semantics with credentialed responses, usually via reflection rather than literal `*` (since literal `*`+credentials is browser-blocked) | Functionally identical end state to #1, but worth distinguishing because some frameworks expose this via a misconfigured CORS *library default* rather than custom code |
| 4 | **Overly broad / unvalidated subdomain or domain-suffix trust** | Server checks only that the `Origin` *contains* or *ends with* the trusted domain string, instead of exact-matching a real subdomain | Any subdomain — including ones vulnerable to XSS, takeover, or attacker-controlled content — becomes a trusted origin |
| 5 | **Trusted insecure protocol / internal network trust** | Server trusts a domain or IP range regardless of scheme (HTTP as well as HTTPS) or trusts internal/private IP ranges | Enables MITM-style or SSRF-adjacent pivoting; internal trust can be abused for internal network reconnaissance and pivot attacks |

A sixth, non-technique-specific point worth flagging here because it gets missed
constantly during real assessments: **CORS misconfiguration is not a vulnerability
unless the response actually contains something the attacker shouldn't otherwise
be able to read.** A CORS-permissive endpoint that returns a generic, public, or
otherwise unauthenticated payload is a finding (because the configuration itself
is bad practice and risks future regressions), but it is not a sev-critical
account-takeover the way the same misconfiguration is when paired with
`/accountDetails`, `/api/me`, `/api-keys`, or similar session-bound endpoints.

## 6. Real-World Framing

In production systems, CORS misconfigurations almost never look like the
textbook examples — they show up as side effects of how teams actually build
APIs:

- **Microservice / multi-tenant SaaS platforms** frequently need to allow many
  customer-controlled subdomains (`tenant1.app.com`, `tenant2.app.com`, ...) to
  call a shared API. Rather than maintain an explicit allowlist, engineers reach
  for regex-based origin validation — and a single overly loose regex
  (`.*\.app\.com$` without anchoring the scheme, or a regex that doesn't escape
  the dot) becomes pattern #4 or #5 above.
- **CORS middleware defaults.** Several popular web framework CORS libraries
  ship with a permissive "reflect any origin" mode meant for local development,
  and it occasionally ships to production unchanged. This is pattern #1/#3 and
  is one of the single most commonly reported CORS findings in bug bounty
  programs, precisely because it's a config default rather than custom code —
  it tends to recur across many of a company's services if one team copies
  another's boilerplate.
- **Internal tooling exposed at the edge.** Internal dashboards and admin panels
  sometimes get a CORS policy that trusts `*.internal.company.com` or private IP
  ranges for convenience during development, and that trust survives into
  production deployment behind a reverse proxy that's reachable from the
  internet. This is pattern #5 and is the basis of the most advanced lab in this
  series (internal network pivot).
- **Single-page application auth flows.** SPA architectures that split the
  frontend (`app.example.com`) from an API/auth backend (`api.example.com`)
  legitimately need CORS. Misconfiguration here is high-impact because the
  credentialed endpoint is usually the session/profile endpoint itself.

The next file, `02-CORS-Exploitation-Techniques.md`, walks through detecting and
exploiting each of these five patterns individually, with the exact request and
response headers you should look for at each step.
