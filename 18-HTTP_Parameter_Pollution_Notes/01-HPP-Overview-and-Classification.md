# 01 — HTTP Parameter Pollution: Overview and Classification

## 1. What HTTP Parameter Pollution actually is

HTTP allows the exact same parameter name to appear more than once in a single request —
in a query string, in a URL-encoded body, or in multipart form data. Nothing in the HTTP
specification says what a server should do when this happens. Each web server, each
application framework, each WAF, and each parsing library independently decided its own
answer decades ago, and those answers do not agree with each other.

HTTP Parameter Pollution (HPP) is the technique family built around **exploiting the gap
between two layers that parse the same duplicated parameter differently.**

Example of the raw primitive, nothing more:

```
GET /transfer?amount=10&amount=99999 HTTP/1.1
```

Two layers looking at this same request can legitimately produce two different values for
`amount`. Whether that disagreement is dangerous depends entirely on *which two layers*
disagree and *what each of them does* with the value they extracted. That "which two layers"
question is exactly what splits HPP into three sub-classes.

## 2. The three sub-classes of HPP — and why they get confused

PortSwigger's own Web Security Academy explicitly flags this naming collision, and it's worth
being precise about it before going further, because mixing these up is the single most common
source of confusion in write-ups across the industry.

| Sub-class | Where the disagreement happens | What attacker controls | Covered in file |
|---|---|---|---|
| **Client-side HPP** | Server embeds user input into a URL on a page; browser/JS on that page then parses the resulting URL differently than the server intended | A link or form the victim's browser will follow | Touched on in `02` (filter bypass overlap) |
| **WAF / filter-bypass HPP** | WAF or input filter parses duplicate parameters one way (e.g., inspects only the first value); application server parses them another way (e.g., uses the last value) | Which value the security control "sees" vs. which value the application actually executes | `02-HPP-WAF-and-Filter-Bypass.md` |
| **Server-side parameter pollution (SSPP)** | Application takes user input and unsafely re-embeds it into a *second*, server-to-server request (often to an internal API); the user's duplicate/encoded parameter injects a sibling parameter into that internal request | A new parameter or path segment inside a backend request the user was never supposed to reach directly | `04-HPP-Server-Side-Parameter-Pollution-Downstream-APIs.md` |
| **Business logic HPP** | Not a separate parsing layer — this is sub-class 2 and 3's *consequence* when the duplicated parameter controls something with monetary or authorization value (price, quantity, role, discount code) rather than something purely technical | Which of two submitted values for a sensitive field "wins" | `03-HPP-Business-Logic-Manipulation.md` |

PortSwigger Academy deliberately uses "server-side parameter pollution" as the formal name for
the third row specifically *because* "HTTP parameter pollution" colloquially gets used for the
WAF-bypass technique elsewhere in the industry, and they wanted to avoid the ambiguity. This
series keeps that same separation, but treats all of these as one technique *family* because
they all stem from the identical root cause: inconsistent duplicate-parameter parsing.

## 3. The parsing table — how each backend technology actually handles `?id=1&id=2`

This table is the backbone of the entire series. Every exploitation file refers back to it by
name. The behavior shown is each technology's **default** behavior; frameworks can override it,
but defaults are what you'll meet in the wild unless a developer specifically changed them.

| Technology / Stack | Result of `?id=1&id=2` | Behavior name |
|---|---|---|
| **ASP.NET / ASP Classic** (IIS) | `1,2` — all values comma-joined into a single string | **All, comma-joined** |
| **PHP** (`$_GET`, `$_POST`) | `2` — last value wins, unless `id[]=1&id[]=2` syntax is used, which produces an array of both | **Last value wins** (array syntax = all) |
| **Node.js / Express** (`req.query` default `qs` parser) | `['1','2']` — returns an array of both values | **All, as array** |
| **Python / Flask** (`request.args`) | `1` — first value wins via `.get()`; `.getlist()` returns both | **First value wins** (explicit method = all) |
| **Python / Django** (`request.GET`) | `2` — last value wins via direct indexing; `.getlist()` returns both | **Last value wins** (explicit method = all) |
| **Java / Apache Tomcat & most servlet containers** | `1` — first value wins via `getParameter()`; `getParameterValues()` returns both | **First value wins** (explicit method = all) |
| **Perl (CGI.pm)** | `1,2` joined, or array depending on call (`param()` vs `param()` in list context) | **Context-dependent** |
| **Ruby on Rails (Rack)** | `2` — last value wins for scalar params; `id[]=` syntax for arrays | **Last value wins** |
| **Apache HTTP Server** (as reverse proxy / mod_rewrite matching) | Typically forwards all instances unchanged to the backend; doesn't itself "resolve" the duplicate | **Passes through unresolved** |
| **Nginx** (as reverse proxy) | Same — passes all duplicate instances through to the upstream untouched by default | **Passes through unresolved** |
| **Many WAF / security-appliance default rule sets** | Inspect only the **first** occurrence of a parameter name for signature matching | **First value inspected** |

### Why this table is the entire vulnerability

Notice the pattern: front-line components that exist purely to *route or filter* traffic
(Nginx, Apache as a proxy, most WAFs) tend to either pass duplicates through untouched or only
inspect the first one. Meanwhile, the actual application logic behind them resolves duplicates
according to its own framework default — which is very often *not* "first value." That mismatch
between "what the filter checked" and "what the app executed" is precisely the WAF-bypass
sub-class. When that same mismatch instead exists between two *application-layer* components
(your app vs. an internal API it calls), you get server-side parameter pollution instead.

## 4. Real-world framing: why this still matters in 2026

This isn't a 2010s-era curiosity. The exact same root cause shows up today in:

- **API gateways in front of microservices** — the gateway and the downstream service almost
  never share a parameter-parsing library, so duplicate-parameter behavior frequently differs
  between them, especially in polyglot stacks (Go gateway in front of a Node service, for
  example).
- **CDN/WAF layers (Cloudflare, AWS WAF, Akamai) in front of mixed-language backends** — these
  products ship sensible defaults, but default rule sets commonly only examine the first
  parameter instance, which is exactly the gap exploited in file `02`.
- **OAuth and SSO flows** — PortSwigger's own OAuth authentication vulnerabilities material
  explicitly recommends testing `redirect_uri` for duplicate-parameter handling, since
  authorization servers and client applications are typically built by entirely different
  teams using entirely different stacks.
- **Checkout and pricing microservices** — price/discount calculation is frequently split
  across a cart service and a pricing service; if either one resolves duplicate `price` or
  `discount_code` parameters differently than the other expects, business logic HPP results
  (file `03`).

## 5. Detection mindset for this whole series

Every technique in this series starts from the same three questions, applied to a single
parameter:

1. **Does the front-line component (WAF, CDN, reverse proxy) treat a duplicated version of
   this parameter differently than a single instance of it?**
2. **Does the back-end resolve duplicates the same way the front-line component assumes it
   does?** (Check this against the parsing table above — what stack is the backend on?)
3. **If those two answers differ, does the parameter control something a filter checks, a
   business rule trusts, or a second downstream request reuses unsafely?**

Files `02`, `03`, and `04` are each one specific, fully worked-out answer to question 3.
