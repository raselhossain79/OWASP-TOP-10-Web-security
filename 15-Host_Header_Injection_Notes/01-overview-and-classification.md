# Host Header Injection — Overview and Classification

## 1. What the Host header actually is

Since HTTP/1.1, the `Host` header is mandatory on every request. It tells the receiving
server which website the client thinks it is talking to:

```
GET /account HTTP/1.1
Host: example.com
```

This exists because a single physical server (or a single IP address) can host many
different websites — a setup called **virtual hosting**. The web server uses the `Host`
value to decide which application, document root, or backend to route the request to.

In the simplest possible deployment (one server, one site, no proxy, no CDN), the `Host`
header is harmless — there's nothing else for it to confuse. The vulnerability class only
exists because **real-world architecture is almost never that simple**. Production stacks
typically look like:

```
Client -> CDN/WAF -> Load Balancer -> Reverse Proxy -> Application Server -> Backend services
```

Every one of those hops can read, trust, rewrite, or forward the `Host` header differently.
The vulnerability arises from **disagreement** between components about what the "real"
host is, or from the application **trusting client-supplied data to build URLs, route
requests, or make security decisions.**

This is why Host header attacks are not really one bug — they're a *category* of bugs that
all stem from the same root cause: **the Host header is attacker-controlled input, but many
systems treat it as trusted configuration.**

## 2. Why this is a high-value real-world finding

In bug bounty and pentest work, Host header issues are attractive because:

- They are **server-side**, often with no required user interaction (unlike most XSS).
- They frequently chain into **account takeover** (via password reset poisoning) or
  **internal network access** (via routing-based SSRF) — both of which are usually
  rated High/Critical on bounty platforms.
- They are common in microservice and cloud-native environments, where load balancers,
  API gateways, and reverse proxies (NGINX, HAProxy, AWS ALB, Cloudflare, Varnish) are
  layered on top of frameworks (Django, Laravel, Express, Spring) that each have their
  own opinion about which header to trust for "the current domain."
- Many frameworks build absolute URLs (password reset links, OAuth redirect URLs,
  password-reset emails, canonical links, password-reset confirmation pages) using
  `request.host` or equivalent — a single line of insecure framework code can expose
  the entire application.
- They are frequently missed by automated scanners because the vulnerable behavior often
  only manifests in a **side channel** (an email sent to a victim, a cached response
  served to someone else) rather than in the direct HTTP response to the attacker.

## 3. The trust model that breaks

Almost every Host header vulnerability reduces to one of these three trust failures:

1. **The application uses the Host header (or a similar header) to construct a URL or
   make a routing/security decision, without validating it against a known-good list.**
2. **Different components in the request path disagree about which header value is
   authoritative**, creating an ambiguous request that can be interpreted two different
   ways by two different systems (the basis of cache poisoning and request smuggling
   style attacks).
3. **A "trust forwarding" header (`X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`,
   `Forwarded`) designed for legitimate proxy use is accepted from the client directly**,
   even when no real proxy is in front of the application, or even when a proxy *is*
   present but fails to strip/overwrite the header before forwarding it.

## 4. Classification of Host header attack types

This series covers the following categories. Each is explored in depth in its own file,
but here's the map:

| Category | Mechanism | Typical impact | Covered in |
|---|---|---|---|
| Password reset poisoning | Host header controls the domain embedded in a password reset link sent by email | Account takeover | File 02 |
| Web cache poisoning via Host header | Ambiguous/duplicate Host headers cause cache and app to disagree on what was requested | Stored XSS / DoS served to all visitors | File 01 (this file) + File 04 lab mapping |
| Routing-based SSRF | Host header is used by an internal load balancer/proxy to pick the backend | Access to internal-only services/admin panels | File 03 |
| SSRF via flawed request-line parsing | Absolute-URI request line is trusted over Host header by a misconfigured proxy | Same as above, different bypass vector | File 03 |
| Host header authentication bypass | App grants elevated trust (e.g., "local"/admin access) based on Host value | Auth/access-control bypass | File 01 (this file) |
| Virtual host brute-forcing | Internal/hidden vhosts respond to a guessed Host value on a public IP | Internal recon, access to hidden apps | File 01 (this file) |
| Connection-state attacks | Server only validates Host on the *first* request of a reused connection | Bypass of Host validation entirely | File 01 (this file) |
| X-Forwarded-Host / X-Host / Forwarded trust issues | App prefers a forwarding header over Host, attacker supplies it directly | Same outcomes as Host injection, often with weaker validation | File 03 |
| X-Forwarded-For trust issues | App treats client-supplied "original IP" as ground truth for access control, rate limiting, or logging | IP allowlist bypass, rate-limit bypass, log poisoning | File 03 |

The first two rows above plus authentication bypass, vhost brute-forcing, and connection
state attacks are covered in this file because they share the same testing methodology.
Password reset poisoning and SSRF/header-trust issues get dedicated files because of their
depth and chain complexity.

## 5. Detection methodology (how you actually find this in the field)

This is the step-by-step process used in real engagements, not just lab solving:

### Step 1 — Confirm you can alter the Host header without breaking the request

```
GET / HTTP/1.1
Host: totally-unexpected-value.invalid
```

**What's happening:** you are testing whether the front-most component (CDN, load
balancer, or the app itself if there's nothing in front) actually inspects and validates
the Host value before routing your request anywhere.

**Why it matters:** three possible outcomes tell you three different things:
- **Connection refused / "Invalid Host header"** → the app or a WAF is validating Host
  against an allowlist. Move to Step 2 (bypass attempts) rather than giving up.
- **You still reach the real site** (it ignored your Host value and used a default/first
  vhost) → flawed validation, worth probing further for reflection.
- **You reach a *different* site or get a routing error indicating an internal hostname**
  → strong signal of a multi-tenant or internally-routed backend worth investigating for
  vhost brute-forcing or routing-based SSRF.

### Step 2 — Bypass flawed validation if direct injection is blocked

If raw Host injection is blocked, the validation logic itself often has gaps. Real-world
validation bugs include:

**a) Port-field smuggling** — some parsers strip everything after the last `:` as a port
and never validate *that* substring:

```
GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here
```
*Breakdown:* the validator sees `vulnerable-website.com` (the domain it expects) and is
satisfied. Anything after the colon, intended to be a numeric port, is parsed separately
and may be passed straight into a header, a log line, or a backend connection string
without being checked at all — your `bad-stuff-here` rides along unvalidated.

**b) Suffix-matching exploitation** — some checks just confirm the Host *ends with* the
expected domain:

```
GET /example HTTP/1.1
Host: notvulnerable-website.com
```
*Breakdown:* if the developer wrote a check like `host.endsWith("vulnerable-website.com")`
intending to allow subdomains, registering `notvulnerable-website.com` (which legitimately
ends in that exact string) passes the check even though it is a completely different,
attacker-owned domain.

**c) Compromised/weak subdomain reuse:**

```
GET /example HTTP/1.1
Host: hacked-subdomain.vulnerable-website.com
```
*Breakdown:* if `*.vulnerable-website.com` is allowlisted wholesale, any subdomain the
attacker controls or has compromised (an abandoned dev environment, a misconfigured S3
bucket with a CNAME, a forgotten staging app) satisfies the allowlist while pointing
attacker-controlled content at the trusted origin.

### Step 3 — Send ambiguous requests to expose component disagreement

The validating code path and the vulnerable code path frequently live in *different*
systems. If you can make those two systems disagree about what the Host actually is, you
can satisfy the validator while smuggling a payload to the vulnerable component.

**Duplicate Host headers:**
```
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```
*Breakdown:* a browser will never send two `Host` headers, so this scenario is frequently
unhandled. If the front-end (CDN/load balancer) reads the **first** Host header to decide
routing and validation, but the backend application framework reads the **last** one when
building a URL or making a decision, you've successfully routed a legitimate request while
smuggling `bad-stuff-here` into the part of the system that actually uses it.

**Absolute-URI request line:**
```
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```
*Breakdown:* HTTP technically permits the request line to contain a full absolute URL
instead of just a path (this is mandatory for proxy requests). Per spec the request line
should take precedence over the Host header when both are present, but many real-world
proxies don't implement that correctly. If the front-end validates against the request-line
URL while a downstream component reads the `Host` header for its own purposes, you get the
same kind of smuggling effect as duplicate headers — this is the exact mechanism behind the
"SSRF via flawed request parsing" lab covered in File 03.

**Line-wrapping / leading-space injection:**
```
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```
*Breakdown:* HTTP/1.1 historically allowed a header line to be "folded" (continued onto the
next line) if that next line starts with whitespace — the indented line is treated as part
of the previous header's value, not a new header. Some parsers honor this obscure rule,
others ignore the indented line entirely and just treat it as a second `Host` header that
happens to have a leading space. When the front-end and back-end disagree on which
interpretation is correct, you can smuggle a payload through the header that one side
silently ignores and the other side parses literally.

> **Real-world note:** these ambiguous-request techniques are a simplified subset of HTTP
> request smuggling. If a target is resistant to all of the above but you suspect a
> front-end/back-end disconnect, it's worth escalating to full request-smuggling testing
> (chunked/Content-Length desync), which is outside the scope of this series.

### Step 4 — Try host-override headers if direct/ambiguous injection both fail

Even when `Host` itself is locked down tight, many frameworks were built to sit behind a
reverse proxy and were explicitly coded to trust a *different* header for "the real
original host," because the proxy rewrites `Host` to its own internal hostname before
forwarding the request upstream. If that trust is extended even when no real proxy is
present (or the real proxy forwards the header through unchecked), you can inject directly:

```
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```
*Breakdown:* `Host` passes validation untouched because it's the real domain. But many web
frameworks (Django with `USE_X_FORWARDED_HOST`, certain Spring/Express configurations,
custom-built apps) will use `X-Forwarded-Host` instead of `Host` whenever it's present,
specifically because that's the "correct" thing to do when sitting behind a real proxy.
The attacker is exploiting the gap between "designed to be proxy-only" and "actually
enforced as proxy-only."

This is covered in full depth, including `X-Host`, `X-Forwarded-Server`,
`X-HTTP-Host-Override`, and `Forwarded`, in **File 03**.

## 6. Host header authentication bypass

A specific, high-impact pattern worth calling out on its own: some applications make
**privilege decisions** based on Host — e.g., assuming that requests arriving with
`Host: localhost` or `Host: internal.example.com` must have originated from inside the
trusted network (because, presumably, only an internal caller would know to send that
value, or only internal DNS resolves to a path that reaches the app with that Host).

```
GET /admin HTTP/1.1
Host: vulnerable-website.com
```
*Server response:* access denied, but the error message reveals the panel exists and is
reachable by "local" users.

```
GET /admin HTTP/1.1
Host: localhost
```
*Breakdown:* the application checks the literal string value of the `Host` header — not
the actual network origin of the connection, not a TLS client certificate, not an
authenticated session tied to an internal role — to decide "is this an insider?" Since
`Host` is just request metadata the client supplies, this is trivially bypassable. Many
real systems do this by accident: a load balancer health check or internal monitoring
script hits the app using `Host: localhost`, and a developer later (mis)reads logs and
adds a "shortcut" that treats that Host value as implicitly trusted.

**Industry framing:** this pattern shows up constantly in microservice meshes where a
sidecar proxy (e.g., Envoy, Istio) is *supposed* to enforce that only internal traffic
ever reaches the pod with certain Host values, but the application itself has no
independent verification — so any Host-validation gap in the mesh becomes a full
authentication bypass in the app.

## 7. Virtual host brute-forcing

Organizations frequently host internal/admin applications on the **same physical
infrastructure** as public-facing sites, distinguished only by hostname:

```
www.example.com       -> 12.34.56.78  (public)
intranet.example.com  -> 10.0.0.132   (private, often with NO public DNS record at all)
```

Even with no public DNS record, if you can reach the server's public IP directly (the
public site's IP, a shared load balancer IP, a shared CDN edge) you can often still reach
the *internal* vhost simply by guessing its hostname and supplying it in the Host header:

```
GET / HTTP/1.1
Host: intranet.example.com
```
*Breakdown:* the request is sent to the public IP address (which you already know), but
the Host header tells the server-side virtual-hosting layer which *application* to route
to on that shared infrastructure. Since the routing decision is based purely on the string
value of Host and not on which DNS name resolved to reach you, a correct guess gives you
direct access to an application that was never meant to be internet-reachable — no DNS
enumeration required.

**Practical approach:** use a wordlist of likely internal subdomain names (`intranet`,
`internal`, `admin`, `staging`, `dev`, `vpn`, `corp`, company-specific naming conventions
found via OSINT) and brute-force the Host header against the known public IP with Burp
Intruder, watching for divergent response codes/lengths/redirects that indicate a
different backend responded.

## 8. Connection-state attacks

Many performance-optimized HTTP servers reuse a single TCP/TLS connection for several
request/response cycles (HTTP keep-alive). Some implementations cut corners by **only
fully validating the Host header on the first request sent over a new connection**,
assuming (reasonably for a normal browser, not safely for an attacker using Burp Repeater)
that the Host won't change mid-connection.

```
Request 1 (same connection): GET / HTTP/1.1
                              Host: vulnerable-website.com      <- passes validation

Request 2 (same connection): GET /admin HTTP/1.1
                              Host: bad-stuff-here               <- validation skipped, "already checked this connection"
```
*Breakdown:* the server's logic effectively becomes "validate Host once per connection,
trust it for every subsequent request on that same connection." An attacker who can keep a
single connection alive (which Burp Repeater does by default, unlike a fresh browser
navigation) can send one innocuous, validating request, then pivot the same connection to
abuse Host on every later request without re-triggering validation. This is a particularly
dangerous root cause because it can revive *every other* attack in this file — routing-based
SSRF, cache poisoning, password reset poisoning — on a target that otherwise looked properly
locked down against direct Host injection.

## 9. Real-world prevention (what defenders should actually do)

- **Best option: don't use the Host header server-side at all.** Require the canonical
  domain to be set explicitly in server-side configuration and reference that value
  instead of anything derived from the request. This single change eliminates password
  reset poisoning entirely, since the reset link domain stops being attacker-influenced.
- If the Host header (or a forwarding header) **must** be used, validate it against a
  strict allowlist of permitted domains and reject/redirect anything else — frameworks
  usually provide this natively (e.g., Django's `ALLOWED_HOSTS`).
- Explicitly **disable support for `X-Forwarded-Host` and similar override headers** unless
  there is a real, trusted proxy in front that strips/overwrites them before forwarding.
- At the load balancer/CDN layer, **strip all inbound `X-Forwarded-*` headers from client
  requests** before re-adding trusted values based on the actual connection.
- Disable connection reuse assumptions for security-relevant validation — validate Host
  on every single request, not once per connection.

The next files in this series go deep on the two highest-impact chains: password reset
poisoning (File 02) and header-trust/routing SSRF (File 03), followed by a consolidated
cheatsheet and the full, difficulty-ordered PortSwigger Academy lab map (File 04).
