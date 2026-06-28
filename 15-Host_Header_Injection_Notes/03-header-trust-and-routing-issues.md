# Header Trust Issues — X-Forwarded-Host, X-Forwarded-For, and Routing-Based SSRF

## 1. Why "forwarding" headers exist at all

When a request passes through a reverse proxy, load balancer, or CDN before reaching the
real application server, the application normally only sees the **proxy's own connection
details** — not the original client's. To preserve that lost information, the proxy is
supposed to attach extra headers describing the original request before forwarding it
upstream:

- `X-Forwarded-Host` — the original `Host` header the client sent to the proxy
- `X-Forwarded-For` — the original client IP address (and any further proxies in the chain)
- `X-Forwarded-Proto` / `X-Forwarded-Scheme` — whether the original request was HTTP or HTTPS
- `Forwarded` — a standardized (RFC 7239) header combining all of the above into one
- `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override` — older/vendor-specific
  equivalents to `X-Forwarded-Host`, used by some load balancers and frameworks

These headers are legitimate and necessary in proxied architectures. **The vulnerability
is not the existence of these headers — it's that applications frequently trust them
unconditionally, with no verification that the value actually came from a real, trusted
proxy rather than directly from the client.**

## 2. X-Forwarded-Host: the direct sibling of Host header injection

If an application is configured (often by framework default, not even a deliberate
developer choice) to prefer `X-Forwarded-Host` over `Host` whenever it's present, then any
client — proxy or not — can simply add the header themselves:

```
GET /reset-password-confirmation HTTP/1.1
Host: example.com
X-Forwarded-Host: evil-user.net
```

*Breakdown:* `Host` is left untouched, so any front-end validation that checks `Host`
against an allowlist passes cleanly — the request is routed to the correct application.
But once the request reaches application code, a framework setting such as Django's
`USE_X_FORWARDED_HOST = True`, or custom code written under the (often correct, but
unverified) assumption "we're always behind our load balancer, so this header is safe,"
causes the application to build any output URL — password reset links, OAuth redirect
URIs, canonical/share links, CORS reflection — using `evil-user.net` instead of the real
domain. Functionally this produces the exact same outcomes covered in Files 01 and 02
(password reset poisoning, cache poisoning), but through a completely different header
that a naive Host-only validation layer never inspects.

**Real-world note:** this gap is extremely common in containerized/Kubernetes deployments.
A sidecar (Envoy, NGINX Ingress) is configured to set `X-Forwarded-Host` correctly for
*legitimate* internal traffic, and the application trusts it because "the sidecar always
sets it correctly" — but the sidecar typically only **adds** the header; it often doesn't
**strip an existing one** supplied directly by the client first. If the client's original
value isn't overwritten, just appended to, multiple `X-Forwarded-Host` values may exist in
the request, and which one the application reads depends entirely on its HTTP library's
behavior (first value, last value, or a comma-joined string) — another source of
exploitable ambiguity.

## 3. Combining override headers: multi-header cache poisoning

Some applications/caches require **more than one** header to be set together before the
poisoned behavior triggers — a deliberately higher bar that still fails because each
individual header is validated (if at all) in isolation, never as a combined set:

```
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: evil-user.net
X-Forwarded-Scheme: http
```

*Breakdown:* here, the application reflects `X-Forwarded-Host` into an absolute URL used to
import a JavaScript resource (e.g., `<script src="http://evil-user.net/resources/js/tracking.js">`),
but only does so when `X-Forwarded-Scheme` indicates a non-HTTPS context — a legitimate
feature for handling protocol-relative resource loading behind an SSL-terminating proxy.
Neither header alone triggers the vulnerable code path; only the combination does. This
matters operationally because **automated scanners that fuzz one header at a time are far
less likely to find this class of bug** than a manual tester who understands the
application is checking a *combination* of forwarded context.

If a caching layer sits in front and includes neither header in its cache key, the
resulting malicious response (now containing a script tag pointing at an attacker-hosted
file) gets cached and served to every subsequent visitor of that URL — converting a
"useless," unexploitable reflection into stored XSS at scale. (Full cache-key mechanics are
covered in File 01, Section 3 — "send ambiguous requests.")

## 4. X-Forwarded-For: a related but distinct trust problem

`X-Forwarded-For` doesn't control routing or URL construction — it claims to identify the
**originating client IP address**, since the application server otherwise only sees the
proxy's IP. The trust failure here has a different shape but the same root cause: **a
header meant to carry information only a real, trusted proxy should set is instead
accepted directly from the client.**

```
GET /admin/dashboard HTTP/1.1
Host: example.com
X-Forwarded-For: 127.0.0.1
```

*Breakdown:* if the application's access-control logic checks "is the *original* client IP
in our internal allowlist" by reading `X-Forwarded-For` (because the real client IP isn't
otherwise visible behind the proxy), and the proxy in front doesn't strip/overwrite any
pre-existing `X-Forwarded-For` value the client supplied before adding its own, the
attacker can simply claim to be `127.0.0.1` (localhost) or any other allowlisted internal
IP. The application has no independent way to verify the claim — it's trusting a plain
text header value.

Common real-world consequences of this exact pattern:

- **Access-control bypass:** admin panels, debug endpoints, or internal APIs that are
  "protected" only by an IP allowlist checked against `X-Forwarded-For` rather than the
  actual TCP connection's source IP.
- **Rate-limiting / brute-force protection bypass:** if rate limiting buckets requests by
  the IP found in `X-Forwarded-For`, an attacker can set a different (often
  randomly-generated) value on every request to make each one appear to come from a unique
  client, completely defeating the throttle on login attempts, password resets, or OTP
  verification.
  ```
  X-Forwarded-For: 203.0.113.<random-octet>
  ```
  *Breakdown:* each request looks like it came from a different external IP in the
  allowlisted/trusted range used for rate-limit bucketing, so the limiter's per-IP counter
  never accumulates enough hits from any single "identity" to trigger a block, even though
  every request is actually coming from the same attacker machine.
- **Log/audit-trail poisoning:** if `X-Forwarded-For` is written directly into application
  or security logs as "the requesting IP" without sanitization, an attacker can inject
  arbitrary log content (including log-injection payloads, or simply false attribution
  that frames a third party's IP for malicious activity during incident response).

**Real-world note:** this is precisely why mature reverse proxy configurations explicitly
**overwrite** `X-Forwarded-For` rather than append to it for the first hop from the public
internet, and why CDNs like Cloudflare provide their *own* trusted header
(`CF-Connecting-IP`) specifically because they know `X-Forwarded-For` itself is
client-forgeable if not handled correctly at every layer of the chain.

## 5. Routing-based SSRF — the Host header as an internal router's input

This is the highest-impact category covered in this file, and it relies on a different
trust failure than the override-header issues above: here, **the Host header itself**
(not a forwarding header) is used by an *internal* load balancer or reverse proxy to
decide which backend to forward the request to.

### Why this architecture exists

Modern cloud-native deployments commonly place an internal routing layer between the
public-facing edge and dozens/hundreds of internal backend services — this is normal and
necessary for scaling. The problem is when that internal router blindly trusts the
client-supplied Host header to make its forwarding decision, rather than relying on a
fixed mapping configured server-side.

### Step 1 — Detect that Host controls backend routing

```
GET / HTTP/1.1
Host: <your-Burp-Collaborator-subdomain>
```

*Breakdown:* you supply a domain you control (ideally a Burp Collaborator payload, which
gives you out-of-band confirmation) as the Host header on a request sent to the target's
normal public IP/domain. If the *target's own infrastructure* subsequently issues a DNS
lookup and/or an HTTP request to your Collaborator domain, that's conclusive proof that
some component in the request path is taking the Host value and using it to decide where
to route or connect to next — exactly the routing-based SSRF primitive.

### Step 2 — Pivot from "I can reach arbitrary public servers" to "I can reach internal-only services"

Once outbound routing to attacker-chosen destinations is confirmed, the next goal is
reaching addresses that should never be internet-routable — the internal network the
router itself sits inside, which is exactly why these routers are such valuable SSRF
targets: they're internet-facing *and* have a foot inside the private network.

```
GET / HTTP/1.1
Host: 192.168.0.§0§
```

*Breakdown:* this is a Burp Intruder payload position (the `§…§` markers denote where
Intruder will substitute values) targeting the last octet of a private IP range. The
attacker is brute-forcing the entire `192.168.0.0/24` block by sending 256 requests, each
with a different Host value, watching for a response that differs from the uniform
"timeout" or "connection refused" baseline returned for IPs with nothing listening. A
distinctive response — commonly an HTTP redirect (`302 Found` to `/admin`) — pinpoints a
live internal service.

```
GET /admin HTTP/1.1
Host: 192.168.0.223
```
*Breakdown:* having identified the live internal IP from the scan, the attacker now issues
a direct request for the discovered path, again setting Host to that internal IP so the
vulnerable router forwards the request there instead of to the public application. The
router doesn't know or care that `192.168.0.223` is supposed to be unreachable from the
internet — it's just doing exactly what it was configured to do: forward based on Host.

### Step 3 — Exploit whatever is found internally

Internal admin panels reached this way frequently have **weaker authentication
assumptions** than the public-facing application, precisely because they were designed
under the assumption that only trusted internal traffic could ever reach them:

```
POST /admin/delete HTTP/1.1
Host: 192.168.0.223
Content-Type: application/x-www-form-urlencoded
Cookie: session=<session-cookie-from-the-internal-panel's-own-response>
Content-Length: 45

csrf=<csrf-token-from-the-form>&username=carlos
```
*Breakdown:* the internal admin panel issued its own session cookie and CSRF token in its
response — both of which the attacker simply harvests from the HTTP response they already
received via the routing-based SSRF, since they're effectively now "inside" the panel's
session. No separate authentication was needed because the panel trusted network position
(reachable only via internal IP) as a substitute for actual access control.

## 6. SSRF via flawed request-line parsing (a Host-validation bypass that enables the same SSRF)

Some proxies validate the **Host header** strictly, blocking direct injection — but
separately trust the **absolute-URI in the request line** for actual routing, without
applying the same validation there:

```
GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
Host: <your-Burp-Collaborator-subdomain>
```

*Breakdown:* the request line itself names the legitimate domain — this is what gets
checked and approved by the proxy's validation logic, since it's specifically looking at
the request line, not the Host header, to decide "is this an allowed destination." But the
*routing/connection* code downstream takes the path's hostname from the `Host` header, not
the request line that was validated. This is structurally the same "validator and consumer
disagree about which field is authoritative" problem as duplicate Host headers (File 01,
Section 3) — except here the two competing fields are the request-line URI and the Host
header itself, rather than two copies of the same header.

Once this gap is confirmed (via the Collaborator interaction triggered above), the
internal IP range scan proceeds exactly as in Section 5, Step 2 — supplying the candidate
internal IP via `Host` while keeping the request line pointed at the legitimate, validated
domain:

```
GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
Host: 192.168.0.§0§
```

## 7. Defenses (and why they actually close these gaps)

- **Never trust `X-Forwarded-Host`, `X-Forwarded-For`, `X-Host`, or `Forwarded` from a
  client connection unless a verified, trusted proxy is the *only* possible source** —
  enforced by having that proxy strip and overwrite (not append to) these headers on every
  inbound request, before they ever reach the application.
- **Configure internal routers/load balancers to forward based on a fixed, server-side
  mapping** rather than dynamically trusting the client-supplied Host header to choose a
  backend.
- **Segment internal-only services so they are unreachable even if Host-based routing is
  abused** — defense in depth via network policy, not just application-layer trust.
- **Validate the request-line URI with the same rigor as the Host header**, and reconcile
  any discrepancy between the two by rejecting the request outright rather than silently
  preferring one.
- For `X-Forwarded-For` specifically: use a CDN/proxy-provided header that the client
  cannot forge (e.g., a header set only at the network edge, never passed through from
  upstream client input) wherever real client-IP attribution is security-relevant.

File 04 consolidates all of the payloads from this file and Files 01–02 into a single
quick-reference cheatsheet, plus the full, difficulty-ordered PortSwigger Academy lab map
for hands-on practice.
