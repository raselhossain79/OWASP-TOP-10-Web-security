# 03 — Header Injection Chained into Web Cache Poisoning

## Why this file is the core of the series

In real-world engagements, a bare CRLF injection with no caching layer
behind it is a low-to-medium severity finding — it affects one client, one
request. The attack becomes high or critical severity the moment the
poisoned response gets **cached and replayed to other users**. This is the
single most important escalation path for CRLF/header injection, and it's
also the part of this topic PortSwigger has built real, current labs for —
so this file doubles as the lab-mapping file for the whole series.

## The two related but distinct mechanisms

It's important to separate two things that get conflated:

1. **Unkeyed-header cache poisoning** — the attacker abuses a header that
   the cache *ignores* when deciding whether two requests are "the same"
   (the cache key), but that the *origin server* still uses to build the
   response. No raw `\r\n` is required here — the header value itself
   (e.g. a hostname) is reflected unsafely into the response. This is the
   mechanism PortSwigger's "Web cache poisoning" topic labs teach, and it's
   by far the most common cache poisoning pattern found in bug bounty
   programs today.
2. **CRLF-driven cache/response-queue poisoning** — the attacker injects a
   literal `\r\n` sequence into a header that survives an HTTP/2-to-HTTP/1.1
   downgrade, turning it into a real line break on the back-end connection.
   This is request smuggling territory, and PortSwigger has two labs that
   use this exact mechanism and name it explicitly as CRLF injection.

Both end in the same place — a malicious response gets cached or queued and
served to a victim — but the entry technique differs. A pentest report
should describe which one you actually used.

## Mechanism 1 — unkeyed header poisoning, piece by piece

Real, common example: `X-Forwarded-Host`.

Many applications use `X-Forwarded-Host` (set by a load balancer/CDN to
tell the origin what hostname the client actually requested) to build
absolute URLs in the response — for example, when generating a `<script
src="...">` tag for a tracking script. Caches almost never include
`X-Forwarded-Host` in the cache key, because it's an internal infra header,
not something a normal client request varies.

Request:

```
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker-controlled.exploit-server.net
```

Breaking down why this works:

| Component | Role |
|---|---|
| `Host: example.com` | This *is* in the cache key — the cache thinks this request is "the normal home page" |
| `X-Forwarded-Host: attacker-controlled.exploit-server.net` | Not in the cache key, but the origin server reads it and uses it to build an absolute URL it embeds in the response body (e.g. `<script src="https://attacker-controlled.exploit-server.net/resources/js/tracking.js">`) |
| Result | The cache stores this poisoned body under the *same* cache key as the legitimate home page. Every subsequent visitor requesting `/` — using their own, totally normal request — receives the attacker's version, including a `<script>` tag pointing at attacker infrastructure |

The attacker then hosts a malicious `tracking.js` on their own server and
waits for the cache to serve their poisoned response to real users. No raw
CRLF byte is needed; the "injection" here is into the *cache key model*, not
into the wire format — but it's still header injection in the broad sense
(an unvalidated header value is driving response generation), and it's the
technique most real-world cache poisoning reports describe.

## Mechanism 2 — CRLF-via-HTTP/2-downgrade, piece by piece

This is the literal `%0d%0a` technique, and it only works where a front-end
speaks HTTP/2 to the client but downgrades to HTTP/1.1 to talk to the
back-end.

Conceptual payload (constructed via Burp's Inspector, since HTTP/2 headers
are binary fields, not raw text — you inject the newline by pressing
Shift+Return inside the header value field, not by typing `%0d%0a`):

```
:method: GET
:path: /
host: lab-id.web-security-academy.net
foo: bar\r\nTransfer-Encoding: chunked
```

Breaking this down:

| Component | Role |
|---|---|
| `foo: bar` | An arbitrary, otherwise harmless header — the actual name doesn't matter |
| `\r\n` inside the value | In HTTP/2, this is just two bytes inside a string — HTTP/2 has no concept of a header "ending" at `\r\n`, since headers are framed explicitly. The front-end's HTTP/2 parser accepts this without complaint |
| `Transfer-Encoding: chunked` | The smuggled second "header" — meaningless on the HTTP/2 side, but about to become very meaningful |
| The downgrade step | When the front-end rewrites this HTTP/2 request as HTTP/1.1 text to forward to the back-end, it serializes the `foo` header value literally — and the `\r\n` you embedded becomes a **real** line terminator. The back-end now sees two headers where the front-end only ever validated one |

The practical effect (used in the PortSwigger labs below): once you can
inject an arbitrary header into the downgraded HTTP/1.1 request, you can
inject a complete second request after it (smuggling), or inject enough
`\r\n\r\n` to make the front-end treat the back-end's *next* response as
belonging to your connection — capturing another user's response,
including their session cookie. That's response-queue poisoning, the
mechanism behind both labs below.

## PortSwigger lab mapping (in Academy order)

### Tier A — Web cache poisoning topic (Apprentice → Practitioner)

These use Mechanism 1 (unkeyed headers, not raw CRLF) and are the correct
starting point — they teach the cache-key model that every later technique
in this file depends on. They appear under **Web cache poisoning →
Exploiting cache design flaws**, then **Exploiting cache implementation
flaws**, in that order on the Academy topic page:

1. `Web cache poisoning with an unkeyed header` — the baseline
   `X-Forwarded-Host` reflected-XSS chain described above.
2. `Web cache poisoning with an unkeyed cookie` — same idea, but the
   unkeyed input is a cookie value reflected into a JavaScript context.
3. `Web cache poisoning with multiple headers` — requires combining two
   unkeyed headers together to produce the harmful response.
4. `Web cache poisoning via an unkeyed header leading to DOM-based XSS` —
   same primitive, escalated to a DOM sink instead of a direct reflection.
5. `Web cache poisoning with an unkeyed cookie and a non-standard cache
   rule` — adds the complication of evaluating which cache rules apply.
6. `Combining web cache poisoning vulnerabilities` — Expert-tier
   capstone that chains two separate cache-key flaws together
   (a backslash/forward-slash normalization quirk plus an unkeyed header)
   to defeat a target that resists either technique alone.

Then under **Exploiting cache implementation flaws** (cache-key
implementation quirks rather than design-level unkeyed inputs):

7. `Web cache poisoning via an unkeyed query string`
8. `Web cache poisoning via a fat GET request`
9. `Web cache poisoning via an unkeyed query parameter`
10. `Web cache poisoning via a cache key injection` (parameter cloaking)
11. `Web cache poisoning via an unkeyed port`

Note: PortSwigger periodically adds or reorders labs within this topic.
Always cross-check the live, current order at the topic's lab index before
treating this list as final — the mechanism breakdowns above remain
accurate regardless of any reordering.

### Tier B — HTTP request smuggling → Advanced (Expert tier, true CRLF injection)

These are the two labs that use the literal `\r\n`-in-HTTP/2-header
mechanism described above, and are the only labs on the Academy that
explicitly use the term "CRLF injection" in their title:

12. `HTTP/2 request smuggling via CRLF injection` — injects `\r\n` into an
    HTTP/2 header that, after downgrade, smuggles a complete prefix request
    onto the back-end connection, letting you capture another user's
    request/response pair to hijack their account.
13. `HTTP/2 request splitting via CRLF injection` — the response-queue
    poisoning variant: injecting enough `\r\n\r\n` during downgrade
    converts a smuggled prefix into a complete *request* on its own,
    poisoning the queue of responses the front-end expects back, letting
    you capture an admin's session cookie and use it to access `/admin`.

These two labs require working through the earlier HTTP Request Smuggling
labs first (CL.TE/TE.CL desync fundamentals) before the Advanced/HTTP-2
section makes sense — they assume you already understand basic request
smuggling, which is its own topic and outside the scope of this CRLF-focused
series.

## Real-world note

Cache poisoning via unkeyed headers (Tier A above) is, by a wide margin,
the more commonly reported finding in live bug bounty programs — it
doesn't require an HTTP/2 downgrade setup, just a CDN/cache configuration
that includes too few headers in its cache key. James Kettle's "Practical
Web Cache Poisoning" (2018) and "Web Cache Entanglement" (2020) research
papers, both referenced directly from the PortSwigger Academy topic page,
document real production poisonings found this way against major sites.
The HTTP/2-downgrade CRLF mechanism (Tier B) is rarer in the wild but higher
severity when found, because it usually indicates a deeper architectural
issue (a front-end/back-end protocol mismatch) rather than a single missed
header.
