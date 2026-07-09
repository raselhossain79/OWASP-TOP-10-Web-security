# 03 — SSRF Filter Bypass Techniques

Maps to PortSwigger Academy SSRF labs #3, #4, #5 (verified official order).
This file is the heart of the "industry-standard" framing the user asked for,
since virtually every production SSRF you encounter outside a lab has *some*
filter in front of it. Direct unfiltered SSRF (file 02) is rare in the wild —
filter bypass is the actual day-to-day skill.

---

## 3.1 SSRF With Blacklist-Based Input Filter

**Lab: "SSRF with blacklist-based input filter"**

### The defense model

A blacklist filter works by checking the supplied input *against a list of
known-bad strings* and rejecting matches — e.g., rejecting any URL containing
`localhost`, `127.0.0.1`, or `admin`. This lab specifically has **two** weak
anti-SSRF defenses stacked, both blacklist-based.

### Bypass technique 1 — alternative IP representations of 127.0.0.1

The filter blocks the literal string `localhost` and `127.0.0.1`, but `127.0.0.1`
is just one of many ways to write the exact same IP address.

```
stockApi=http://127.1/admin
```

| Part | What it does | Why it bypasses the filter |
|---|---|---|
| `127.1` | A shorthand IPv4 notation. IPv4 parsers historically accept fewer than 4 octets and fill in zeros: `127.1` is interpreted as `127.0.0.1` because the parser treats the last given octet as filling the low-order bits and pads the rest with zero. | The blacklist string-matches against the literal text `127.0.0.1`. `127.1` never contains that substring, so the filter's check passes — but the underlying HTTP client's URL parser still resolves it to the loopback address when it actually connects. The filter and the HTTP client disagree on what "127.0.0.1" looks like as a string, and that disagreement is the entire bypass. |

Other equivalent representations that work on the same principle (each is the
*same* address, encoded differently so it doesn't match a naive string
blacklist):

| Representation | Form | Why it equals 127.0.0.1 |
|---|---|---|
| `2130706433` | Decimal (dword) notation | `127.0.0.1` as a 32-bit integer: `127*256^3 + 0*256^2 + 0*256 + 1 = 2130706433`. Many IP-parsing libraries accept a single decimal integer as a full IPv4 address. |
| `017700000001` | Octal notation | Leading `0` signals octal to many parsers; `0177` = 127 in octal, etc. |
| `0x7f000001` | Hexadecimal notation | `0x7f` = 127 in hex; the whole thing is the IP packed into one hex dword. |
| `127.0.0.1.nip.io` (or similar wildcard-DNS services) | A domain that resolves to whatever IP is embedded in its own name | Bypasses string blacklists that only check for literal IP-looking text, since the input is a hostname, not an IP literal — but it still resolves to the loopback/internal address you want. |

### Bypass technique 2 — domain you control that resolves to 127.0.0.1

```
stockApi=http://spoofed.burpcollaborator.net/admin
```

| Part | What it does | Why it bypasses the filter |
|---|---|---|
| A registered domain pointing to `127.0.0.1` | The DNS A record for this domain is configured (by you, or in this case provided by the Academy's Collaborator infrastructure) to resolve to `127.0.0.1`. | The blacklist filter checks the literal *string* you submitted (`spoofed.burpcollaborator.net` — which contains none of the blocked terms). The actual network connection, however, happens only *after* DNS resolution, at which point the destination is `127.0.0.1`. The filter operates at the wrong layer: it validates the hostname text, not the resolved IP the request will actually hit. |

### Bypass technique 3 — encoding/case obfuscation

```
stockApi=http://localhost%2F@expected-host/admin
```
or simply
```
stockApi=http://LOCALHOST/admin
```

| Part | What it does | Why it bypasses the filter |
|---|---|---|
| Case variation (`LOCALHOST`) | Hostnames are case-insensitive at the DNS/HTTP layer, but a naive blacklist may do a case-sensitive string comparison against the lowercase `localhost`. | The filter's string check fails to match `LOCALHOST`; the HTTP client's hostname resolution doesn't care about case at all and connects to loopback regardless. |
| URL-encoding (`%2F` etc.) | The filter may inspect the raw string before URL-decoding happens, while the HTTP client decodes it before connecting. | Same root cause as the IP-representation bypasses: filter and client operate on different representations of the same logical value. |

**The unifying lesson for this whole lab:** every blacklist bypass here exploits
the same root cause — **the filter and the thing that actually makes the
request don't agree on canonical form.** Anytime you see a blacklist-based
SSRF defense, your first move should be enumerating every alternative encoding
of the blocked value, because blacklists can only block strings they thought of
in advance.

---

## 3.2 SSRF With Whitelist-Based Input Filter

**Lab: "SSRF with whitelist-based input filter"**

### The defense model

Instead of blocking known-bad strings, the filter only *allows* input matching
an expected pattern — e.g., requiring the URL to start with (or contain)
`https://weliketoshop.net`. This sounds stronger than a blacklist, but it's
only as strong as the URL parser's understanding of "the hostname" matches the
filter's understanding.

### Bypass technique 1 — embedded credentials (`@` character)

```
stockApi=https://weliketoshop.net:fakepassword@192.168.0.X/admin
```

| Part | What it does | Why it bypasses the filter |
|---|---|---|
| `weliketoshop.net` (before the `@`) | In standard URL syntax, anything before an `@` in the authority component is **userinfo** (username:password), not the hostname. | The whitelist filter, doing a naive "starts with the allowed domain" check, sees the string begin with the expected domain and passes it. |
| `:fakepassword` | The password portion of that userinfo. Arbitrary — doesn't need to be a real credential. | Just needed to form valid userinfo syntax; some parsers require the colon-password format to correctly treat everything before `@` as userinfo rather than as the host itself. |
| `192.168.0.X` (after the `@`) | This is the **actual hostname** the URL parser and HTTP client will connect to, per the URL specification — everything after the last `@` and before the next `/`, `?`, or `#` is the real authority host. | The filter checked the *beginning* of the string and found the expected domain there — but the real host, per spec, is what comes after `@`. The filter and the actual URL-parsing logic disagree about which substring "is the hostname." |

### Bypass technique 2 — URL fragment (`#` character)

```
stockApi=https://192.168.0.X/admin#weliketoshop.net
```

| Part | What it does | Why it bypasses the filter |
|---|---|---|
| `192.168.0.X/admin` | The real host and path the request actually goes to. | This is what the HTTP client connects to — the fragment (`#...`) is never sent to the server at all in a normal HTTP request; it's purely a client-side artifact (originally for in-page anchors). |
| `#weliketoshop.net` | A URL fragment. | If the filter checks whether the expected domain appears *anywhere* in the string (a "contains" check rather than "starts with"), this satisfies it — `weliketoshop.net` is textually present — while having zero effect on where the request is actually routed. |

### Bypass technique 3 — DNS naming hierarchy (subdomain trick)

```
stockApi=https://weliketoshop.net.192.168.0.X/admin
```
or, with an attacker-registered domain:
```
stockApi=https://weliketoshop.net.evil-domain.com/admin
```

| Part | What it does | Why it bypasses the filter |
|---|---|---|
| `weliketoshop.net.evil-domain.com` | This is a single fully-qualified hostname. Reading right-to-left per DNS hierarchy rules, the actual domain being queried is `evil-domain.com` (registered and controlled by the attacker) with `weliketoshop.net` as nothing more than a subdomain label. | A naive "starts with weliketoshop.net" filter passes, because the string literally starts with that text. But DNS doesn't care about string prefixes — it resolves the *whole* name, and the authoritative owner of that name is whoever controls `evil-domain.com`, who can point it at any IP they like, including an internal target. |

### Bypass technique 4 — combining techniques

The Academy's own guidance (and real-world WAF bypass practice) explicitly
notes these techniques compose: e.g., combining the `@`-userinfo trick with
URL-encoding the `@` itself (`%40`) to dodge a filter that *does* check for raw
`@` characters but doesn't account for percent-encoding, then relying on the
HTTP client to decode it before connecting.

**The unifying lesson:** whitelist filters fail for the exact same root cause as
blacklist filters — the filter's idea of "where is the hostname in this
string" is based on naive string operations (`startsWith`, `contains`), not on
RFC-compliant URL parsing. Anywhere the URL spec has a feature most developers
forget exists (userinfo, fragments, the DNS label hierarchy), that feature is a
candidate bypass.

---

## 3.3 SSRF With Filter Bypass via Open Redirection

**Lab: "SSRF with filter bypass via open redirection vulnerability"**

### The defense model

This time the filter is the strictest kind: it validates that the destination
host is *exactly* the application's own domain — not a prefix trick, not a
fragment trick, an actual exact match. Direct SSRF to an internal IP is
completely blocked.

### The bypass: chaining through an existing open redirect

The application has a separate, unrelated vulnerability: an open redirection
on its own "next product" feature.

```
/product/nextProduct?currentProductId=6&path=http://evil-host.com
```

This legitimately redirects (HTTP 3xx + `Location` header) to whatever URL is
in the `path` parameter — that's the open redirect bug, independent of SSRF.

### The combined payload, broken down

```
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.X:8080/admin
```

| Part | What it does | Why it bypasses the filter |
|---|---|---|
| `http://weliketoshop.net/product/nextProduct...` | This is the URL the SSRF filter actually inspects. | It's the application's own domain — an exact match against the whitelist. The filter approves it and lets the back-end request proceed. |
| `?currentProductId=6&path=http://192.168.0.X:8080/admin` | Query parameters for the legitimately-vulnerable redirect endpoint. | `path` is the open-redirect injection point — whatever URL you put here, this endpoint responds with a `Location:` header pointing there. |
| The full chain at request time | (1) Filter approves the outer URL because it's the trusted domain. (2) Server requests that URL. (3) The app's *own* `nextProduct` endpoint responds with a 3xx redirect to the internal IP. (4) **If** the HTTP client library used for the stock-check feature follows redirects automatically, it now issues a *second*, unfiltered request — directly to `192.168.0.X:8080/admin`. | The filter only ever validated the *first* URL in the chain. It has no visibility into, and no opportunity to re-validate, the destination of a redirect that the underlying HTTP client follows on the filter's behalf. This is the single most important bypass concept in this entire file: **filters that validate input once, before a redirect is followed, are validating the wrong thing.** |

### Why this matters beyond the lab

This exact bypass class is why the standard real-world mitigation isn't just
"validate the URL" — it's "validate the URL, **and** disable automatic
redirect-following in the HTTP client used for this feature, **and** if
redirects must be supported, re-validate the destination of every redirect hop
against the same allow-list before following it." Most production SSRF
defenses that get bypassed in bug bounty reports are bypassed exactly this way:
the developer validated once at the front door and trusted the HTTP client's
default redirect-following behavior not to walk the attacker back out the
side door.

## 3.4 DNS Rebinding (Concept — Not a Standalone Academy Lab)

Not covered in dedicated PortSwigger Academy labs as of this writing, but
essential for real-world SSRF bypass work and worth covering accurately rather
than omitting it.

### The mechanism

A whitelist/allow-list filter that validates a *hostname* (not a raw IP) by
resolving it once and checking the resolved IP is not internal, then later
making the actual request, is vulnerable to a TOCTOU (time-of-check to
time-of-use) gap if DNS resolution happens twice.

1. Attacker controls a domain, e.g. `attacker-controlled.com`, with a very low
   DNS TTL.
2. First resolution (at validation time): the domain resolves to a harmless
   public IP — passes the filter's "is this IP internal?" check.
2. The attacker's DNS server then changes the record (TTL has already expired)
   to point to `127.0.0.1` or an internal IP.
3. Second resolution (at actual request time, performed by the HTTP client
   library, independently of the filter's earlier check): the domain now
   resolves to the internal address, and the request goes there.

| Why it works | Root cause |
|---|---|
| The filter validated *a hostname's resolved IP* as a one-time check, then trusted the hostname string for the actual request, which triggers an independent, later DNS lookup. | Same root cause as every other bypass in this file: validation and execution are not the same operation, and anything that can change between them is a bypass surface. Here, what changes is the DNS record itself, not the URL string. |

### Real-world mitigation note

This is precisely why the most robust SSRF defenses **resolve the hostname
once, validate that specific resolved IP, and then connect to that exact IP
directly** (pinning the connection to the validated address) rather than
re-resolving the hostname at request time. Cloud-native HTTP clients and
egress proxies (e.g., enterprise SSRF-protection gateways) implement exactly
this pinning behavior as their core defense.

## Real-World Notes

- Bug bounty programs that pay out for SSRF almost always require demonstrating
  a filter bypass, not just unfiltered SSRF, because unfiltered SSRF on
  internet-facing apps is now relatively rare — most platforms have *some*
  blacklist or whitelist in place. The skill being tested in 3.1–3.3 is the
  actual day-to-day bug bounty skill.
- The `@`/userinfo and `#`/fragment tricks from 3.2 are listed nearly verbatim
  in PortSwigger's own SSRF URL-validation-bypass cheat sheet and recur
  constantly in real disclosed reports across HackerOne — they are not
  lab-only tricks.
- DNS rebinding is a heavier, infrastructure-dependent technique (you need
  control of an authoritative DNS server with a fast-changing record) and is
  more commonly seen in dedicated security research and red-team engagements
  than in quick bug-bounty turnaround testing, but it's the correct answer
  whenever you see a hostname-based allow-list that resolves once and trusts
  the result.
