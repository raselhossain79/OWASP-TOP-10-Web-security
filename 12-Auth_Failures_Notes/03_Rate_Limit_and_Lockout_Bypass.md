# 03 — Rate-Limit and Account-Lockout Bypass

## 1. Why This Gets Its Own File

File 02 covers *performing* a credential attack. This file covers what
happens when the target actually defends against it — because in real
engagements, an undefended login form is rare; a **poorly implemented**
defense is common. Distinguishing "no rate limiting" from "rate limiting
that can be bypassed" is itself part of the finding and changes how it gets
written up: the latter is a more interesting, often higher-severity report
because it shows the developer tried and the control still fails.

## 2. How Rate Limiting and Lockout Are Usually Implemented (and Why Each Breaks)

| Implementation | How it works | How it typically breaks |
|---|---|---|
| **Per-account lockout** | Counter tied to the *username*; N failures locks that account regardless of source IP | Doesn't stop an attacker trying **one password against many usernames** (password spraying) — the per-account counter never gets close to N for any single account |
| **Per-IP rate limit / block** | Counter tied to source IP; N failures from one IP triggers a block or CAPTCHA | Defeated by changing the apparent source IP (Section 3) |
| **Global/app-wide throttle** | Slows down *all* login attempts past a threshold, regardless of account or IP | Rare in practice; mostly defeats unsophisticated single-threaded scripts, not a real distributed attack |
| **CAPTCHA after N failures** | Forces a CAPTCHA challenge instead of an outright block | Often only applied after the rate-limit window resets, or only checked client-side; sometimes the CAPTCHA token isn't actually re-validated server-side on resubmission |

## 3. IP Rotation and Header Spoofing

### 3.1 X-Forwarded-For and Similar Header Spoofing

Many applications sit behind a reverse proxy or load balancer and therefore
trust a header to determine the "real" client IP for rate-limiting purposes,
since the TCP connection itself always appears to come from the proxy, not
the actual client. The most common headers used for this:

- `X-Forwarded-For`
- `X-Real-IP`
- `X-Client-IP`
- `True-Client-IP` (notably used by some CDN configurations)
- `X-Originating-IP`

If the application reads one of these headers **without validating that it
actually came from a trusted upstream proxy**, an attacker can simply set it
to an arbitrary value on every request, and the app's rate limiter will
treat each request as coming from a "different" client — this is precisely
PortSwigger Lab 6 (Broken brute-force protection, IP block).

**Burp Intruder configuration for this attack:**
1. Capture the login `POST` request.
2. In the **Positions** tab, add a custom header line (if not already
   present) and mark the **value** of `X-Forwarded-For` as a payload
   position, in addition to (or instead of) the password field.
3. Use **Pitchfork** if you're rotating both a fake IP **and** a password
   guess simultaneously per request (one list of throwaway IPs, one list of
   passwords, matched index-for-index), or **Battering ram** if you only
   need a fresh IP value reused across the attack while password stays
   fixed per request batch.
4. Payload type for the IP list: **Simple list**, populated with
   sequential or random IPv4 addresses (e.g., `1.1.1.1`–`1.1.1.250`), or a
   **Numbers** payload type configured to generate the last octet
   incrementally, which is cleaner than maintaining a static text file.

### 3.2 Real Source-IP Rotation (When Header Spoofing Doesn't Work)

If the application correctly validates `X-Forwarded-For` against a trusted
proxy list (i.e., header spoofing fails), the rate limit is keyed to the
actual TCP source IP, and bypassing it requires genuinely different egress
points:

- **Proxy chains / rotating proxy pools** — commercial or self-hosted
  rotating-proxy services that assign a different exit IP per request or
  per session.
- **Tor** — each circuit can present a different exit node IP, though Tor
  exit nodes are frequently already on reputation blocklists, which can
  trigger other defenses (CAPTCHA-on-Tor-exit policies) before the rate
  limiter itself is even reached.
- **Cloud-provider IP pools** — spinning up requests across multiple cloud
  regions/instances to diversify source IPs; this is the technique most
  closely mirrored by commercial credential-stuffing botnets, which use
  large pools of compromised residential IPs (residential proxy networks)
  specifically because they're far less likely to already be blocklisted
  than datacenter ranges.

This is genuinely the most resource-intensive evasion technique in this
file, both to set up and to execute responsibly within engagement scope —
for most authorized pentests, simply demonstrating that the header-spoofing
bypass (3.1) works, or doesn't, is sufficient to prove or disprove the
control without needing to stand up real distributed infrastructure.

## 4. Response-Based Lockout Detection

Before attempting to bypass a rate limit, confirm it actually exists and
characterize its exact trigger condition — guessing wastes requests and risks
unnecessarily locking real test accounts. Build a small detection matrix by
observing how the response changes as failed attempts accumulate:

| Signal | What changed | What it tells you |
|---|---|---|
| HTTP status code | `200` → `429 Too Many Requests` | Explicit, standards-compliant rate limiting — usually also exposes a `Retry-After` header telling you exactly how long to wait |
| HTTP status code | `200` → `403 Forbidden` | Often a WAF-layer block (Cloudflare, AWS WAF) sitting in front of the app, not app-level logic — may have a different bypass surface than the app's own lockout |
| Response body text | Error message changes from "Invalid credentials" to "Account locked" or "Too many attempts" | App-level lockout — combine with Section 3.1 of File 02 (account-lock enumeration) since this same signal can itself leak username validity |
| Response time | Sudden, consistent jump in latency after N attempts | Possible artificial delay-based throttling rather than a hard block — check whether the delay is fixed (same backoff for everyone) or escalating (real adaptive throttling) |
| Response headers | `Retry-After`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` | The server is telling you exactly how its rate limiter is counting — read these literally, they often state the limit and window directly |

**Practical method:** in Burp Intruder, run a short, deliberately slow
calibration pass (low thread count, one request at a time) against a
disposable/test account, sort results by **Status**, **Length**, and
**Response received** time, and look for the exact attempt number where any
of the above signals shift. This tells you the real threshold (e.g., "lockout
triggers after the 5th failure within a 60-second window") before you
design the real attack around it.

## 5. Slowing and Distributing Requests to Stay Under Threshold

Once the real threshold is known, the attack can be deliberately throttled
to stay just under it rather than trying to overwhelm or outright defeat
the control:

- **Burp Intruder Resource Pool**: set **Maximum concurrent requests** to 1
  and a **Delay between requests** large enough that the rolling request
  count within the rate limiter's window never crosses its threshold (e.g.,
  if the limit is "5 failures per 60 seconds," configure roughly one request
  every 15 seconds, comfortably under 5/60s, rather than guessing).
- **Hydra `-t` (thread count)**: drop to `-t 1`, and if the module/version
  supports it, add a `-W <seconds>` wait-time-between-attempts style flag
  (exact flag support varies by Hydra build and module — check `hydra -U
  <module>` for module-specific timing options) to manually pace requests.
- **Jitter**: a perfectly even interval (e.g., exactly one request every 10
  seconds, forever) is itself a detectable pattern to a security team
  watching logs or an ML-based anomaly detector. Randomizing the delay
  within a range (e.g., 8–15 seconds) better mimics organic traffic and is
  standard practice in real credential-stuffing tooling for this reason.
- **Distributing across the IP-rotation techniques in Section 3**: combining
  IP rotation with per-IP pacing (e.g., 3 requests per IP before rotating)
  multiplies effective throughput without ever exceeding the per-IP
  threshold on any single source — this is the core technique behind Lab 13
  (multiple credentials per request) when combined with the next section.

## 6. Multiple Credentials Per Request (Lab 13)

A distinct and more subtle bypass: if a rate limiter counts **HTTP
requests**, not **credential-checking operations**, then an application that
accepts an **array** of credentials in a single request body (e.g., a JSON
login endpoint that — due to a backend bug — iterates over a submitted
array of password guesses and returns success if *any* one of them
matches) lets an attacker test dozens of passwords inside one request,
which the rate limiter sees as a single attempt. This is why testing should
always include sending malformed/array-wrapped parameter values
(`"password": ["guess1","guess2","guess3"]` instead of
`"password": "guess1"`) against any JSON-based login endpoint — it costs
nothing to try and occasionally reveals exactly this class of bug.

## 7. Real-World / WAF-Specific Notes

- **Cloudflare** rate limiting (and similar CDN-layer controls) is
  typically IP- and path-based by default; the X-Forwarded-For bypass in
  Section 3.1 generally does **not** work against Cloudflare's own edge
  rate limiting (Cloudflare sees the true connecting IP at its edge,
  regardless of what header value the client sends), but it can still work
  against the **origin application's own** secondary rate limiting if the
  origin trusts a forwarded header from Cloudflare without restricting it
  to Cloudflare's actual IP ranges.
- **AWS WAF** rate-based rules operate similarly — edge-level IP tracking
  that header spoofing alone won't defeat, but origin-level logic behind it
  might still be vulnerable.
- The practical takeaway for both pentest and bug bounty reporting: always
  test the **origin application's own logic**, not just the edge
  CDN/WAF, since a finding of "the app's internal rate limiter trusts a
  spoofable header" is valid and reportable even when the CDN in front of
  it is correctly configured — they are two separate controls.
