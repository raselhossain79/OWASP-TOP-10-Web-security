# 04 — Cheatsheet and Lab Mapping

## Quick detection checklist

- [ ] Identify endpoints with a security-critical limit, balance, or single-use state
      (coupons, withdrawals, ratings, CAPTCHA, login attempt counters, invite/voucher redemption).
- [ ] Ask: does this endpoint read state and then write updated state, with any logic in between?
      If yes, it is a race condition candidate.
- [ ] Ask: could two requests touching the same record (same user, same coupon, same balance)
      plausibly collide? No collision potential = not worth testing.
- [ ] Benchmark normal sequential behavior first (separate connections, one at a time).
- [ ] Send the same group using the single-packet attack (Repeater "send group in parallel," or
      Turbo Intruder with `Engine.BURP2`, `concurrentConnections=1`, and a shared gate).
- [ ] Look for any deviation from baseline: more than one success response, inconsistent
      response times, second-order effects (duplicate emails, duplicate database side effects).
- [ ] Trim the request set down to the minimum reproducible case before writing it up.

## Quick reference: which race class am I looking at?

| Symptom | Likely class | Where to look |
|---|---|---|
| Same endpoint, identical requests, limit gets exceeded | Limit-overrun | `02` §1–3 |
| Same endpoint, identical requests, against a rate-limit/lockout counter specifically | Bypassing rate limits | `02` §3 |
| Two different endpoints involved (e.g. payment + confirmation) | Multi-endpoint | `02` §1 (basket adjustment variant) |
| Same endpoint, different parameter values, session-shared state | Single-endpoint | `02` §6 |
| Object created via multiple internal steps, exploitable empty/null intermediate value | Partial construction | — see Academy page directly; no scenario file section needed beyond `01` definition |
| Token derived from timestamp rather than CSPRNG | Time-sensitive (not a true race) | `01` "Time-sensitive attacks" |

## Turbo Intruder minimal template (copy-paste starting point)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)

    for i in range(20):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

See `03-Turbo-Intruder-Single-Packet-Attack.md` for the full line-by-line explanation before using
this against a real target.

## PortSwigger Web Security Academy — Race Conditions lab mapping

The Race Conditions topic on the Web Security Academy currently contains **6 labs**, spanning
Apprentice through Expert. This is a complete, dedicated lab set — there are no gaps to disclose
in this category, unlike some other topics where Academy coverage is partial.

Labs are listed below in official Academy difficulty-progression order, each mapped to the
technique and real-world scenario it corresponds to in this series.

| # | Difficulty | Lab name | Technique it teaches | Maps to |
|---|---|---|---|---|
| 1 | Apprentice | **Limit overrun race conditions** | Basic limit-overrun via parallel identical requests to one endpoint (a coupon/discount race). Solvable via Burp Repeater's "Trigger race condition" custom action or grouped parallel send — no scripting required at this level. | `01` Limit-overrun; `02` §1 |
| 2 | Practitioner | **Bypassing rate limits via race conditions** | Using a parallel batch (typically via Turbo Intruder for the full wordlist volume) to defeat a per-username failed-login counter and brute-force a password despite an apparent lockout. | `02` §3; `03` full script |
| 3 | Practitioner | **Multi-endpoint race conditions** | Racing two different endpoints (cart/coupon application vs. checkout) where processing times don't naturally align — requires understanding connection warming / timing alignment, not just raw parallel sending. | `02` §1 (basket variant); `03` "Working around multi-endpoint timing mismatches" |
| 4 | Practitioner | **Single-endpoint race conditions** | Same endpoint, different parameter values, exploiting session-shared state to cause a value collision (e.g. password-reset-style session token race). | `02` §6; `03` "Adapting the template: per-request payload substitution" |
| 5 | Practitioner | **Exploiting time-sensitive vulnerabilities** | Token generation based on a high-resolution timestamp instead of a CSPRNG; requires precisely timed (not necessarily concurrent) requests to force two tokens to collide. | `01` "Time-sensitive attacks" |
| 6 | Expert | **Partial construction race conditions** | Exploiting the brief window where an object (e.g. a newly registered user) exists in the database but a related field hasn't been populated yet, by sending a request whose value matches the uninitialized default (empty string / null-equivalent, including PHP `param[]` array-syntax tricks). | `01` "Partial construction race conditions" |

### Notes on solving these labs

- Labs 2 onward generally require **Burp Suite 2023.9 or higher** and the latest Turbo Intruder
  version from the BApp Store, per PortSwigger's own lab requirements — confirm your Burp version
  before attempting them if you hit unexpected failures.
- Lab 1 can be solved without any scripting at all using Burp Suite Professional's **"Trigger race
  condition"** custom Repeater action, which sends a request 20 times in parallel with a single
  click. This is worth knowing for speed during live engagements where Burp Pro is available, even
  though understanding the underlying Turbo Intruder mechanics (covered in `03`) remains essential
  for the harder labs and for engagements without Burp Pro's custom action available.
- Lab 6 (Partial construction) is the only Expert-rated lab in this set and is meaningfully harder
  than the rest — it combines the race-window concept with framework-specific parameter parsing
  quirks (PHP/Rails array syntax), so revisit `01`'s partial construction section closely before
  attempting it.

## Real-world reporting notes

- When writing up a race condition finding, always state the root cause precisely: "non-atomic
  read-then-write on `<endpoint>` allows the `<limit>` check to be bypassed under concurrency" —
  not just "race condition found." This matters because the correct remediation (database
  transaction, atomic decrement, unique constraint) is different from a generic "add a rate limit"
  fix, and an imprecise root cause description can lead to an incomplete fix being shipped and the
  bug being re-opened.
- Always include the minimal reproducible request count and the exact tool/technique used (single
  packet, last-byte sync, or scripted Turbo Intruder with a specific gate count) in a finding —
  triagers reproducing financial-impact races need to know whether 2 requests or 30 requests were
  required, since this affects exploitability scoring.
- For financial-impact findings (double withdrawal, currency duplication), cap the demonstrated
  impact at the minimum needed to prove the bug, and never execute the attack against production
  balances beyond what's authorized in the engagement scope — this is standard responsible-testing
  practice for any business-logic financial bug.
