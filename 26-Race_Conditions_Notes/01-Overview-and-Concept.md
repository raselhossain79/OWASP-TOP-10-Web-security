# 01 — Race Conditions: Overview and Core Concept

## What a race condition actually is

A race condition exists whenever an application performs two logically separate steps —
a **check** and an **action** — and there is any gap in time between them during which the
underlying state can be changed by a second, concurrent operation. This pattern is formally
called **Time-Of-Check to Time-Of-Use (TOCTOU)**.

The canonical sequence for a vulnerable operation looks like this:

1. **Check**: the server reads some piece of state (has this coupon been used? does this
   account have sufficient balance? has this token already been redeemed?).
2. **Act**: the server performs the privileged action based on that check (apply the discount,
   transfer the funds, mark the token as used).
3. **Commit**: the server writes the updated state back to permanent storage (database row
   updated, balance decremented, "used" flag set).

In a single-threaded, perfectly serialized world, step 1 always reflects the true current state
because nothing else can run between steps 1 and 3. The vulnerability appears the moment a server
handles requests concurrently (which virtually all modern web servers do, since they are built on
thread pools, async event loops, or multiple worker processes) and the check-act-commit sequence is
not wrapped in an atomic transaction or lock.

## The race window

The **race window** is the period of time between when the check is performed and when the commit
finishes. If a second request for the same operation arrives and is processed by the server during
that window, it will read the *same pre-commit state* that the first request saw — because the
first request hasn't finished updating it yet. Both requests believe they are the only one
operating, so both proceed to completion. This is sometimes described as a temporary **sub-state**:
a state the application transitions into and back out of within the lifetime of a single request,
which is invisible from the outside under normal sequential conditions but exploitable when accessed
concurrently.

Race windows are frequently described in milliseconds, sometimes single-digit milliseconds. They
are not a theoretical edge case — they exist on essentially any endpoint that performs a
read-then-write operation without database-level atomicity (transactions, row locks, unique
constraints, atomic increment/decrement operations).

## Why this differs from "Insecure Design"

Insecure Design (OWASP A04) is a broad category describing any flaw rooted in missing or
inadequate security controls at the architecture level. Race conditions are a specific, mechanical
sub-class of that broader problem with their own:

- **Detection methodology** — predicting collision-capable endpoints, probing with grouped
  parallel requests, and proving the concept by trimming the request set down to the minimum
  reproducible case.
- **Exploitation tooling** — Burp Repeater's grouped "send in parallel" feature and the Turbo
  Intruder extension's single-packet attack technique, both purpose-built to defeat network jitter.
- **A specific root cause class** — non-atomic read-then-write operations — rather than a generic
  absence of threat modeling.

Treating race conditions as their own topic (as PortSwigger does, with a dedicated lab category)
reflects that this is a distinct testing discipline, not just "a kind of business logic bug."

## Classes of race condition

PortSwigger's research (the *Smashing the State Machine* whitepaper, presented at Black Hat USA
2023) and the Web Security Academy break race conditions into the following categories. Each is
covered with concrete examples in `02-Real-World-Exploitation-Scenarios.md`.

### Limit-overrun race conditions

The most common and most intuitive form. A limit imposed by business logic (single-use coupon,
withdrawal cannot exceed balance, one rating per user, CAPTCHA used once, login attempts capped at
N) is exceeded because multiple concurrent requests all pass the check before any of them commits
the updated state.

### Multi-endpoint race conditions

The check and the action are split across *two different requests to two different endpoints*
rather than happening inside one handler. A classic example is adding items to a cart during the
race window between payment validation and order confirmation, when those two steps are processed
by separate endpoint calls. These are harder to exploit because the two endpoints' internal
processing times rarely line up by default — see the section on connection warming and abusing
rate limits in `03` and `04`.

### Single-endpoint race conditions

A single endpoint is hit twice in parallel, but with **different parameter values** rather than
identical ones, in order to cause a collision between two different operations sharing the same
underlying session or record. The password-reset scenario in `02` is the canonical example.

### Partial construction race conditions

An object (a user account, an API key, a session) is created across multiple internal steps —
for example, a row is inserted in one SQL statement and a related field is populated in a second,
separate statement. There's a brief window where the object exists but a field is uninitialized
(empty string, `null`, or similar default). If an attacker can craft a request whose value will
compare as equal to that uninitialized default, they can authenticate as, or interact with, an
object that shouldn't yet be usable.

### Time-sensitive attacks (not always a true race condition)

Some vulnerabilities aren't actually exploitable via concurrency, but still require the same
precise request-timing techniques to exploit — for example, a password reset token generated from
a high-resolution timestamp rather than a cryptographically secure random value. Triggering two
resets timed to land in the same timestamp window can produce a predictable, shared token.

## Real-world framing

Race conditions have become one of the highest-payout bug classes in modern bug bounty programs,
particularly against fintech, e-commerce, and loyalty/rewards platforms, because the impact is
usually directly financial (double-spend, currency duplication, free goods) rather than requiring
chained exploitation to demonstrate severity. Triagers on platforms like HackerOne and Bugcrowd
generally treat a demonstrated limit-overrun against a payment or balance endpoint as Critical or
High severity by default, since the proof-of-concept is self-evidently exploitable at scale
(an attacker can simply repeat the attack to extract unlimited value, not just a single instance
of fraud). This is part of why this class deserves separate, deep coverage rather than being
treated as a single bullet point under "business logic flaws."

## What this series does NOT cover

This series focuses on web application HTTP-layer race conditions (the PortSwigger Academy
scope). It does not cover low-level OS/filesystem TOCTOU races (e.g. symlink races in system
binaries) or race conditions in smart contracts, which are different exploitation domains with
their own tooling.
