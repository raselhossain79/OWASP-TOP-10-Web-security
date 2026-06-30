# 01 — Overview: What Chaining Is, and Why It's the Real Skill

## The gap this file addresses

Every individual vulnerability-type series in this library teaches you to recognize
and exploit one bug class cleanly. That's necessary, but it's not what gets you paid
in bug bounty or what makes a pentest report land with a client. Real applications are
not PortSwigger labs. A lab is built so that one vulnerability, exploited correctly,
produces one clean flag. A production application is a pile of features built by
different teams over different years, and its most serious security failures
*almost never live in a single bug*. They live in the gap between two or three bugs
that, individually, look minor.

This is the single biggest mindset shift between "I finished the labs" and "I can
hunt on a live target": **stop looking for the bug. Start looking for the chain.**

## Why low-severity findings matter

In lab training, a self-XSS, an open redirect, a verbose error message, or an IDOR
that only leaks a username is treated as a dead end — interesting, but not worth a
flag. On a real target, every one of those is a potential *component*. A self-XSS
becomes exploitable the moment you find a CSRF flaw that lets you force a victim into
the vulnerable state. An open redirect that "only" sends a user to an attacker domain
becomes an account takeover the moment the target's OAuth flow trusts the same
redirect parameter for `redirect_uri` validation. A verbose stack trace that "only"
reveals a framework version becomes a precise SSTI payload selection.

The practical consequence: **never throw away a low-severity finding.** Log it,
understand exactly what it gives you (what input it lets you control, what state it
lets you reach, what information it leaks), and keep it in your notes for the rest of
the engagement. The bugs you find on day one of a target often only become useful on
day three, once you understand more of the application.

## The core question behind every chain

Every chain pattern in this series reduces to one question, asked over and over as
you move through an application:

> **What does this bug give me control over, or visibility into, that I didn't have
> before — and is there another part of this application that consumes that exact
> thing?**

A bug "gives" you one or more of these primitives:

- **Input control** — you can inject a value into a place the app didn't expect
  (a header, a parameter, a filename, a redirect target).
- **Read access** — you can read something you shouldn't (a file, an internal
  response, another user's data, a token).
- **Write access** — you can write or store something an attacker controls
  (a file, a cached response, a database row, a session value).
- **Trust** — you can act as, or be trusted as, an entity you shouldn't be
  (another user, an internal service, a same-origin script).
- **Timing/state** — you can manipulate the order or repetition of operations
  (race conditions, TOCTOU windows).

Chaining is the practice of taking the primitive one bug gives you and finding the
exact place in the application where that primitive is the missing ingredient for a
second bug. File `02` walks through fourteen documented patterns built on exactly this
logic.

## Why this matters more in bug bounty specifically

Bug bounty triagers see the same individual bug classes hundreds of times. A bare
reflected XSS on a low-traffic parameter, or an IDOR that leaks a non-sensitive field,
gets triaged fast and paid at the bottom of the scale — if it's accepted at all. The
reports that get paid at P1/Critical, and the reports that get read carefully by a
program manager instead of auto-triaged, are the ones that demonstrate **realistic,
documented business impact**. A chain that ends in account takeover, data exfiltration
at scale, or remote code execution is unambiguous. It removes the triager's ability to
argue about severity, because you've already shown the full path from "attacker has
nothing" to "attacker has everything."

This is also why file `07` exists as a dedicated topic. A chain that is technically
correct but written up as a list of disconnected findings will frequently be
**downgraded by the triager**, because they will evaluate each step independently
unless your report explicitly walks them through the connection. Writing the chain
clearly is not optional polish — it is part of the exploit.

## Why this matters more on authorized pentest engagements

A client paying for a penetration test is not paying you to confirm that their WAF
blocks `' OR 1=1--`. They are paying you to tell them what an attacker with no inside
knowledge could actually achieve against their environment. A report listing fifteen
isolated medium-severity findings is far less useful to a client's risk committee than
a report showing that findings 3, 7, and 12 combine into a single critical path to
their production database. Chaining is also how you demonstrate engagement value when
individual findings are mundane — which, on a mature target, they usually are.

## What the rest of this series covers

- `02-chain-patterns.md` — fourteen real, documented chain patterns with the exact
  mechanism connecting each step.
- `03-attack-surface-mapping.md` — how to inventory everything an application exposes
  *before* you start testing, so you can recognize chain opportunities as you find
  individual bugs.
- `04-adapting-to-unknowns.md` — what to do when a target doesn't match any known lab
  pattern or CVE, including fuzzing methodology and behavioral inference.
- `05-real-world-waf-behavior.md` — how production defenses differ from lab
  environments and how that changes your testing approach.
- `06-end-to-end-methodology.md` — a full checklist tying recon through reporting
  together as one repeatable process.
- `07-report-writing-for-chains.md` — how to write up a multi-step finding so its
  severity is obvious to a non-technical reader.

The mindset to carry into every file that follows: **a vulnerability is not "found"
until you've asked what it connects to.**
