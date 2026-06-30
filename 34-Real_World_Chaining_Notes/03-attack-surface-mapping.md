# 03 — Attack Surface Mapping for an Unfamiliar Target

Chaining requires knowing what *else* exists in an application before you can ask
"does this bug connect to anything." That means mapping the full attack surface
**before** going deep on any single finding — going deep too early is the most common
reason hunters miss chains: they spend six hours perfecting one XSS payload on a
target they've only seen 10% of.

## Phase 1 — Passive reconnaissance (no traffic to the target's app logic)

The goal here is to discover scope *without* touching anything that could be logged
as exploitation traffic — pure OSINT and DNS work.

- **Subdomain enumeration.** Pull from certificate transparency logs, DNS
  aggregators, and passive sources before sending a single active probe. This is
  where subdomain takeover candidates (chain pattern 7) and forgotten staging/
  internal environments get found.
- **Technology fingerprinting from passive sources.** Job postings, GitHub repos
  (including the target's *employees'* personal repos — internal tool names, API
  paths, and config samples leak this way constantly), Wayback Machine snapshots of
  old versions of the app that may still reveal endpoints removed from the current
  UI but not from the backend.
- **Cloud asset discovery.** Search for exposed storage buckets (S3, GCS, Azure
  Blob) using the target's naming conventions — these are frequently misconfigured
  independently of the main application and are a common source of the credentials
  that make chain pattern 2 (SSRF + cloud metadata) immediately monetizable.
- **API documentation and JS bundle inspection.** Pull every JS file the app loads
  and grep it for endpoint paths, internal field names, and feature flags. Modern
  SPAs routinely ship API routes in the bundle for features not yet visible in the
  UI — these are prime mass-assignment (chain pattern 11) and IDOR candidates because
  they're the least-tested code paths.

## Phase 2 — Active content discovery

- **Directory/endpoint brute-forcing** against each discovered host, using
  wordlists informed by what you found in phase 1 (don't run a generic wordlist
  blind when you already have real API path fragments from the JS bundle —
  permutate those instead).
- **Parameter discovery** on every endpoint you find — many vulnerabilities (mass
  assignment, SSRF via a webhook URL field, open redirect via an undocumented
  `redirect`/`continue`/`next` param) only appear once you know a parameter exists
  at all, since it's never rendered in any visible UI element.
- **Authenticated vs. unauthenticated surface mapping.** Walk through every
  available account role (if you have multiple test accounts/tiers) and diff what
  each role can reach. The *difference* between roles is exactly where access
  control failures (chain patterns 1, 11) live.

## Phase 3 — Functional inventory (the part most hunters skip)

Build an actual written inventory, not just a mental model. For every distinct
feature you find, record:

| Feature | Input it accepts | What it does with that input | Output/state it produces |
|---|---|---|---|
| "Export report as PDF" | a URL or HTML template selection | server-side fetch/render | PDF file, served back to user |
| "Add webhook for events" | a URL | server makes outbound request to that URL on trigger | HTTP request from app's infra to attacker-controlled endpoint |
| "Upload profile photo" | file content | stored, served from CDN/static path | file at a predictable or returned path |
| "Update profile" | JSON body | bound to user model | persisted user record |

This table is the actual mechanism for spotting chains. Look at the "input it
accepts" and "output/state it produces" columns across every row: any row whose
*output* matches another row's *input* is a candidate chain. In the table above,
"Add webhook" produces an outbound server-side request — that's an SSRF candidate
by itself, and its primitive (server makes a request to an attacker-chosen URL) is
exactly what chain pattern 2 needs. "Upload profile photo" produces a file at a path
— if any other feature in your inventory *includes* a file by path (a template
loader, a report generator referencing a stored file), that's chain pattern 8.

## Phase 4 — Tracking findings as you go (don't wait until the end)

Keep a running log, separate from your final report, structured as:

- **Finding**: short description
- **Primitive gained**: input control / read access / write access / trust /
  timing-state (see file `01`)
- **Confirmed or suspected**: be honest — half your log entries at any given time
  should be suspected-but-unconfirmed, that's normal
- **Possible chain target**: which other feature in your Phase 3 inventory this
  primitive might feed into

Re-read this log every time you confirm a *new* bug — the new bug might be the
missing "Bug B" for something you logged on day one and otherwise would have
forgotten about.

## What "full" attack surface actually means in practice

You will rarely have time to exhaustively map 100% of a large target. Prioritize by
where chains are statistically richest:

1. **Anything that makes an outbound server-side request** (webhooks, URL-fetch
   features, link previews, PDF/image generation from URL) — highest-value for SSRF
   chains.
2. **Anything that stores user-controlled content and is later rendered or included
   elsewhere** (uploads, rich-text fields, templates) — highest-value for stored
   XSS and LFI/upload chains.
3. **Anything involving identity or session state across a boundary** (OAuth flows,
   SSO, password reset, subdomain/cookie scoping) — highest-value for account
   takeover chains.
4. **Anything with a "check then act" two-step pattern** (redemptions, transfers,
   limited-use codes) — highest-value for race condition chains.

This isn't a complete taxonomy of the application — it's a prioritized lens for where
to spend mapping time first when the clock is limited, which is the realistic
condition on both bug bounty (your own time budget) and pentest (contracted time
window) engagements.

Once the map exists, file `06`'s end-to-end checklist tells you how to move from this
map into systematic testing and, where a known bug class doesn't immediately apply,
file `04` covers how to approach the parts of the surface that don't match anything
you've seen in a lab before.
