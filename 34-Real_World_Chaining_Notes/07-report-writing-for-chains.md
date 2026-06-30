# 07 — Report Writing for Chained/Multi-Step Findings

A technically correct chain that's poorly written up gets misjudged constantly — bug
bounty triagers and pentest report reviewers default to evaluating each step on its
own unless your writeup actively prevents that. This file is a structure and a set of
habits specifically for multi-step findings, building on whatever general reporting
conventions your existing series/templates already use.

## Why chains get under-rated in reports

Two failure modes account for most underscored chain reports:

1. **The report describes the steps but never explicitly states the combined
   impact up front.** A reviewer skimming the summary sees "found an open redirect"
   and "found a loose OAuth redirect_uri check" as two separate medium items, because
   the connection between them was buried in paragraph four instead of stated in
   sentence one.
2. **The report doesn't give the reviewer enough evidence to verify each link
   independently**, so a skeptical reviewer (correctly, from their position) treats
   the unverified middle steps as unconfirmed and rates the finding by its weakest
   substantiated link rather than its strongest demonstrated outcome.

Both are solved by structure, not by writing more — the fix is *how* the information
is sequenced and evidenced, covered below.

## Structure for a chained-finding report

### 1. Title — state the end impact, not the starting bug

Bad: "Open Redirect on /go endpoint"
Better: "Account Takeover via OAuth Authorization Code Theft (chained: Open Redirect
+ redirect_uri validation flaw)"

The title is read first and often skimmed alone when a program is triaging volume —
it needs to carry the actual severity on its own.

### 2. Impact summary (2-4 sentences, before any technical detail)

State, in plain language, what an attacker can ultimately achieve, who is affected,
and roughly how (named at a high level, not yet step-by-step). This section should be
understandable by a non-technical stakeholder and should make the severity
unambiguous without requiring them to read further. This is the single most
frequently skipped section by hunters in a hurry, and it's the section that prevents
the under-rating failure mode above.

### 3. Chain overview (a short numbered list before the detailed walkthrough)

A compressed version of the full chain, e.g.:

1. Attacker abuses open redirect at `/go?next=` to control final redirect destination
2. Attacker crafts an OAuth authorization URL using the application's loosely-
   validated `redirect_uri`, pointing through step 1's redirect to an attacker domain
3. Victim authenticates via the crafted link; authorization code is delivered to
   attacker's domain via the chained redirect
4. Attacker exchanges the stolen code for an access token, completing account
   takeover

This numbered overview lets a reviewer mentally hold the whole chain before getting
into evidence-heavy detail — it's a map of what's coming.

### 4. Step-by-step technical walkthrough, each step independently evidenced

For each numbered step from the overview, include:

- **What was sent** (exact request, including relevant headers)
- **What was observed** (exact response, or the specific server-side effect
  confirmed)
- **Why this step works** — the mechanism, in the same style as file `02`'s
  pattern breakdowns: what does this step give the attacker, and how does it connect
  to the *next* step specifically
- **Evidence** — screenshot, raw request/response, or video for steps involving
  timing/race conditions or multi-request sequences that are hard to capture in a
  static screenshot

Treat each step as something that needs to survive a skeptical reviewer checking it
in isolation. If a reviewer can independently verify steps 1, 2, 3, and 4 each on
their own evidence, they cannot reasonably dispute the combined conclusion — this is
the core technique for preventing the under-rating problem.

### 5. Proof of concept — the full chain executed end to end

Separate from the step-by-step breakdown, include one clean, complete demonstration
of the entire chain run start to finish — a single video or a tightly sequenced
screenshot set showing the unbroken path from "attacker has nothing" to "attacker has
full account access" (or whatever the end state is). This is what most reviewers will
actually watch/look at first, with the step-by-step section serving as backup detail
for anyone who wants to verify a specific link.

### 6. Severity justification, explicitly addressing "why not just the weakest
   link's severity"

Directly state why the combination is rated above any individual component, e.g.:
"While the open redirect alone is typically Low severity and the redirect_uri
validation gap alone would be Medium (limited without a same-host endpoint to abuse),
their combination enables unauthenticated account takeover with no user-visible
warning, which is rated Critical." Naming the individual components' standalone
severity *and* explaining the jump is what stops a reviewer from anchoring on the
lower number.

### 7. Remediation — address every link, not just one

A chain breaks if *any* link is fixed, so list remediation for each component
separately, and note that fixing only one is sufficient to break this specific chain
even if the others remain present as standalone lower-severity issues. This is
genuinely useful to the client/program (clear, actionable, prioritizable) and also
demonstrates you understand the chain isn't a single monolithic bug.

## Habits that prevent disputes during triage

- **Never claim a step you haven't actually demonstrated.** If you've confirmed
  steps 1, 2, and 4 but step 3 is inferred rather than directly observed (common with
  blind/timing-based steps), say so explicitly and explain why the inference is
  sound (e.g. via an out-of-band confirmation channel) rather than presenting it with
  the same confidence as the directly-observed steps. Reviewers downgrade hard when
  they catch an overstated step that turns out to be inferred and they weren't told —
  it damages trust in the rest of the report.
- **Timestamp and correlate evidence across steps**, especially for race-condition or
  multi-actor chains (e.g. one chain step performed as a victim test account, the
  next as the attacker test account) — a reviewer needs to be able to follow that
  these are genuinely sequential parts of one scenario, not unrelated tests.
- **State the realistic attacker prerequisite clearly** (does this require the
  victim to click a link? Visit a page with no interaction? Does it require the
  attacker to already have a low-privilege account?) — this directly affects severity
  scoring on most frameworks (CVSS user-interaction and privileges-required metrics)
  and a vague writeup forces the reviewer to guess, usually conservatively, in the
  finding's disfavor.
