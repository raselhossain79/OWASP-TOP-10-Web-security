# Validation and Evidence Collection

## 1. Purpose
Turn an interesting result into a defensible finding. This is the step that
separates a report that gets acted on from one that gets marked "not applicable"
or "informative" by a triager.

## 2. When to Use
Immediately after any detection signal from `06-Vulnerability-Testing/`, before
writing anything up.

## 4. Methodology

### a) Reproduce before reporting
Run the exact same test 2–3 times. A finding that doesn't reproduce consistently
is not ready to report — figure out why first (timing variance? session state
changed? caching?) rather than reporting an inconsistent result and hoping the
triager can reproduce it.

### b) Isolate the variable
Change only the one thing that matters, and confirm the signal tracks it
predictably. For SQLi: does `SLEEP(10)` take roughly twice as long as `SLEEP(5)`?
For boolean-based: does the "false" version of the condition reliably differ from
the "true" version across repeats? If the signal doesn't track the variable you
believe is causing it, you haven't actually isolated the real cause yet.

### c) Rule out alternate explanations
Before concluding a finding is real, actively try to disprove it:
- Could a cache be producing this result regardless of my input?
- Could this be a WAF/rate-limit artifact rather than an application behavior?
- Could the "other user's data" I'm seeing actually be intentionally public?
- Could the timing delay be general server load rather than my payload?

### d) Minimal reproduction
Reduce the proof to the smallest request/payload that still demonstrates the
issue. A report with a 200-character obfuscated payload when a single quote would
have shown the same thing makes the issue harder for a triager to verify quickly
— simpler evidence is stronger evidence, not weaker.

### e) Capture the evidence artifacts
- Full request (every header, full body) and full response, as sent/received —
  not a paraphrase.
- A screenshot where the response is visual (XSS execution, UI-rendered data
  exposure).
- For timing-based findings, multiple timing samples, not just one.
- A short, plain description of *why* this request/response pair demonstrates the
  vulnerability — don't assume it's self-evident to someone seeing it for the
  first time.

## 9. Common False-Positive Sources (recap/expansion)
| Source | Symptom | How to rule out |
|---|---|---|
| Caching | Same "finding" appears regardless of payload validity | Repeat identical request twice; stale/cached response won't change |
| WAF/rate-limit artifacts | Block page resembles an app error | Compare against a confirmed clean baseline and a confirmed WAF block page side by side |
| Session/state drift | Result differs between identical-looking requests | Confirm session/cookie state is actually identical between the two requests |
| Intentionally shared data | "Unauthorized" access to data that's actually public | Check the feature's own UI for a public/shared indicator |
| Tool-reported false positive (e.g. automated scanner) | A scanner flags something a manual request doesn't reproduce | Always manually verify any automated tool finding before relying on it |

## 11. Safety Considerations
Minimal reproduction isn't just about report clarity — it's also the safest
approach: the smallest payload/request that proves the issue is also the one
least likely to cause unintended side effects (data modification, service
disruption) on the live target.

## 12. Documentation
The deliverable from this phase is the evidence package `09-Reporting/
professional-reporting.md` will draft from: request, response, reproduction
steps, and the plain-language explanation of impact.
