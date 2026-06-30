# Real-World Exploitation & Vulnerability Chaining

**Capstone series — read this AFTER completing the individual vulnerability-type series.**

This series does not teach a new vulnerability class. It teaches the methodology that
separates someone who can solve a known PortSwigger lab pattern from someone who can
walk into an unfamiliar bug bounty target or pentest engagement and find critical,
client-impacting issues. The core skill is **chaining**: combining multiple
individually low-severity bugs into one finding that a triager cannot dismiss.

## Who this is for

You've already built (or are building) standalone reference notes for SQLi, XSS, SSRF,
IDOR, SSTI, XXE, File Upload, LFI/RFI, Request Smuggling, Race Conditions, Mass
Assignment, CORS, Open Redirect, Subdomain Takeover, Host Header Injection, Web Cache
Poisoning, Clickjacking, and the rest of the OWASP Top 10 categories. This series
assumes that mechanism-level knowledge exists already and builds on top of it.

## File index

| File | Covers |
|---|---|
| `01-overview.md` | What chaining is, why "low severity" bugs are dangerous, the mindset shift from lab-solving to real-world hunting |
| `02-chain-patterns.md` | 14 documented real-world chain patterns, broken down step by step |
| `03-attack-surface-mapping.md` | Methodology for mapping an unfamiliar target's full attack surface |
| `04-adapting-to-unknowns.md` | Fuzzing methodology and behavioral inference when there's no known CVE or lab pattern to match |
| `05-real-world-waf-behavior.md` | How production WAFs differ from lab conditions, and how to test around that |
| `06-end-to-end-methodology.md` | Full recon → mapping → testing → chaining → reporting checklist |
| `07-report-writing-for-chains.md` | How to document a multi-step chain so a client or triager doesn't underscore the impact |

## How to use this series

Read `01` through `07` in order once, then keep `06` (the checklist) and `02` (the
pattern catalog) open as working references during live engagements. `07` should be
revisited every time you're about to submit a report — chained findings are the ones
most commonly underpaid or downgraded because the writeup fails to make the impact
obvious.

## Conventions carried over from the rest of the library

- Mechanism-first explanations — every chain step explains *why* it works, not just
  *that* it works.
- Real-world industry framing throughout.
- Honest gap disclosure: chaining is inherently target-specific, so this series gives
  you the patterns and the thinking process, not a single canned walkthrough. There is
  no PortSwigger Academy lab series that teaches chaining directly as a category — the
  closest official material is scattered across individual labs (e.g. the SSRF cloud
  metadata labs, the OAuth account-takeover labs). This series fills that specific gap.
