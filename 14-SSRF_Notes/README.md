# Server-Side Request Forgery (SSRF) — OWASP A10:2021

Complete technical note series on Server-Side Request Forgery, built to the same
standard and depth as the SQL Injection series in this repository: every payload
broken down piece by piece, every PortSwigger lab mapped honestly in official
Academy order, and real-world framing throughout rather than lab-only theory.

## Why SSRF is A10:2021

SSRF was added to the OWASP Top 10 in the 2021 revision as a standalone category
for the first time (previously it sat inside broader categories). OWASP's own
justification for promoting it: industry survey data showed SSRF had a
above-average incidence rate despite below-average testing coverage, and the
community specifically flagged its growing relevance as architectures moved into
cloud and containerized environments where internal services and metadata
endpoints became high-value, frequently reachable targets.

## File Index

| # | File | Covers |
|---|------|--------|
| 1 | `01-SSRF-Overview-Classification.md` | What SSRF is, attack categories, trust-boundary theory, real-world incident context |
| 2 | `02-Basic-Blind-SSRF.md` | Direct/visible SSRF, blind SSRF, out-of-band detection, Shellshock chaining |
| 3 | `03-Filter-Bypass-Techniques.md` | Blacklist bypass, whitelist bypass, IP encoding tricks, DNS rebinding, open-redirect bypass |
| 4 | `04-Cloud-Metadata-Exploitation.md` | AWS IMDSv1/v2, GCP metadata, Azure IMDS — full exploitation chains |
| 5 | `05-SSRFmap-Tool.md` | SSRFmap — every flag, every module, explained |
| 6 | `06-Gopherus-Tool.md` | Gopherus — gopher:// payload generation for internal service attacks |
| 7 | `07-Cheatsheet-Lab-Mapping.md` | Capstone cheatsheet + verified PortSwigger lab mapping table |

## How This Series Is Built

- **Every command/payload is broken down.** No "just use this" — every part of a
  URL, header, or CLI flag is explained: what it does and *why* it triggers the
  bypass or the request.
- **PortSwigger labs are mapped in real Academy order**, not grouped by theme.
  The SSRF topic on the Academy currently has **7 labs total**. That is the full
  set — this series does not pad the mapping with labs that don't exist or
  labs borrowed from other topics (e.g. the XXE-to-SSRF lab is noted separately
  in the cheatsheet as a cross-topic bonus, not counted as an SSRF-topic lab).
- **Full English only.** No Bangla/Banglish in any file.
- **Real-world framing** in every file — actual disclosed breaches, bug bounty
  patterns, and production architecture notes, not just lab walkthroughs.

## Suggested Reading Order

Read files 1 → 7 in order. The technique files (2, 3) follow the exact
difficulty progression PortSwigger uses for its own labs, so working through
them in order mirrors how you'd actually progress through the Academy.
