# Race Conditions (TOCTOU) — Vulnerability Note Series

A structured reference series on Race Condition vulnerabilities in web applications, focused on
Time-Of-Check to Time-Of-Use (TOCTOU) flaws. This is treated as its own category, distinct from
general Insecure Design, because it has a dedicated exploitation methodology, dedicated tooling
(Burp Repeater parallel requests, Turbo Intruder single-packet attack), and a dedicated lab
progression on PortSwigger Web Security Academy.

## Files in this series

| File | Contents |
|---|---|
| `01-Overview-and-Concept.md` | Core mechanism: what a race condition is, why the check/action gap exists, race windows, sub-states, classification (limit-overrun, multi-endpoint, single-endpoint, partial construction, time-sensitive). |
| `02-Real-World-Exploitation-Scenarios.md` | Concrete exploitation patterns: coupon/discount reuse, double withdrawal, one-time-limit bypass, multipart upload races, MFA/2FA bypass races, password reset token races — each with the underlying flawed logic and real-world bug bounty framing. |
| `03-Turbo-Intruder-Single-Packet-Attack.md` | Full breakdown of the Turbo Intruder Python script structure for the single-packet attack technique: engine setup, gates, concurrency settings, and exactly why each line affects the race window. |
| `04-Cheatsheet-and-Lab-Mapping.md` | Quick-reference cheatsheet, detection checklist, and the PortSwigger Web Security Academy Race Conditions labs mapped to techniques, in official difficulty-progression order. |

## How this series was verified

The lab list and technique descriptions in this series were cross-checked directly against the
current PortSwigger Web Security Academy "Race conditions" topic page and the official lab listing
before writing, rather than relying on memory. The Academy's Race Conditions topic currently has a
complete, well-developed set of 6 labs spanning Apprentice through Expert difficulty — there are no
missing or undocumented techniques in this category, unlike some other topics in this series where
PortSwigger has gaps.

## Suggested reading order

1. Read `01` to internalize the core TOCTOU mechanism before touching any tooling.
2. Read `02` to see how the mechanism maps onto real bug classes you'll find in bounty programs.
3. Read `03` before attempting any lab that requires Turbo Intruder — understand the script before running it.
4. Use `04` as your working reference while solving labs and during live engagements.
