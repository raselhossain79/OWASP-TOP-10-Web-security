# Host Header Injection & Password Reset Poisoning — Note Series

A complete, GitHub-ready reference covering HTTP Host header attacks: classic header
injection (cache poisoning, routing-based SSRF), the password-reset-poisoning chain, and
header-trust issues involving `X-Forwarded-Host` and `X-Forwarded-For`. Built to match the
structure and depth of the SQL Injection series in this same notes library — every payload
is broken down piece by piece, with mechanism explanations and PortSwigger Web Security
Academy lab mappings in official difficulty order.

This topic maps to **OWASP Top 10 A01:2021 — Broken Access Control** (Host header
authentication bypass, routing-based SSRF reaching internal admin functionality) and
**A05:2021 — Security Misconfiguration** (trusting unvalidated forwarding headers,
flawed Host validation), with the password-reset-poisoning chain specifically
demonstrating account-takeover impact.

## Files in this series

| File | Contents |
|---|---|
| [`01-overview-and-classification.md`](01-overview-and-classification.md) | What the Host header is, why the trust model breaks, full classification table, detection methodology, host-based auth bypass, vhost brute-forcing, connection-state attacks, prevention |
| [`02-password-reset-poisoning-chain.md`](02-password-reset-poisoning-chain.md) | The full account-takeover chain step by step: legitimate reset flow, where the link domain comes from, weaponizing it against a victim, the dangling-markup variant, chain-specific defenses |
| [`03-header-trust-and-routing-issues.md`](03-header-trust-and-routing-issues.md) | `X-Forwarded-Host`/`X-Host`/`Forwarded` trust issues, multi-header cache poisoning, `X-Forwarded-For` access-control and rate-limit bypass, routing-based SSRF against internal infrastructure, SSRF via flawed request-line parsing |
| [`04-cheatsheet-and-lab-mapping.md`](04-cheatsheet-and-lab-mapping.md) | Quick detection checklist, payload reference table, tooling notes (Burp Repeater/Intruder/Collaborator, Param Miner), full PortSwigger Academy lab list in official difficulty order, honest disclosure on cross-topic labs |

## How to use this series

1. Start with File 01 to understand the shared root cause behind every variant in this
   topic — that's what makes the rest of the series make sense rather than feeling like a
   list of unrelated tricks.
2. Read File 02 for the highest-impact real-world chain (password reset poisoning →
   account takeover).
3. Read File 03 for the broader header-trust landscape and routing-based SSRF.
4. Use File 04 as your working reference during actual testing/lab practice, and to find
   the exact PortSwigger lab for each technique.

## Conventions used throughout this series

- Every request example is annotated with a **mechanism breakdown** — which header is
  being manipulated, what the server-side component does with it, and why that produces
  the vulnerability. No payload is presented as "just send this."
- PortSwigger Web Security Academy labs are mapped to techniques in their **official
  difficulty-progression order**, with honest disclosure where a relevant technique's lab
  lives under a different Academy topic.
- Real-world/industry framing is included throughout — how this shows up in actual cloud
  and microservice architectures, not just lab theory.
- Written entirely in English.
