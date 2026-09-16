# DNS Rebinding — Awareness-Level Notes

## Scope note (read first)

This folder is intentionally kept **light** — one file, awareness-level
depth — rather than following the multi-file (overview + sub-technique +
tooling + WAF-bypass + cheatsheet) convention used elsewhere in this
library. Rationale: DNS rebinding is a real, documented technique, but for a
web/API-focused pentest and bug bounty practice (this repo's actual scope),
it comes up rarely — it's primarily relevant to browser-driven attacks
against internal network services (IoT devices, internal admin panels,
localhost-bound dev servers) rather than typical web/API application
findings. This folder exists for reference completeness so the concept is
documented when a target does call for it, without over-investing study
time here relative to the 🔴 High topics elsewhere in this repo.

## File

- `01-mechanism-detection-remediation.md` — what it is, how to recognize a
  vulnerable target, and how it's fixed.
