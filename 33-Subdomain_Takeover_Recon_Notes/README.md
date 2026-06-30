# Subdomain Takeover & Attack Surface Mapping — Reference Notes

A GitHub-ready reference series covering attack surface mapping methodology, subdomain
enumeration tooling, subdomain takeover exploitation, and content discovery. Built for
real-world bug bounty and penetration testing engagements, not just lab theory.

## Why This Series Exists

Subdomain takeover is a specific, high-value, high-payout vulnerability class on every
major bug bounty platform. But it cannot be found without solid reconnaissance —
subdomain enumeration is the tooling foundation that surfaces the dangling DNS records
in the first place. Rather than scatter recon methodology across other vulnerability
note series, this series treats it as a first-class topic with its own dedicated
coverage, then builds subdomain takeover and general attack surface mapping on top of it.

## File Structure

| File | Contents |
|---|---|
| `01-Overview-and-Methodology.md` | What attack surface mapping is, the recon → takeover → discovery pipeline, where this fits in an engagement, PortSwigger Academy lab coverage disclosure |
| `02-Recon-Tooling-Amass-Subfinder-httpx.md` | Passive recon (certificate transparency, DNS aggregators), active brute-forcing, and flag-by-flag breakdown of Amass, Subfinder, and httpx |
| `03-Subdomain-Takeover-Exploitation.md` | Dangling DNS record theory, CNAME fingerprint database per cloud provider, claiming a resource, demonstrating impact, automation tooling |
| `04-Content-Discovery-ffuf-gobuster.md` | Technology stack identification, exposed endpoint/parameter discovery, flag-by-flag breakdown of ffuf and gobuster |
| `05-Checklist.md` | End-to-end engagement checklist tying every file together |

## How to Use This Series

Read in order if you're new to recon-driven bug hunting: methodology first, then tooling,
then exploitation, then content discovery, then use the checklist as a field reference
during live engagements.

If you already understand recon fundamentals, jump straight to
`03-Subdomain-Takeover-Exploitation.md` for the takeover-specific content and the CNAME
fingerprint reference table.

## Lab Coverage Note

This category is infrastructure and DNS-focused rather than application-logic-focused,
so PortSwigger Web Security Academy has **no dedicated lab category** for subdomain
takeover or recon methodology. This is addressed explicitly in
`01-Overview-and-Methodology.md`. Real practice for this category comes from live bug
bounty programs (HackerOne, Bugcrowd) and intentionally vulnerable cloud-takeover labs
(e.g., `0xpatrik`'s resources, `EdOverflow`'s `can-i-take-over-xyz` repository) rather
than Academy.

## Conventions Used Throughout

- Every command is broken down flag by flag — what it does and why, never "just run this."
- Real-world industry framing in every file (what this looks like on an actual program).
- Honest gap disclosure where lab coverage doesn't exist.
- Full English only.
