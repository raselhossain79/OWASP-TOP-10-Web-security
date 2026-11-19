# Port and Service Enumeration

## 1. Purpose
Identify which network services are exposed on in-scope hosts beyond just the web
port — relevant for both web-focused engagements (finding an exposed admin panel on
a non-standard port) and broader infrastructure testing.

## 2. When to Use
After live host discovery, when the program scope includes IP ranges or full-host
testing (not just a single web application path).

## 3. Prerequisites
Confirmed in-scope IPs/hosts, and confirmation the program permits port scanning
(some web-application-only bug bounty programs explicitly disallow infrastructure
scanning — check scope first).

## 4. Methodology
1. Fast scan across the full port range to find anything open.
2. Targeted service/version detection on discovered open ports only — don't run
   full version detection across all 65535 ports by default, it's slow and noisy
   for little extra benefit on ports that turned out closed anyway.

## 5. Commands

```bash
nmap -p- --min-rate 1000 -T4 target.com -oG initial_scan.gnmap
```
```bash
nmap -sV -sC -p 22,80,443,8080,8443 target.com -oN service_scan.txt
```

## 6. Command Breakdown
- `-p-`: scans all 65535 TCP ports, not just the common top-1000 default.
- `--min-rate 1000`: tells nmap to send at least 1000 packets/second — speeds up the
  full-range scan considerably, but increases the chance of triggering network-level
  alerting/rate limiting on sensitive targets. Lower this on programs that state
  strict rate-limit requirements.
- `-T4`: a timing template (0–5 scale) balancing speed vs. reliability; `T4` is
  "aggressive" and generally safe on stable internet connections, but can produce
  inaccurate results on unreliable links.
- `-oG`: "grepable" output format, convenient for scripting the next command against
  only the ports that came back open.
- `-sV`: service/version detection — sends additional probes to identify the actual
  software and version behind each open port.
- `-sC`: runs nmap's default safe script set against open ports (banner grabbing,
  basic enumeration) — "safe" here means non-intrusive by nmap's own script
  classification, not a guarantee of zero impact.
- `-oN`: normal human-readable output file.

## 7. Expected Output
A list of open ports with service names/versions, e.g.:
```
22/tcp open ssh OpenSSH 8.9p1
443/tcp open https nginx 1.24.0
8080/tcp open http Apache Tomcat 9.0.70
```

## 8. Interpretation
An open, unexpected port (e.g. `8080` running Tomcat on a target you only knew as a
marketing site) is a new attack surface entry point — feed it back into
`live-host-discovery.md`/`technology-fingerprinting.md` as its own asset, not just a
footnote on the main domain.

## 9. False Positives
- Version strings reported by `-sV` are the banner the service presents, which
  administrators sometimes deliberately alter — treat the version as a lead to
  confirm, not a settled fact, before relying on it for a specific CVE hypothesis.
- Firewalls/IPS can return `filtered` rather than `closed` for blocked ports, which
  is different from "not running a service there" — don't conflate the two.

## 10. Next Action
Any open web-adjacent port (8080, 8443, 3000, etc.) goes back through
`technology-fingerprinting.md`. SSH/other services are generally outside a
web-focused testing scope unless the engagement explicitly covers infrastructure.

## 11. Safety Considerations
Full port-range scans are the most likely single action in the recon phase to
trigger network-level security alerting (IDS/IPS). Confirm scope explicitly permits
this before running it, and use conservative timing (`-T2`/`-T3`) on anything marked
as sensitive or production-critical by the program.

## 12. Documentation
Keep the raw nmap output files — they're standard, reviewer-recognizable evidence
format for a report appendix.
