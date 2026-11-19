# Reconnaissance Tools — Quick Reference

Covers tools used in `02-Asset-Discovery/` and `03-Origin-Infrastructure/`. For full
usage and flag explanations, see the relevant module file — this is a lookup table,
not a substitute for those.

| Tool | Used For | Passive/Active | Module |
|---|---|---|---|
| `subfinder` | Subdomain enumeration via passive sources | Passive | subdomain-enumeration.md |
| `puredns` | DNS brute-forcing | Active | subdomain-enumeration.md |
| `dnsx` | Bulk DNS resolution | Active (low noise) | live-host-discovery.md |
| `httpx` | HTTP probing, tech hints, status/title | Active (low noise) | live-host-discovery.md |
| `nmap` | Port/service scanning | Active | port-service-enumeration.md |
| `whatweb` | Technology fingerprinting | Active | technology-fingerprinting.md |
| `wafw00f` | WAF product fingerprinting | Active (low noise) | cdn-waf-identification.md, waf-detection.md |
| `shodan` (CLI/web) | Cert/favicon-hash search, exposed service search | Passive | origin-ip-discovery.md |
| `openssl` | TLS certificate inspection | Active (single connection) | origin-ip-discovery.md |
| `gau` | Historical URL collection | Passive | endpoint-discovery.md |
| `katana` | Site/JS crawling | Active (standard page load traffic) | javascript-analysis.md, endpoint-discovery.md |
| `ffuf` | Directory/parameter brute-forcing | Active | endpoint-discovery.md |
| `arjun` | Parameter discovery via response-diffing | Active | parameter-discovery.md |
| `trufflehog` | Secret scanning in collected content | Passive (operates on downloaded content) | javascript-analysis.md |

## Notes
- Version/output format differences exist across tool versions — always check
  `--help` for the installed version if a command here doesn't behave as described.
- "Passive" here means no deliberately crafted/abnormal requests sent to the
  target's own infrastructure — normal page loads and third-party data source
  queries still generate some traffic.
