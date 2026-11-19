# Subdomain Enumeration

## 1. Purpose
Find every subdomain belonging to the target so you know the full breadth of
in-scope assets before narrowing down to live, testable hosts.

## 2. When to Use
First recon action on any new target with a wildcard scope (`*.target.com`).

## 3. Prerequisites
Confirmed scope (see `01-Scope-and-Authorization.md`) including whether wildcard
subdomains are genuinely in-scope or only specific listed ones.

## 4. Methodology
1. **Passive enumeration first** (no direct interaction with target infrastructure):
   certificate transparency logs, passive DNS aggregators, search engine dorking.
2. **Active enumeration second** (only once passive sources are exhausted and scope
   permits active probing): DNS brute-forcing against a wordlist.
3. **Resolve and dedupe** everything collected into one list before moving to live
   host discovery.

## 5. Commands

```bash
subfinder -d target.com -silent -o subs_passive.txt
```
```bash
# Certificate transparency, manually via crt.sh (passive, no rate-limit risk)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```
```bash
# Active brute-force (only after confirming the program allows active DNS enumeration)
puredns bruteforce wordlist.txt target.com -r resolvers.txt -o subs_active.txt
```

## 6. Command Breakdown
- `subfinder -d target.com`: queries dozens of passive sources (APIs, cert logs)
  aggregated by the tool — this is why it's listed as passive even though it makes
  network requests: it queries third-party data sources, not the target directly.
- `-silent`: output-only mode, no banner, useful when piping to another tool.
- `crt.sh/?q=%25.target.com&output=json`: `%25` is the URL-encoded `%` wildcard —
  this query asks crt.sh's certificate transparency database for every certificate
  ever issued containing any subdomain of `target.com`.
- `jq -r '.[].name_value'`: parses the JSON response and extracts just the certificate
  common/alt names, one per line.
- `puredns bruteforce`: unlike `subfinder`, this one **does** send DNS queries
  directly related to guessing subdomain names against the target's DNS — this is
  the active step, and is noisier/more likely to be logged.
- `-r resolvers.txt`: a list of public DNS resolvers to distribute queries across,
  reducing the chance of any single resolver rate-limiting you.

## 7. Expected Output
A deduplicated list of hostnames, e.g. `app.target.com`, `api.target.com`,
`staging.target.com`. Volume varies hugely by organization size — a handful to
several thousand are both normal.

## 8. Interpretation
Not every hostname found is a live, testable asset — many certificate transparency
entries are for decommissioned or never-deployed subdomains. This list is raw
material for the next step (`live-host-discovery.md`), not a final attack surface.

## 9. False Positives
- Expired/unused DNS records still appearing in passive sources.
- Wildcard DNS records (`*.target.com` resolving to a single catch-all IP) can make
  it look like thousands of subdomains exist when really only one record does —
  check for this before treating a huge subdomain count as meaningful.

## 10. Next Action
Feed the full list into `live-host-discovery.md` to filter down to hosts that
actually respond.

## 11. Safety Considerations
Passive steps carry essentially no risk. Active brute-forcing generates real DNS
traffic against the target's infrastructure — confirm the program doesn't exclude
active DNS enumeration, and keep resolver concurrency moderate to avoid being
mistaken for a DNS-layer attack.

## 12. Documentation
Save the raw output file with a timestamp — subdomain inventories change over time
and you want to be able to show what existed when you tested.
