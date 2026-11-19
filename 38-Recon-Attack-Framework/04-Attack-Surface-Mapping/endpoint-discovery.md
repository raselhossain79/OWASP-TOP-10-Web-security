# Endpoint Discovery

## 1. Purpose
Map every reachable path on a target beyond the handful of links visible in the UI —
most real attack surface is in endpoints not linked from the visible site.

## 2. When to Use
After technology fingerprinting, before parameter/input analysis.

## 3. Prerequisites
A confirmed live host and its tech stack guess (shapes which wordlists/conventions
to expect — e.g. Laravel routes vs WordPress paths).

## 4. Methodology
1. Passive: crawl historical archives and JS for paths already known publicly.
2. Active: directory/file brute-forcing with a wordlist matched to the tech stack.
3. Crawl the live site itself with a spidering tool to catch linked-but-unlisted pages.

## 5. Commands
```bash
# Passive — historical URLs
gau target.com | sort -u > historical_urls.txt

# Active — content discovery against the live app
ffuf -u https://target.com/FUZZ -w raft-medium-directories.txt \
  -mc 200,301,302,403 -fs 0 -t 40 -p 0.1
```

## 6. Command Breakdown
- `gau`: pulls URLs the target has ever had indexed (Wayback Machine, Common Crawl,
  AlienVault OTX) — purely passive, zero direct target traffic.
- `ffuf -u .../FUZZ`: `FUZZ` marks the injection point the wordlist fills in.
- `-mc 200,301,302,403`: match these status codes as "found" — 403 is included
  deliberately since an access-controlled path is still a discovered endpoint.
- `-fs 0`: filter out responses of size 0 (often a sign of a generic empty
  catch-all response rather than a real distinct page).
- `-t 40`: 40 concurrent threads — reasonable default; lower on rate-limited targets.
- `-p 0.1`: adds a 0.1s delay between requests per thread — a basic politeness/rate
  control, raise it if the program states strict rate limits.

## 7. Expected Output
A list of paths with status codes, e.g. `/admin [403]`, `/api/v1/users [200]`,
`/backup.zip [200]`.

## 8. Interpretation
Treat every non-404 as worth a manual look, not just the 200s — a 403 on `/admin`
confirms the path exists and is access-controlled, which matters for
`authorization-mapping.md` later.

## 9. False Positives
- Wildcard/catch-all responses returning 200 for any path — confirm with an
  obviously-random path (`/asdkjasdkjasd123`) to see if it also returns 200; if so,
  your `-mc`/`-fs` filters need adjusting before trusting results.
- Soft-404s (app returns 200 with a "not found" page body instead of an actual 404
  status) — `ffuf`'s `-fs`/`-fr` (filter by response text regex) help filter these
  once you spot the pattern.

## 10. Next Action
Feed discovered endpoints into `parameter-discovery.md` and, for anything
API-shaped, into `api-discovery.md`.

## 11. Safety Considerations
Active brute-forcing is one of the noisier recon actions — respect rate limits,
and avoid wordlists aimed at destructive paths (e.g. ones including
`/delete`, `/reset`) without specific intent to handle a hit carefully, not blindly
request it.

## 12. Documentation
Save the full result list with status codes and response sizes — useful evidence
for scope/attack-surface discussion in the final report.
