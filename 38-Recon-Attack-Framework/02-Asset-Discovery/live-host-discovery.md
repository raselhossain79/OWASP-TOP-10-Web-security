# Live Host Discovery

## 1. Purpose
Reduce the raw subdomain/asset list down to hosts that are actually online and
responding, so later effort isn't spent on dead records.

## 2. When to Use
Immediately after subdomain enumeration, before any deeper probing.

## 3. Prerequisites
A deduplicated host list from `subdomain-enumeration.md`.

## 4. Methodology
1. Resolve DNS for every host, drop anything with no A/AAAA record.
2. Probe HTTP(S) on resolving hosts to confirm an application is actually listening.
3. Record status code, title, and response headers per host for later triage —
   don't just discard non-200 responses (a 401/403 is still a live, in-scope host).

## 5. Commands

```bash
cat subs.txt | dnsx -silent -a -resp -o resolved.txt
```
```bash
cat resolved.txt | httpx -silent -status-code -title -tech-detect -o live_hosts.txt
```

## 6. Command Breakdown
- `dnsx -a -resp`: `-a` requests A record resolution specifically; `-resp` prints the
  resolved IP alongside the hostname instead of just confirming it resolves.
- `httpx -status-code -title -tech-detect`: probes each host over HTTP(S), printing
  the response status code, page title, and `httpx`'s built-in technology
  fingerprint guess (based on response headers and common static file signatures) —
  this gives a first-pass tech stack hint that `technology-fingerprinting.md` will
  verify more thoroughly.

## 7. Expected Output
A filtered list like:
```
https://app.target.com [200] [App Login] [nginx,react]
https://old.target.com [403] [Forbidden]
```

## 8. Interpretation
- `200`: live and serving content — primary candidates for deeper testing.
- `403`/`401`: live, but access-controlled — still in-scope and worth noting, may be
  relevant to authorization-mapping later.
- No response / connection refused: likely dead DNS record, deprioritize.

## 9. False Positives
- A host returning `200` for every path (including nonexistent ones) usually means a
  catch-all/wildcard response, not a real distinct application — verify with a
  deliberately invalid path before treating it as a meaningful asset.
- `httpx`'s `-tech-detect` is a best-effort guess based on common signatures — treat
  it as a hint for `technology-fingerprinting.md`, not a confirmed fact.

## 10. Next Action
For hosts with open web ports, continue to `technology-fingerprinting.md`. For hosts
with other services, continue to `port-service-enumeration.md` first.

## 11. Safety Considerations
This step is low-noise (one or two requests per host) but still active traffic
against every discovered asset — stay within program rate-limit expectations if a
very large subdomain list was found.

## 12. Documentation
Save the full live-host list with status codes — this becomes your working asset
inventory for the rest of the engagement.
