# Technology Fingerprinting

## 1. Purpose
Identify the frameworks, CMS, languages, and libraries a target uses. This shapes
every later hypothesis — you test differently for a WordPress site than for a
custom React + GraphQL app.

## 2. When to Use
Right after a host is confirmed live, before attack-surface mapping begins.

## 3. Prerequisites
A live host list from `live-host-discovery.md`.

## 4. Methodology
1. Passive fingerprinting from HTTP response headers and page markup first.
2. Targeted checks for known CMS/framework fingerprints (file paths, cookie names,
   generator meta tags) second.
3. Cross-reference at least two independent signals before concluding what stack a
   target runs — a single header can be spoofed or outdated.

## 5. Commands

```bash
whatweb -a 3 https://target.com
```
```bash
curl -s -I https://target.com
```
```bash
# Check for a common CMS fingerprint file as one data point (WordPress example)
curl -s -o /dev/null -w "%{http_code}\n" https://target.com/wp-login.php
```

## 6. Command Breakdown
- `whatweb -a 3`: `-a` sets aggression level 1–4; level `3` performs more requests
  (following some links, checking common paths) than the default level `1`
  (headers/homepage only), giving a more complete fingerprint at the cost of more
  traffic against the target.
- `curl -I`: fetches headers only — look at `Server`, `X-Powered-By`, and any
  framework-specific cookie name (`PHPSESSID` suggests PHP, `JSESSIONID` suggests
  Java) as initial, low-confidence signals.
- The `wp-login.php` check is a single-point manual confirmation technique — a `200`
  or `302` strongly suggests WordPress; a `404` doesn't rule it out (the path could
  be renamed/blocked) but lowers confidence.

## 7. Expected Output
A short profile like: `nginx, PHP 8.1 (X-Powered-By), WordPress 6.4 (meta generator
tag), Cloudflare (CDN headers)`.

## 8. Interpretation
Use this to prioritize which vulnerability classes are worth testing first. A
confirmed CMS version lets you check for known CVEs against that specific version —
but a known CVE existing is a hypothesis to test, not a confirmed finding until you
reproduce the actual behavior (see `08-Validation-and-Evidence/`).

## 9. False Positives
- `Server`/`X-Powered-By` headers are configurable and sometimes deliberately
  misleading (security-conscious admins change them).
- A generator meta tag can be left over from a migrated/decommissioned platform and
  no longer reflect the live stack.

## 10. Next Action
Feed the confirmed (or best-guess, clearly labeled as such) stack into attack
surface mapping — it determines which endpoint/parameter conventions to expect
(e.g. WordPress `admin-ajax.php` patterns vs a custom API's REST conventions).

## 11. Safety Considerations
Level 3+ `whatweb` aggression and manual path-checking generate more requests than
passive recon — stay within rate-limit expectations, especially on smaller/self-hosted
targets that may not handle burst traffic gracefully.

## 12. Documentation
Record each fingerprint signal with its source (which header, which path check) —
if a later finding depends on "this is WordPress," you want to show how you knew
that.
