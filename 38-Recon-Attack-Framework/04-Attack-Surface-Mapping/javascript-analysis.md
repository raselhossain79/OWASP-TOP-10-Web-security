# JavaScript Analysis

## 1. Purpose
Modern web apps expose most of their real attack surface — API endpoints,
parameter names, feature flags, sometimes credentials/keys — inside client-side JS
bundles rather than server-rendered HTML. This is often higher-signal than
blind endpoint brute-forcing.

## 2. When to Use
As soon as a target is confirmed to be a JS-heavy application (React/Vue/Angular,
detected in `technology-fingerprinting.md`).

## 3. Prerequisites
A live host to pull JS bundles from.

## 4. Methodology
1. Collect every JS file the app loads (including lazy-loaded/chunked bundles).
2. Extract endpoint-shaped strings, parameter names, and any hardcoded
   secrets/keys from each file.
3. Cross-reference extracted endpoints against what `endpoint-discovery.md` already
   found — JS analysis frequently surfaces endpoints that wordlist brute-forcing
   misses entirely (custom route names won't be in any generic wordlist).

## 5. Commands
```bash
# Collect JS file URLs referenced by the page
katana -u https://target.com -jc -silent -o js_urls.txt

# Download and search them for endpoint-shaped strings and potential secrets
cat js_urls.txt | while read url; do curl -s "$url"; done > all_js.txt
grep -Eo '"/[a-zA-Z0-9_/\-]+"' all_js.txt | sort -u > possible_endpoints.txt

# Dedicated secret-scanning pass
trufflehog filesystem all_js.txt --no-update
```

## 6. Command Breakdown
- `katana -jc`: `-jc` enables JS-file crawling specifically, following and listing
  script sources the page loads, not just HTML links.
- `grep -Eo '"/[a-zA-Z0-9_/\-]+"'`: a simple extended-regex pass pulling anything
  that looks like a quoted path string — this is a blunt instrument that will catch
  a lot of noise (CSS class names, non-endpoint strings) alongside real endpoints;
  manual review of the output is still required.
- `trufflehog filesystem`: scans the collected JS content for patterns matching
  known secret formats (API keys, tokens) using its built-in detector rules —
  flags candidates, does not itself confirm a key is live/valid.

## 7. Expected Output
A list of candidate endpoint paths and, separately, any flagged potential secrets
with the detector rule that matched.

## 8. Interpretation
Endpoint strings found here are candidates to verify are real, reachable, and
in-scope — minified/bundled JS can contain dead code, removed features, or
third-party library internals that aren't actually part of the target's own API.

## 9. False Positives
- The regex extraction catches many non-endpoint strings — don't report anything
  from this step without confirming the path actually resolves to something on the
  live target.
- Flagged "secrets" from `trufflehog` are pattern matches, not validated credentials
  — a surprising number of matches are expired, test/placeholder, or public-by-design
  keys (e.g. a public analytics key meant to be client-exposed). Confirm scope/
  sensitivity before treating any flagged secret as a finding.

## 10. Next Action
Feed confirmed endpoints into `api-discovery.md` and `parameter-discovery.md`.
Any confirmed live, sensitive secret is a finding in its own right — validate
carefully and minimally (see `08-Validation-and-Evidence/`) before using it further.

## 11. Safety Considerations
Downloading and scanning JS files is passive from the target's perspective beyond
normal page-load traffic. If a flagged secret turns out to be live/valid, do not use
it to access further systems beyond the minimum needed to confirm it's real and
report it — using a found credential to pivot further is a scope/authorization
question, not just a technical one.

## 12. Documentation
Save the specific JS file URL and line/snippet where each endpoint or secret was
found — this is the evidence a report needs to be actionable.
