# Parameter Discovery

## 1. Purpose
Find parameters an endpoint accepts but doesn't visibly use — hidden/debug
parameters are a common source of access-control and injection bugs precisely
because they weren't designed with the same scrutiny as the visible feature.

## 2. When to Use
Per-endpoint, once you have a confirmed list from `endpoint-discovery.md`.

## 3. Prerequisites
A specific endpoint URL to test against.

## 4. Methodology
1. Check JS/API responses for parameter names already referenced in code
   (see `javascript-analysis.md`) — this is higher-signal than blind brute-forcing.
2. Brute-force common parameter names against the endpoint, watching for any
   response difference (size, status, timing) versus a baseline with no extra param.

## 5. Commands
```bash
arjun -u https://target.com/profile -m GET -o found_params.json
```

## 6. Command Breakdown
- `arjun`: sends requests with batches of candidate parameter names, comparing each
  response against a baseline to detect ones that change behavior — it doesn't
  guess blindly one-by-one, it uses response-diffing to flag likely real parameters
  efficiently.
- `-m GET`: tests parameters as query-string values; swap to `-m POST` or
  `--headers`/`--cookies` modes available in the tool for other input locations.
- `-o found_params.json`: structured output for later reference.

## 7. Expected Output
A list of parameter names the endpoint responds differently to, e.g. `debug=1`,
`role=`, `redirect=`.

## 8. Interpretation
A parameter that changes behavior is a new input to run through
`input-surface-analysis.md` and eventually `06-Vulnerability-Testing/` — it is not
itself a finding yet.

## 9. False Positives
- Caching layers can make a parameter look like it changes behavior (cache-buster
  effect) when it actually does nothing server-side — confirm by repeating the
  request with the same parameter value twice before concluding it's meaningful.

## 10. Next Action
Catalog each discovered parameter in `input-surface-analysis.md` with its
location (query/body/header) before testing any specific vulnerability class.

## 11. Safety Considerations
Parameter brute-forcing sends many requests per endpoint — throttle on
rate-limited programs, and avoid parameter names suggestive of destructive actions
(e.g. `delete=true`) unless you're prepared to handle a hit carefully.

## 12. Documentation
Record each parameter found, the endpoint it belongs to, and the specific response
difference that flagged it.
