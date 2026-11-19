# WAF Detection

## 1. Purpose
Identify, as specifically as possible, what's actually blocking a request before
attempting any evasion — see `03-Origin-Infrastructure/cdn-waf-identification.md`
for the broader layer distinction this builds on.

## 2. When to Use
When a vulnerability test from `06-Vulnerability-Testing/` gets an unexpected block
response instead of the expected app behavior.

## 3. Prerequisites
A specific blocked request to investigate, plus its baseline (non-blocked)
counterpart for comparison.

## 4. Methodology
1. Signature-based fingerprinting against known WAF products.
2. Behavioral comparison — timing and response characteristics between a benign
   and a malicious-looking request.
3. Explicitly note the limitation: a "no WAF detected" result does not mean no
   filtering exists — it means no *known, signatured* product was matched.

## 5–6. Commands & Breakdown
```bash
wafw00f https://target.com -v
```
`-v` adds verbose output showing exactly which signature(s) matched, if any —
useful to understand *why* a product was identified rather than taking the
conclusion on faith.

```bash
curl -s -o /dev/null -w "%{http_code} %{time_total}\n" "https://target.com/?x=<script>"
curl -s -o /dev/null -w "%{http_code} %{time_total}\n" "https://target.com/?x=normal"
```
A malicious-looking request returning quickly with a distinct status (often faster
than the app's normal processing time, since a network-edge WAF rejects before the
request reaches the application) suggests an edge-layer block. A malicious-looking
request that takes *as long or longer* than normal, with an app-specific error
page rather than a generic block page, suggests the request reached the
application and was rejected there instead.

## 7–8. Expected Output / Interpretation
Either a named, confirmed WAF product, or an unidentified filtering behavior with
behavioral characteristics documented (fast edge-block vs. slower app-layer
rejection).

## 9. False Positives / Limitations
- Signature databases lag behind new product versions and custom/managed rule
  sets — treat a "no WAF" result as "no *known* WAF," not "confirmed no filtering."
- A single blocked request proves only that *this specific request* was blocked —
  it says nothing about whether the underlying input would have been exploitable
  if it had reached the application unfiltered. **Do not report "WAF blocked my
  payload" as evidence of a vulnerability, and do not report "no block occurred"
  as evidence of no vulnerability** — both require the actual application-layer
  test (per `06-Vulnerability-Testing/`) to resolve.

## 10. Next Action
If a confirmed WAF/filter is blocking a test you have reason to believe would
otherwise be exploitable (e.g. error-based SQLi confirmed on a similar unprotected
parameter elsewhere), proceed to `authorized-bypass-testing.md`. If the program's
policy restricts bypass attempts, stop here and report based on what you could
confirm without evasion.

## 11. Safety Considerations
A handful of comparison requests is enough to characterize the filtering layer —
this step does not require repeated or escalating attempts.

## 12. Documentation
Record the exact blocked request, the response (status, body snippet, timing),
and the fingerprinting tool's confidence level/signature match if any.
