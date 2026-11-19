# CDN / WAF / Reverse Proxy / Application-Filter Identification

## 1. Purpose
These four layers are frequently conflated but behave differently, and confusing
them leads to wasted effort (e.g. trying WAF "bypass" techniques against something
that's actually an application-level input validator with no WAF involved at all).

## 2. When to Use
Before attempting any filter-evasion work, and ideally before origin IP discovery
too, since knowing *what* sits in front of the target shapes which discovery
techniques are worth trying.

## 3. Prerequisites
A live host to probe (`live-host-discovery.md`).

## 4. Distinguishing the Four Layers

| Layer | What it does | How to recognize it |
|---|---|---|
| **CDN** (Cloudflare, Akamai, CloudFront, Fastly) | Caches/serves content from edge locations close to the user; may or may not include security filtering | DNS resolves to known CDN IP ranges; response headers like `cf-ray`, `x-amz-cf-id`, `x-served-by` |
| **WAF** (ModSecurity, AWS WAF, Imperva, Cloudflare's own WAF module) | Inspects request content for malicious patterns and blocks/challenges matching requests | A crafted malicious-looking request (e.g. a quote character) gets a distinct block response (403, CAPTCHA page, branded block page) that a benign request doesn't |
| **Reverse proxy** (nginx, HAProxy, Envoy) | Routes/load-balances traffic to backend servers; not inherently a security control | `Server:` header often names it directly; behavior is routing-related (e.g. consistent backend selection) rather than content-inspection-related |
| **Application-level filtering** | Input validation/sanitization written into the app itself (e.g. a framework's built-in escaping, a custom regex check) | No CDN/WAF signature is detected, but malformed input still produces a distinct error — the block decision happens *after* reaching the actual application, often visible in response timing (slower, since it reached app logic) or in app-specific error pages rather than a generic block page |

A single target can have **more than one of these stacked** — e.g. Cloudflare (CDN)
+ Cloudflare WAF module + nginx (reverse proxy) + Laravel's own input validation
(application-level), all in front of the same request.

## 5. Commands

```bash
# Baseline header check — look for CDN signatures
curl -s -I https://target.com

# Fingerprint known WAF products against signature database
wafw00f https://target.com

# Send a deliberately malformed request and compare block response characteristics
curl -s -o /dev/null -w "%{http_code} %{time_total}\n" "https://target.com/?x=<script>"
curl -s -o /dev/null -w "%{http_code} %{time_total}\n" "https://target.com/?x=normalvalue"
```

## 6. Command Breakdown
- `wafw00f`: matches response headers/behavior against a curated signature database
  of known WAF products — this only identifies *named, known* WAF products. It
  **cannot** reliably detect custom/unbranded filtering logic, and a "no WAF
  detected" result does not mean no filtering exists at all — see Section 9.
- Comparing status code **and** timing across a benign vs. malicious request helps
  distinguish a WAF-layer block (often fast, before reaching the app) from an
  application-layer rejection (often slower, since the request actually reached and
  was processed by the backend).

## 7. Expected Output
A labeled stack, e.g.: "Cloudflare (CDN, confirmed via headers) + Cloudflare WAF
(confirmed via `wafw00f` + block page) + unknown reverse proxy (nginx, via `Server`
header) + no detected application-level filtering beyond framework defaults."

## 8. Interpretation
This labeling determines your next move:
- **CDN only, no WAF detected**: origin IP discovery may let you bypass caching, but
  there may be no security filtering to bypass at all — test normally.
- **WAF confirmed**: filter-evasion techniques (`07-WAF-and-Filter-Analysis/`) are
  relevant if testing gets blocked.
- **Reverse proxy only**: not a security control by itself — don't waste time on WAF
  bypass techniques against something that isn't inspecting content.
- **Application-level filtering, no WAF**: evasion approach is different — you're
  working against the actual app's input validation logic, which may be bypassed by
  understanding its specific logic (e.g. a regex with an exploitable gap), not by
  generic WAF-evasion tricks.

## 9. False Positives / Known Limitations
- `wafw00f` and similar fingerprinting tools rely on signature databases that lag
  behind new WAF product versions and custom deployments — a negative result is not
  proof of "no filtering."
- A generic 403 could come from any of the four layers, or from an entirely
  unrelated cause (IP-based geo-blocking, a misconfigured rule unrelated to your
  specific input) — don't assume causation from a single blocked request. **A WAF
  block does not prove a vulnerability exists behind it, and the absence of a block
  does not prove one doesn't.** Both are simply unknowns until tested further.

## 10. Next Action
If a WAF/application filter is confirmed and blocking your testing, go to
`07-WAF-and-Filter-Analysis/waf-detection.md` for deeper fingerprinting before
attempting any evasion technique.

## 11. Safety Considerations
Sending deliberately malformed requests to probe filter behavior is active testing —
keep volume low (a handful of comparison requests is enough to characterize the
layer; this is not a step that requires hundreds of requests).

## 12. Documentation
Record which layer(s) were identified and the specific evidence (header name, block
page content, timing delta) — this matters later if a report needs to explain why a
particular bypass approach was or wasn't attempted.
