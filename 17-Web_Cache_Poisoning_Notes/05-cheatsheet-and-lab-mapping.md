# Web Cache Poisoning — Cheatsheet & PortSwigger Lab Mapping

## Part A: Quick-Reference Cheatsheet

### A1. The One Sentence That Explains the Whole Category

> If an unkeyed input can change the content of a cacheable response, you can poison the cache.

### A2. The Core Methodology (Every Attack, No Exceptions)

1. Identify an unkeyed input (manually, or via Param Miner's "Guess headers" — file 04).
2. Confirm it actually changes the response in some exploitable way (reflected, used to build a URL/redirect, used to import a resource).
3. Confirm the response is cacheable, and confirm the poisoned response is served back on a **second, clean request** with no cache buster and no attacker-controlled input — this is your proof of real impact, not just self-poisoning.

### A3. Headers Worth Testing First (Design Flaws — File 02)

| Header | Common Use by Application | Typical Exploit |
|---|---|---|
| `X-Forwarded-Host` | Building absolute URLs, canonical links, OG tags, resource imports | Reflected XSS, malicious script import |
| `X-Forwarded-Scheme` / `X-Forwarded-Proto` | Enforcing HTTPS via redirect | Cached open redirect (often needs chaining with `X-Forwarded-Host`) |
| `X-Forwarded-Port` | Building absolute URLs | Same pattern as unkeyed port (file 03) |
| `X-Host`, `X-Original-URL`, `X-Override-URL` | App-specific routing/rewrite logic | Varies — often custom, found via Param Miner, not guessable by name |
| `Cookie` values (e.g. language/locale/edge-node cookies) | Per-user content variation | Wrong-language or wrong-region content served to everyone; reflected cookie value → XSS |

### A4. Cache Key Flaws Worth Testing (Implementation Flaws — File 03)

| Flaw | How to Detect | How to Exploit |
|---|---|---|
| Unkeyed port | Send arbitrary `Host: site.com:1337`, confirm reflected; resend without port, check for cache hit still showing `:1337` | DoS via dead port, or XSS if non-numeric port accepted |
| Unkeyed query string | Page looks "static" even when params change; no visible cache header to confirm | Reflected XSS becomes "stored" against the plain URL |
| Unkeyed query parameter | Specific param (often `utm_*`) excluded while others remain keyed | Usually a dead end alone — combine with parameter cloaking |
| Parameter cloaking | Inject a second `?` or use `;` where backend (e.g. Rails) treats it as a delimiter | Smuggle a malicious value into a keyed parameter without changing the key |
| Fat GET | Send a body on a `GET` request, or use `X-HTTP-Method-Override: POST` | Backend reads duplicate param from body, cache key stays clean |
| Normalized cache key | Send raw special characters directly (bypassing browser encoding) via Repeater; check if it shares a key with the browser-encoded equivalent | Converts "browser always encodes this, so it's unexploitable" XSS into a real, clickable exploit |
| Cache key injection | Look for a diagnostic `X-Cache-Key` (or similar) header revealing key construction and its delimiter | Inject the delimiter + payload into a keyed header so the malicious key is reconstructible from a plain URL |
| Internal/fragment cache | Your input shows up on pages you never tested, or a response mixes content from unrelated prior requests | Single request poisons a fragment reused site-wide — test only with payloads you fully control |

### A5. Cache Hit/Miss Indicators to Look For During Recon

- `X-Cache: hit` / `X-Cache: miss`
- `CF-Cache-Status` (Cloudflare)
- `X-Varnish`, `Age` (Varnish)
- `Cache-Control`, `Age` generally (confirms cacheability + how stale the entry is)
- `Pragma: akamai-x-get-cache-key` → `X-Cache-Key` (Akamai — exposes the literal key, useful for the cache key injection technique)
- `Pragma: x-get-cache-key` (used in several Academy labs as a diagnostic hint)

### A6. Cache Busters — When and How

- Default: unique query parameter, e.g. `?cb=4471829`.
- If the query string itself is unkeyed: move the buster to a still-keyed header instead — `Accept-Encoding`, `Accept`, `Cookie`, or `Origin` are common candidates.
- Always remove the cache buster for the final, live exploitation request — a busted request only ever poisons your own private cache entry, never a real victim's.
- Never test against an internal/fragment cache the same way — there is no key to bust; use a fully attacker-controlled payload (your own exploit-server domain) so any accidental live poisoning is contained and reversible.

### A7. Prevention Talking Points (Useful for Reports / Client-Facing Notes)

- Disable caching entirely where feasible, or restrict it strictly to genuinely static content.
- If a header/parameter must be excluded from the cache key for performance, **rewrite the request** to strip or normalize it server-side rather than silently ignoring it while still processing it.
- Don't accept "fat GET" requests; reject bodies on `GET` unless explicitly required.
- Disable forwarding of headers the application doesn't actually need — many of these vulnerabilities exist purely because infrastructure (CDNs, load balancers) forwards headers by default that the application team never asked for.
- Patch client-side vulnerabilities even when they look "unexploitable" via normal means (e.g. requiring unencoded input a browser would never send) — cache poisoning is precisely the kind of cache-layer quirk that can later make an assumed-safe bug exploitable.

---

## Part B: PortSwigger Web Security Academy Lab Map

The Web Cache Poisoning topic on the Academy is genuinely one of the more fully developed lab sets — it splits cleanly into two sub-topics that match files 02 and 03 of this series exactly: **Exploiting cache design flaws** and **Exploiting cache implementation flaws**. The table below follows that same order, which is also the Academy's own difficulty progression (Apprentice → Practitioner → Expert).

**Honesty note on difficulty tags:** PortSwigger occasionally adjusts difficulty labels and lab wording over time. The tiers below reflect the documented structure and ordering at time of writing; always cross-check the live difficulty badge on the Academy page itself before treating it as gospel in your own notes.

### B1. Exploiting Cache Design Flaws (maps to File 02)

| # | Lab Name | Tier (typical) | Maps to File 02 Technique |
|---|---|---|---|
| 1 | Web cache poisoning with an unkeyed header | Apprentice | Section 1 — `X-Forwarded-Host` poisoning |
| 2 | Web cache poisoning with an unkeyed cookie | Apprentice | Section 3 — unkeyed cookie poisoning |
| 3 | Web cache poisoning with multiple headers | Practitioner | Section 4 — chaining multiple unkeyed headers |
| 4 | Targeted web cache poisoning using an unknown header | Practitioner | Section 1 mechanism + Param Miner discovery (file 04) for an obscure, app-specific header |
| 5 | Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria | Practitioner | Section 6 — DOM-based vulnerabilities via cache poisoning |
| 6 | Combining web cache poisoning vulnerabilities | Expert | Sections 4 + 5 combined — full multi-step chain requiring both a header-based poison and a separate redirect/normalization quirk |

### B2. Exploiting Cache Implementation Flaws (maps to File 03)

| # | Lab Name | Tier (typical) | Maps to File 03 Technique |
|---|---|---|---|
| 7 | Web cache poisoning via an unkeyed query string | Practitioner | Section 3 — unkeyed query string |
| 8 | Web cache poisoning via an unkeyed query parameter | Practitioner | Section 4 — unkeyed query parameter (sets up the need for cloaking) |
| 9 | Parameter cloaking | Practitioner / Expert | Section 5 — cache parameter cloaking (delimiter confusion / duplicate-parameter precedence) |
| 10 | Web cache poisoning via a fat GET request | Practitioner | Section 6 — fat GET requests |
| 11 | URL normalization | Expert | Section 7 — normalized cache keys |
| 12 | Cache key injection | Expert | Section 8 — cache key injection |
| 13 | Internal cache poisoning | Expert | Section 9 — poisoning internal/fragment caches |

### B3. Related Lab in a Different Academy Topic (Worth Knowing About, Honestly Flagged)

| Lab Name | Actual Academy Topic | Why It's Relevant Here |
|---|---|---|
| Exploiting HTTP request smuggling to perform web cache poisoning | **HTTP Request Smuggling** topic, not the Web Cache Poisoning topic | Demonstrates that request smuggling is itself a separate, alternative path to "get a harmful response cached" — the second half of the file 01 attack model — without needing any of the unkeyed-input techniques in this series at all. Worth doing once you've finished your HTTP Request Smuggling series, as a cross-category capstone. |

### B4. Honest Gap Disclosure

No gaps to disclose for the core Web Cache Poisoning topic itself — unlike some other categories in your repository, this one has a dedicated, well-developed, two-part lab set on the Academy that covers essentially every technique described in files 02 and 03 above, in a clean Apprentice → Practitioner → Expert progression. The only thing genuinely "outside" this topic's own lab set is the request smuggling crossover lab noted in B3, which lives under a different topic by Academy's own organization, not because of any missing content here.

A separate, newer topic exists on the Academy called **Web Cache Deception** (distinct from Web Cache Poisoning — it exploits cache *rules* around static file extensions and path normalization rather than unkeyed inputs in the cache *key*). It is related conceptually but is its own attack class with its own lab set, and is intentionally out of scope for this series. If useful, it would make a strong follow-up series given how closely it sits next to this material.

---

## Part C: Suggested Practice Order

1. Labs 1–2 (unkeyed header, unkeyed cookie) — build comfort with the basic mechanism and with reading `X-Cache`/cache-buster behavior.
2. Lab 4 (unknown header) — do this one specifically with Param Miner enabled (file 04), not by guessing manually, to build the discovery habit early.
3. Labs 3, 5 — multiple-header chaining and DOM-based variants.
4. Lab 6 — first real multi-step chain; expect to need both design-flaw and basic-redirect concepts together.
5. Labs 7–10 — implementation flaws, in order; lab 9 (parameter cloaking) is the conceptual centerpiece of file 03 and rewards re-reading section 5 of that file closely.
6. Labs 11–13 — the three Expert-tier implementation flaws; attempt these only after you're comfortable reading raw `X-Cache-Key` output, since most of these labs lean on that diagnostic.
7. Optional capstone: the request smuggling crossover lab (B3), after completing your HTTP Request Smuggling series.
