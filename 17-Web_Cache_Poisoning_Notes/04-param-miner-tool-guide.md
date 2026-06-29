# Web Cache Poisoning — Param Miner (Burp Extension) Guide

Every technique in files 02 and 03 depends on first finding an unkeyed input. Manually testing this — adding a random header, comparing the response, repeating for dozens of plausible headers — does not scale. **Param Miner** is the Burp Suite extension purpose-built for automating exactly this discovery process, and it is the closest thing this vulnerability category has to a dedicated tool-equivalent (the same role Burp's Intruder/Repeater play generically for other injection categories, except Param Miner is custom-built specifically for cache-key and parameter-discovery problems).

Param Miner was created by James Kettle (PortSwigger's Director of Research) as part of the original "Practical Web Cache Poisoning" research, and it remains the standard tool referenced directly in the PortSwigger Web Security Academy's own official methodology for this category.

---

## 1. Installing Param Miner

- Open Burp Suite → **Extensions** tab → **BApp Store**.
- Search for **Param Miner**.
- Click **Install**.
- Param Miner is available in both Burp Suite Community Edition and Professional. The output mechanism differs slightly between editions (covered below), but the core discovery functionality is the same in both — this matters for you specifically, since you've already standardized on Community Edition.

---

## 2. Core Function: "Guess Headers"

The primary workflow:

1. With Burp's proxy running, browse to the target page normally so the request appears in **Proxy → HTTP history**.
2. Right-click the request you want to investigate (commonly a `GET` request for the home page, or any page you suspect is cached).
3. Select **Extensions → Param Miner → Guess headers** (the exact menu path may show as a top-level "Guess headers" option directly in the right-click context menu, depending on Burp version).

### What happens mechanically when you do this

Param Miner does **not** just send one or two test requests. It sends the original request repeatedly, each time injecting a single header from its own large, built-in wordlist of known real-world header names — things like `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `X-HTTP-Method-Override`, `X-Original-URL`, and many dozens more, including obscure, vendor-specific, and CDN-specific headers that a human tester would be unlikely to think to test manually.

For each injected header, Param Miner compares the resulting response against a baseline response (the original, unmodified request) and looks for **any observable difference** — a changed reflected value, a different response length, a different status code, a timing anomaly, or any other measurable deviation. If a difference is detected, Param Miner concludes that this specific header has an effect on the back-end's processing of the request — meaning the application reads and uses it, which is exactly the signal you need before deciding it's worth manually weaponizing per the techniques in files 02–03.

This is the manual equivalent of the "elicit a harmful response" testing strategy described in file 01, just automated and run against a wordlist instead of a guess-by-guess process you'd otherwise have to do by hand using a tool like Burp Comparer.

### Reading the results

- **In Burp Suite Professional:** detected unkeyed/effective inputs are logged directly into the **Issues** pane (the same panel used by Burp's active scanner), with a description identifying which header had an effect.
- **In Burp Suite Community Edition** (your setup): there is no Scanner/Issues pane, so results appear instead in **Extensions → Installed → Param Miner → Output**. This is the tab you should check after running "Guess headers" — it's easy to miss the first time, since nothing pops up automatically the way a Professional-edition issue would.

A concrete real example from PortSwigger's own documentation: running "Guess headers" against a target's home page surfaced `X-Forwarded-Host` as an unkeyed header with an observable effect on the response — exactly the header used as the worked example throughout file 02.

---

## 3. The Critical Safety Feature: Automatic Cache Busting

This is the single most important reason to use Param Miner rather than testing headers manually with plain Burp Repeater, and it directly addresses the risk flagged in file 01's discussion of cache busters.

**The problem it solves:** when you're actively probing a *live* target for unkeyed inputs, every single test request you send is a potential live poisoning attempt. If you happen to land on a real unkeyed-and-exploitable header during testing, and the resulting response gets cached under the legitimate key, you've just poisoned the cache for every real visitor — by accident, mid-recon, before you even confirmed the bug works.

**What Param Miner does about it:** the extension automatically appends a cache buster to every outbound request it sends during its probing process. Because this cache buster has a fixed, predictable value (rather than a different random value every single time), you can still observe the cache's hit/miss behavior consistently across your own test requests — letting you verify caching behavior — without that cache-busted value ever matching the real, legitimate cache key that actual site visitors would produce. In effect, Param Miner gives itself (and you) a private, isolated lane inside the shared cache to experiment in, without leaking poisoned test responses out to real traffic.

In Burp Suite Professional, there are dedicated configuration options for this behavior (toggle automatic cache-buster injection on/off, and choose whether to include cache busters in headers specifically — useful for the "unkeyed query string" scenario from file 03, where a query-string cache buster would do nothing and you specifically need a header-based one instead). This is also directly relevant for client engagements: when testing a production system that real customers are using, this safety behavior is the difference between responsible testing and accidentally causing a real (if temporary) incident on a paying client's live site.

---

## 4. Using Param Miner for Parameter and Cookie Discovery (Not Just Headers)

Param Miner's name reflects its broader scope — it isn't limited to headers. The same underlying "inject a candidate input, compare against baseline, flag any observable difference" engine is also used (via separate menu options in the same extension) to discover:

- **Hidden/unlinked query parameters** that the application reads but that never appear anywhere in the visible page or its source — these are exactly the kind of candidates relevant to the "unkeyed query parameter" and parameter-cloaking discussion in file 03.
- **Hidden cookies** that influence application behavior without being documented or obviously referenced in client-side code — directly relevant to the unkeyed-cookie technique in file 02.

This is genuinely useful beyond cache poisoning specifically — hidden parameter discovery is a broadly applicable recon technique across many vulnerability classes (IDOR, access control bypass, debug/feature-flag parameters), which is one reason Param Miner is commonly left enabled as a standing part of a tester's Burp setup rather than something installed only when specifically hunting for cache bugs.

---

## 5. A Worked Example Tied to a Real Lab Pattern

This mirrors the methodology used in PortSwigger's "Targeted web cache poisoning using an unknown header" lab (mapped in file 05), where the vulnerable header isn't one of the well-known `X-Forwarded-*` family at all, but an obscure, application-specific custom header that nobody would think to test by hand.

1. Load the target's home page with Burp running, generating a request in HTTP history.
2. Right-click that request → **Guess headers**.
3. Let Param Miner run its full wordlist (this can take some time on a large wordlist against a slow target — it is sending a meaningfully large number of requests).
4. Check **Extensions → Installed → Param Miner → Output** (Community Edition) for any reported finding.
5. PortSwigger's documented result for this scenario: Param Miner reports a "secret input" — in that specific case, the custom header `X-Host` — as having a measurable effect on the response.
6. From here, you switch back to manual technique: take the now-confirmed unkeyed-and-effective header, and apply the exact same weaponization process from file 02 (test what value it accepts, see how it's reflected or used, craft a payload, confirm cacheability, remove your cache buster, confirm a clean follow-up request also receives the poisoned response).

**The key mental model:** Param Miner replaces the *discovery* phase (step 1 of the file 01 methodology — "identify and evaluate unkeyed inputs") with an automated process. It does not replace the *exploitation* phase — you still need to manually work out how to weaponize whatever input it flags, exactly as covered in files 02 and 03.

---

## 6. Real-World Industry Notes

- Param Miner is explicitly referenced by name in PortSwigger's own official Web Security Academy course material as the recommended tool for this category — it isn't a third-party convenience tool layered on top of the curriculum, it's treated as core methodology.
- In professional engagements with time constraints (a fixed-scope pentest, for instance), running Param Miner's header-guessing pass early against every cacheable-looking endpoint is a low-cost, high-yield habit — it runs largely unattended while you move on to manually testing other parts of the application.
- Because Param Miner's wordlist includes many obscure, real CDN/infrastructure-specific headers (not just the well-known `X-Forwarded-*` family), it routinely surfaces vendor-specific quirks that wouldn't be on a manually-curated personal cheat sheet — this is a genuine advantage over relying purely on memorized payloads from a write-up.
- A practical caution worth internalizing for client work specifically: always confirm Param Miner's cache-busting behavior is active before running "Guess headers" against a production target you don't fully control, especially one you suspect may have an internal/fragment cache per file 03's section 9 — that's precisely the scenario where an automated, high-volume probing tool without cache-bust protection could cause real, visible damage to a live site.

---

## 7. What's Next

File 05 is the final cheatsheet and the complete PortSwigger Web Security Academy lab map for this entire topic, presented in the Academy's own difficulty progression order.
