# Web Cache Poisoning — Note Series

A complete, GitHub-ready reference series on Web Cache Poisoning, built to the same structure and depth as the SQL Injection reference series: mechanism-first breakdowns of every payload, real-world industry framing, and honest PortSwigger Web Security Academy lab mapping in official difficulty-progression order.

## Why This Topic Splits Into Two Exploitation Files

PortSwigger's own Web Security Academy splits this topic into two distinct sub-sections — "Exploiting cache design flaws" and "Exploiting cache implementation flaws" — because they require genuinely different mindsets. Design flaws are about recognizing that a header or cookie is simply ignored by the cache. Implementation flaws are about finding quirks in *how* a specific cache parses or transforms inputs that are normally assumed to be safely keyed. This series mirrors that same split (files 02 and 03) rather than collapsing both into one generic "exploitation techniques" file, because the two categories genuinely call for different testing instincts.

## File Index

| File | Contents |
|---|---|
| `01-cache-fundamentals-and-unkeyed-inputs.md` | What cache poisoning is, how cache keys work, what makes an input "unkeyed," the three-step attack methodology, cache busters, impact model, real-world framing |
| `02-exploitation-design-flaws.md` | Unkeyed header poisoning (`X-Forwarded-Host`, `X-Forwarded-Scheme`/`Proto`), unkeyed cookie poisoning, chaining multiple headers, the full cache-poisoning-to-XSS chain, DOM-based variants |
| `03-exploitation-implementation-flaws.md` | Cache probing methodology, unkeyed port, unkeyed query string/parameters, cache parameter cloaking, fat GET requests, normalized cache keys, cache key injection, poisoning internal/fragment caches |
| `04-param-miner-tool-guide.md` | Dedicated guide to the Param Miner Burp extension — installation, "Guess headers" workflow, automatic cache-bust safety behavior, parameter/cookie discovery, a worked example |
| `05-cheatsheet-and-lab-mapping.md` | Quick-reference cheatsheet (headers to test, key flaws to test, cache indicators, prevention talking points) + the complete PortSwigger lab map in Academy progression order + honest gap disclosure |

## How to Use This Series

If you're new to the topic, read in file order — each file ends with a short pointer to what comes next. If you're already comfortable with the fundamentals and just want lab-by-lab guidance, go straight to file 05's lab map and use files 02–04 as reference while you work through each lab.

## Conventions Used Throughout (Consistent With the Rest of This Repository)

- Every request/response example is broken down piece by piece: which input is unkeyed (or which keyed component has a parsing quirk), why the cache ignores or mishandles it, and exactly how the application's behavior turns that into an exploit.
- PortSwigger labs are mapped in the order they actually appear on the Academy, not reordered by personal preference.
- Where a lab's exact difficulty tier could not be independently re-verified at time of writing, this is explicitly flagged rather than stated as certain — see the honesty note in file 05, Part B.
- Gaps in lab coverage, or related-but-out-of-scope topics (Web Cache Deception, the request smuggling crossover lab), are disclosed explicitly rather than silently omitted.
- All content is written in full English. No Bangla or Banglish appears anywhere in this series.

## Practice Platform

This series is written for hands-on practice on **PortSwigger Web Security Academy** using **Burp Suite**, consistent with the rest of this note repository.
