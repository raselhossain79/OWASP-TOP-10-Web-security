# Web Cache Poisoning — Fundamentals: Cache Keys vs Unkeyed Inputs

## 1. What Web Cache Poisoning Actually Is

Web cache poisoning is an attack where the attacker tricks a web cache into storing a harmful HTTP response, so that the cache then hands that harmful response out to other users automatically, with zero further effort from the attacker.

This is fundamentally different from a normal reflected vulnerability (like reflected XSS). A normal reflected XSS payload only fires against the one victim you trick into clicking a malicious link. A cache-poisoning payload fires against *every single visitor who requests the affected URL while the cache is poisoned* — without you sending them anything. You poison the cache once, and the cache becomes your delivery mechanism.

This is why cache poisoning is treated as a severity multiplier rather than a vulnerability class on its own. It rarely does damage by itself — its real power is turning an otherwise "minor" or "unexploitable" reflected bug into something that behaves like a stored, self-propagating vulnerability affecting a whole site's user base.

Two phases define every cache poisoning attack:

1. **Elicit a harmful response** — get the back-end server to generate a response that contains something dangerous (an XSS payload, a malicious script import, an open redirect, etc.) as a side effect of some input you controlled.
2. **Get that harmful response cached** — make sure the cache stores that specific harmful response and serves it to other users on subsequent requests.

Both steps must succeed for the attack to work. You can find a "perfect" injection point that gets reflected beautifully, and still get nowhere if you can't get the resulting response cached. Equally, you can have a page that caches very aggressively, but if nothing you send actually changes the response content, there's nothing to poison it with.

## 2. Why Caches Exist (and Why That Creates the Vulnerability Class)

Before this attack makes sense, you need to understand *why* caches behave the way they do.

If a back-end server had to generate a fresh response for every single incoming request, high-traffic sites would buckle under load. A cache sits in front of (or sometimes inside) the application and stores copies of responses. When an equivalent request comes in again, the cache serves the stored copy directly — the back-end server is never even contacted.

```
Normal cache flow:

User A  --GET /home-->  [Cache] --(cache miss)--> [Origin server] --response--> [Cache stores it] --> User A
User B  --GET /home-->  [Cache] --(cache hit)----------------------------------------------------> User B
User C  --GET /home-->  [Cache] --(cache hit)----------------------------------------------------> User C
```

User A's request goes all the way to the origin server because there was nothing in the cache yet (a "miss"). The server's response gets stored. Users B and C send what the cache considers an *equivalent* request, so they get served the exact same stored response (a "hit") without the origin server being touched at all.

This is good for performance. It is dangerous the moment "equivalent" is defined more loosely than it should be — which is exactly what happens with unkeyed inputs.

## 3. Cache Keys: How a Cache Decides Two Requests Are "The Same"

A cache cannot compare entire raw HTTP requests byte-for-byte — that would defeat the purpose, because nearly every request differs slightly (different `User-Agent`, different timestamps in some header, etc.). Instead, the cache builds a **cache key**: a reduced fingerprint made from only *some* parts of the request.

By default, a typical cache key is built from:

- The request line (method + path, e.g. `GET /home`)
- The `Host` header

That's it, in many default configurations. Anything else in the request — most headers, most cookies, and sometimes even the query string — is simply **not part of the comparison**. The cache looks only at the cache key. If two different requests produce the same cache key, the cache treats them as identical and will serve one cached response for both, regardless of how different the rest of the request actually was.

```
Request 1:
GET /home HTTP/1.1
Host: example.com
X-Forwarded-Host: example.com
User-Agent: Mozilla/5.0 (real browser)

Request 2:
GET /home HTTP/1.1
Host: example.com
X-Forwarded-Host: evil.com
User-Agent: curl/8.0
```

If the cache key here is built only from `GET /home` + `Host: example.com`, **both of these requests produce an identical cache key.** The cache has no idea that the `X-Forwarded-Host` value or the `User-Agent` differ between them. As far as the cache is concerned, they're the same request, and whichever response gets cached first will be served for both.

## 4. Unkeyed Inputs: The Actual Vulnerability

Any part of the request that is *not* included in the cache key is called an **unkeyed input**. This is the single concept the entire web cache poisoning category is built on. Memorize this relationship:

> **If an unkeyed input can influence the content of a cacheable response, you have a cache poisoning primitive.**

Why does this matter so much? Because the back-end application doesn't know or care what the cache used to build its key — the full request, including every unkeyed header and cookie, is still passed through to the application code. The cache key is purely a caching-layer decision; it has nothing to do with what data the application actually receives and processes.

So you get this mismatch:

- **The cache** ignores the `X-Forwarded-Host` header when deciding whether to serve a stored response.
- **The application** still reads `X-Forwarded-Host` and uses it to build a URL, a redirect, an `<img>` tag, whatever.

If you send a request with a malicious `X-Forwarded-Host` value, the application happily processes it and bakes it into the response. The cache then looks at its key (which never saw your malicious header) and says "this matches the key for `/home`, I'll cache this as the canonical response for `/home`." From that moment, *every* user requesting `/home` — including users whose `X-Forwarded-Host` was never tampered with — gets your poisoned version.

This is the entire mechanism. Every technique in this series — header poisoning, cookie poisoning, parameter cloaking, fat GET requests, cache key injection — is just a different specific way of finding and abusing an unkeyed input.

## 5. Constructing an Attack: The Three-Step Methodology

PortSwigger frames the general methodology for basic cache poisoning in three steps. Every technique in this series is an instance of this pattern:

1. **Identify and evaluate unkeyed inputs** — find a header, cookie, or query component that the cache ignores but the application still processes. (This is where Param Miner comes in — see file 04.)
2. **Elicit a harmful response from the back-end** — confirm that your unkeyed input actually changes the response content in an exploitable way (reflected without sanitization, used to build a URL, used to set a redirect target, etc.).
3. **Get the response cached** — confirm that the harmful response you generated actually gets stored by the cache and is then served back to you (and, critically, to other users) on a follow-up request.

A subtlety that trips up a lot of people new to this category: **getting a cache hit on your own poisoned request proves nothing about other users.** You need to confirm that an *unmodified* request (one without your cache buster, ideally one that looks like a normal visitor's request) also receives the poisoned response. That's the real proof of impact.

## 6. Cache Busters: Testing Safely

Because you are actively trying to manipulate a shared cache, careless testing on a live target can genuinely poison the cache for real users while you're still investigating. The standard safeguard is the **cache buster** — adding a unique, throwaway value to a part of the request that *is* keyed, so your test requests get their own unique cache key and never collide with real traffic.

```
GET /home?cb=4471829 HTTP/1.1
Host: example.com
```

Here, `cb=4471829` is an arbitrary, unique query parameter. As long as the query string is keyed (which it usually is by default), this guarantees your request gets a cache key nobody else will ever produce, so any response you cause to be stored is only ever served back to you. Once you're confident in your exploit, you remove the cache buster and send the "clean" version that will actually match real users' cache keys — that's the live attack.

**Important real-world nuance:** if you discover that the *query string itself* is unkeyed (see file 03), a query-string cache buster won't work, because the cache ignores it entirely — you'd be cache-busting nothing. In that scenario you need to use a buster on a header or cookie that you've confirmed remains part of the cache key.

## 7. Impact Model: Why Severity Varies So Much

Two independent factors determine how bad a given cache poisoning bug actually is:

- **What you can get cached.** A poisoned redirect to a typo'd domain is a nuisance. A poisoned response containing a working XSS payload that fires `document.cookie` theft is a session-hijacking machine. The payload determines the ceiling.
- **How much traffic hits the affected URL while poisoned.** Poisoning the home page of a high-traffic site can affect thousands of users from a single attacker request, because the cache itself does the distribution work. Poisoning an obscure, rarely-visited internal page does almost nothing, because almost nobody will ever request it while it's poisoned.

This is also why cache poisoning is one of the more commonly underrated bug classes by junior testers and even by some automated scanners: a header like `X-Forwarded-Host` being reflected somewhere looks "low impact" in isolation, but combined with a cacheable, high-traffic endpoint, it becomes a critical, mass-exploitable bug. Bug bounty programs (HackerOne, Bugcrowd) have repeatedly paid out high-severity awards for exactly this combination — a "low" reflected issue that nobody else noticed could be cached.

## 8. Real-World Industry Notes

- This entire attack class was effectively unlocked at scale by James Kettle's 2018 research paper *"Practical Web Cache Poisoning"*, and extended further in 2020 with *"Web Cache Entanglement: Novel Pathways to Poisoning."* Both papers documented real, in-the-wild vulnerabilities found on sites belonging to Mozilla, GitHub Enterprise, Cloudflare-fronted sites, and others. This isn't lab theory — it's a documented, repeatable, real-world bug class with a public research trail.
- CDNs (Cloudflare, Akamai, Fastly, CloudFront) and reverse proxies (Varnish, Nginx with proxy_cache, Squid) are the most common places this lives in production. Each implementation has its own quirks in how it builds cache keys, which is why "implementation flaw" techniques (file 03) exist as a separate, deeper layer beyond the basic "design flaw" techniques (file 02).
- A huge driver of this vulnerability class in practice is third-party technology. A site might be perfectly secure in its own code, but adopt a CDN, WAF, or load balancer that injects or forwards headers like `X-Forwarded-Host` by default — headers the application team never asked for and may not even know exist. You inherit the caching behavior of every piece of infrastructure in front of your application, whether you intended to or not.
- Many bug bounty triagers specifically ask "can you demonstrate this against an unauthenticated, cache-busted-free request that proves a second client received the poisoned response?" — if you can't show that, the report will often get downgraded to a self-XSS-style finding. Always capture evidence of a "clean" second request getting the poisoned content.

## 9. What's Next

File 02 covers exploiting **cache design flaws** — the classic, simplest path: unkeyed headers and cookies that are simply reflected or used unsafely by the application, including the canonical cache-poisoning-to-XSS chain.

File 03 goes deeper into **cache implementation flaws** — quirks in how specific caches build their keys (unkeyed ports, unkeyed query strings, parameter cloaking, fat GET requests, normalized keys, cache key injection, and poisoning internal application-level caches).

File 04 covers **Param Miner**, the Burp extension used to actually discover unkeyed inputs at scale instead of guessing headers manually.

File 05 is the cheatsheet and the full PortSwigger Web Security Academy lab map in Academy difficulty order.
