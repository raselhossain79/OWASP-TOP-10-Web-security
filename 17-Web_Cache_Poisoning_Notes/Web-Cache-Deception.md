# Web Cache Deception (Web Cache Poisoning Sub-Topic)

> Place this file inside your existing `17-Web_Cache_Poisoning_Notes/` folder
> as a companion file — related family (cache misconfiguration), but a
> distinct mechanism from cache poisoning itself, so it's kept as its own
> file rather than merged into the main poisoning content.

## How This Differs From Cache Poisoning

Cache poisoning (the rest of folder #17) is about getting the cache to store
and serve *attacker-controlled content* to other users. Web Cache Deception
is the inverse: tricking the cache into storing a *legitimate, sensitive,
user-specific response* (like an account page) under a URL that the cache
treats as static/cacheable — so the attacker can later request that same
cache entry and receive the victim's private data.

## 1. Mechanism

### Why test it
Caches typically decide what to cache based on the URL path, often using
simple rules like "cache anything that looks like a static file
(`.css`, `.js`, `.jpg`)." If the application's routing is lenient about
trailing path segments (e.g., `/account/settings/nonexistent.css` still
routes to the same dynamic, authenticated `/account/settings` handler), an
attacker can get a victim's authenticated response cached under a
predictable, guessable URL.

### Classification
High — direct sensitive data exposure (session tokens, PII, account details)
affecting other users, without needing to compromise the cache
infrastructure itself.

### Attack Flow
1. Identify a dynamic, authenticated endpoint that returns sensitive
   per-user data (e.g., `/my-account`, `/api/user/profile`).
2. Append a path segment or extension the cache is configured to treat as
   static (`/my-account/nonexistent.js`, `/my-account.css`,
   `/my-account%2f..%2fstatic.css` — normalization quirks matter here).
3. Confirm the application still routes this to the same authenticated
   handler and returns the real sensitive content (not a 404).
4. Confirm the cache stores this response under the crafted URL — check for
   cache-hit indicators (`X-Cache: HIT`, `Age` header present on repeat
   request, response timing drop on second request).
5. Send the crafted URL to a victim (via a link); once the victim's
   authenticated browser loads it and the response gets cached, the
   attacker requests the same URL unauthenticated and receives the cached
   (victim's) sensitive response.

### Detection & interpretation
- Test path-confusion variants systematically: extra path segments, fake
  extensions, path parameter injection (`;`), URL-encoded traversal
  sequences — and check whether the application's router treats them as
  equivalent to the clean authenticated path.
- After a request with a crafted suffix, repeat the exact same request from
  a fresh/unauthenticated session or client — if sensitive content is
  returned without authentication, and cache headers indicate a hit, the
  deception is confirmed.
- False-positive check: some frameworks correctly 404 on unrecognized
  extensions — that's a pass, not a finding.

### Remediation
- Configure the cache to key strictly on exact path + query, not
  loosely-matched extensions/patterns; where a CDN/cache layer must cache by
  extension, ensure the origin returns a genuine 404 for any path segment it
  doesn't explicitly recognize rather than falling through to a catch-all
  authenticated handler.
- Add `Cache-Control: private, no-store` explicitly on all authenticated,
  per-user response paths so no intermediate cache stores them regardless of
  URL shape.
- Normalize/canonicalize paths consistently between the cache layer and the
  origin application so they can't disagree about what a given URL means.

## PortSwigger Lab Mapping

PortSwigger's Web Security Academy has a dedicated "Web Cache Deception"
topic within its caching-related labs, covering exactly this path-confusion
pattern — solid direct coverage, no gap to disclose for this one.
