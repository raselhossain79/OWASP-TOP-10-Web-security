# Open Redirect — Cheat Sheet & Full Lab Mapping

## 1. Detection Checklist

1. Fuzz every request parameter against the wordlist below, on every login flow, "next step" link, logout button, marketing redirector, and checkout success/cancel callback.
2. For each candidate, supply a value pointing at infrastructure you control (Burp Collaborator subdomain or your exploit server).
3. Watch for a `3xx` response whose `Location` header echoes your canary domain (server-side), **or** the address bar actually navigating there with no obvious matching request in the proxy history (DOM-based — go read the page's JS for `location.*` sinks).
4. Characterize what validation exists: none / blocklist / loose allowlist (substring or prefix) / strict allowlist (exact match). Strict exact-match is the only pattern that resists everything below.
5. If found, immediately check whether the same host also runs an OAuth/SSO callback (`/oauth-callback`, `/callback`, `/sso`, `/auth/callback`) — that's the chain in file 3 — and whether any Referer-trusting integration exists nearby.

### Parameter wordlist
```
url, redirect, redirect_url, redirect_uri, redirectTo, return, returnUrl,
return_to, returnTo, next, continue, dest, destination, target, rurl,
redir, forward, out, view, login_url, logout, callback, checkout_url,
success_url, cancel_url, image_url, domain, data, u, r, link, navigate,
goto, path
```

## 2. Payload Quick Reference

| Technique | Payload | Why it works (one line) |
|---|---|---|
| Protocol-relative URL | `//evil.com` | No `http` substring exists to match; browser still does scheme-relative resolution to `evil.com`. |
| Malformed/double slash | `https:////evil.com` / `https:evil.com` | Special-scheme parsing skips *any* number of slashes (incl. zero) after the scheme colon. |
| `@` userinfo trick | `https://trusted.com@evil.com` | Everything before `@` is userinfo, not host — `evil.com` is the real host. |
| Backslash conversion | `https:\\evil.com` | Special-scheme parser treats `\` and `/` as interchangeable after the scheme colon. |
| Leading whitespace | `\thttps://evil.com` | `startsWith("http")` is false on the raw string; browser trims the leading char first. |
| Embedded tab/newline | `ht\ntp://evil.com` | Browser strips ALL tabs/newlines from anywhere in the URL before parsing; substring filter never sees a contiguous `http`. |
| Null byte (legacy) | `...evil.com%00.trusted.com` | C-style string truncation in older/custom validators; unreliable against modern stacks — disclose honestly. |
| Combined/stacked | `\thttps:/\trusted.com@evil.com` | Defeats a leading-`http` gate, a substring allowlist, and a `://`-literal check simultaneously — see file 2 §6 for the full breakdown. |

Full piece-by-piece breakdowns for every row are in `02-Open-Redirect-Bypass-Techniques.md`.

## 3. Impact-Chain Quick Reference

| Chain | One-line mechanism | Detail file |
|---|---|---|
| Phishing credibility / gateway evasion | Trusted domain + valid TLS cert visible until the final hop; URL-reputation scanners often only check the first hostname. | File 1 §4 |
| OAuth/SSO token theft via `redirect_uri` | Loose `redirect_uri` prefix validation + path traversal lands the code/token on an in-scope open redirect, which forwards it fully off-domain. | File 3 |
| Referer-based trust bypass | Open redirect lives on the trusted domain, so the first-hop Referer satisfies allowlists; departing a page with sensitive query-string data leaks that data to the attacker's Referer logs. | File 1 §4 |

## 4. Full PortSwigger Lab Mapping (Consolidated, Official Academy Order)

| Lab | Topic area | Difficulty | What it teaches | Covered in |
|---|---|---|---|---|
| DOM-based open redirection | Client-side → DOM-based vulnerabilities | Apprentice | Basic, unfiltered DOM sink (`location.href` write from a `url` parameter) | File 1 |
| SSRF with filter bypass via open redirection vulnerability | SSRF | Practitioner | Open redirect used as a chain ingredient to defeat a separate SSRF allowlist | File 1, File 2 §7 |
| Authentication bypass via OAuth implicit flow | OAuth authentication | Apprentice | Basic implicit-flow mechanics (context only) | File 3 |
| Forced OAuth profile linking | OAuth authentication | Practitioner | Missing `state` → CSRF on account linking (adjacent, not redirect_uri) | File 3 |
| OAuth account hijacking via redirect_uri | OAuth authentication | Practitioner | No `redirect_uri` validation at all | File 3 |
| Stealing OAuth access tokens via an open redirect | OAuth authentication | Practitioner | Path-traversal `redirect_uri` bypass chained into an in-scope open redirect; implicit-flow token theft | File 3 |
| Stealing OAuth access tokens via a proxy page | OAuth authentication | Expert | Same bypass, exfiltration via `postMessage` proxy instead of a second open redirect | File 3 |
| SSRF via OpenID dynamic client registration | OAuth authentication | Expert | Different vulnerability class (SSRF via `/reg`) — listed for completeness, out of scope for this series | File 3 (flagged out of scope) |

## 5. Honest Coverage Gaps

State these plainly in your own notes/reports rather than implying lab coverage that doesn't exist:

- **No Academy lab exists for plain server-side reflected/stored open redirect in isolation.** Only the DOM-based variant is built out as an interactive lab; the server-side issue types are documented in PortSwigger's vulnerability catalog, not as a standalone lab.
- **No Academy lab exists for practicing blocklist bypass on an open redirect by itself.** The one open-redirect lab has zero filtering. The SSRF lab that touches open redirect assumes the redirect is already unfiltered and present.
- **Null-byte truncation is a legacy technique.** It is included in this series for completeness and because some legacy/embedded/custom-WAF targets still exhibit it, but don't expect it against a modern browser or modern backend framework.
- **"SSRF via OpenID dynamic client registration" is not a redirect_uri/open-redirect technique** despite living in the OAuth topic — it's a distinct SSRF vector through client self-registration and is out of scope for this series.

## 6. Real-World Severity/Triage Cheat Notes

- Standalone open redirect: typically **Low/Informational** in bug bounty triage; many program policies explicitly exclude it unless chained.
- Open redirect chained into OAuth `redirect_uri` token theft: typically **Critical** — demonstrable full account takeover with no credentials.
- Open redirect chained into SSRF filter bypass: severity inherits from whatever the SSRF reaches (internal admin panels, cloud metadata endpoints, etc.) — see the dedicated SSRF note series.
- Open redirect used for Referer-leak / phishing-credibility framing: severity is context-dependent and often argued case-by-case — strongest reports demonstrate the specific sensitive data that leaked, not just the theoretical possibility.
