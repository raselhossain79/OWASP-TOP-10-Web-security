# CSP Bypass Techniques (XSS Sub-Section)

> Place this file inside your existing `02-XSS_Notes/` folder — this is not a
> standalone vulnerability class, it's the post-XSS step: what to do when
> you've found an injection point but a Content-Security-Policy header is
> blocking your payload from executing.

## Why this belongs inside XSS, not its own folder

CSP bypass has no exploitation value on its own — there is no "CSP bypass
vulnerability" independent of an underlying injection. It only matters once
you already have a way to inject markup/script and need to get past the
policy that would otherwise stop it from running. Treating it as a
standalone folder would misrepresent it as a separate finding class.

## 1. Understand the Policy Before Attacking It

### Why test it
A CSP is only as strong as its weakest directive. Before attempting any
bypass, extract and parse the actual policy — most "CSP bypasses" are really
just spotting a misconfiguration the policy author didn't realize they made.

### Detection & interpretation
- Read the `Content-Security-Policy` (or `-Report-Only`) response header
  directly, or check for an equivalent `<meta http-equiv>` tag.
- Parse each directive (`script-src`, `default-src`, `style-src`,
  `object-src`, `base-uri`) separately — a strict `script-src` with a
  missing `object-src` or `base-uri` is a common gap.

## 2. Common Bypass Patterns

| Weakness in policy | Why it's exploitable | Classification |
|---|---|---|
| `unsafe-inline` present | Inline `<script>`/event handlers execute regardless of nonce/hash | Critical — policy provides no real protection |
| `unsafe-eval` present | `eval()`/`Function()`-based payloads still run | High |
| Wildcard or overly broad host (`*.example.com`, `*`) in `script-src` | Any subdomain/host matching the pattern can host attacker script, including via a JSONP or open-redirect endpoint on an allowed domain | High |
| Missing `object-src 'none'` | Flash/plugin-based injection vectors (legacy but still checked) | Medium |
| Missing `base-uri 'self'` | `<base href="attacker.com">` injection redirects relative script/resource loads | High |
| Whitelisted CDN with known JSONP/Angular/unsafe endpoints | Attacker abuses a legitimate allowed host's own JSONP callback or client-side template injection to smuggle execution | High |
| `nonce`-based policy with a predictable/reused nonce, or nonce leaked via another response | Attacker replays the leaked nonce on injected markup | Critical |
| Policy delivered only via `<meta>` tag, not response header | `<meta>` CSP does not cover resources loaded before it appears in the DOM, and doesn't block outbound requests (e.g. `Referrer-Policy`-relevant leaks) the same way a header does | Medium |

### Detection & interpretation
- For allowed-host bypasses: check known JSONP-endpoint lists (there are
  public "CSP bypass via JSONP" reference lists per popular CDN/service —
  cross-check whatever hosts appear in the target's `script-src`) and
  Angular/client-side-template-injection-capable libraries hosted on the
  same allowed domain.
- For nonce reuse: confirm whether the same nonce value appears across
  multiple page loads/responses (it must be unique per response to be
  secure).

## 3. Remediation (What "Good" Looks Like)

- Avoid `unsafe-inline`/`unsafe-eval` entirely; use per-response nonces or
  content hashes instead.
- Explicitly set `object-src 'none'` and `base-uri 'self'` even if
  `default-src` looks restrictive — these don't inherit safely from
  `default-src` in all browser implementations.
- Avoid wildcarding `script-src` hosts; pin to exact paths where the CDN
  supports subresource integrity (`integrity="sha384-..."`) as well.
- Deliver CSP via the actual HTTP header, not only a `<meta>` tag.
- Rotate nonces per-response, never per-session or per-deployment.

## PortSwigger Lab Mapping

PortSwigger's "Content Security Policy" lab category directly covers this —
CSP bypass via dangling markup, JSONP endpoints, AngularJS sandbox escape
within an allowed script-src host, and `<base>` tag injection are all
represented there. This is one of the few adjacent-topics in this library
with strong, direct lab coverage — no significant gap to disclose here.
