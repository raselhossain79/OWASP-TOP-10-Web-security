# Open Redirect — Overview and Classification

## 1. What Open Redirect Actually Is

Open redirect (CWE-601: URL Redirection to Untrusted Site) happens when an application takes user-controllable input and uses it — without sufficiently validating that it stays within the application's own domain — as the destination of a redirect.

That destination assignment can happen in two fundamentally different places:

- **Server-side**: the application reads a request parameter and writes it into the `Location` header of an HTTP 3xx response. The browser never executes any application JavaScript; it just follows the header.
- **Client-side (DOM-based)**: JavaScript already running in the page reads a value (from the URL, a stored value, a postMessage, etc.) and assigns it to a sink such as `location.href`, `location.replace()`, or `window.open()`. No full server round-trip is required for the redirect itself.

Both produce the same end-user outcome: the victim's browser ends up navigating to a domain the victim never typed in and never intended to visit, while everything up to that point — the link's hostname, the TLS certificate, the address bar — belonged to a domain they trust.

That last point is the entire reason this is treated as a vulnerability rather than a cosmetic bug: it lends **borrowed credibility** to whatever comes next. A phishing link that starts with `https://accounts.example.com/...` and only redirects to the attacker's page after the click is dramatically more convincing — and survives automated URL-reputation scanning dramatically better — than a bare `https://evil-attacker-site.ru/...` link.

## 2. Classification — The Four Issue Types

Open redirect is not one monolithic bug class. There are four distinct issue types, split along two axes: **where the unsafe data originates** (reflected from the current request vs. stored from a previous one) and **where the redirect actually happens** (server response header vs. client-side script).

| Issue type | Origin of unsafe data | Where the redirect executes |
|---|---|---|
| Open redirection (reflected) | Current request's parameter | Server `Location` header |
| Open redirection (stored) | Previously submitted/stored value | Server `Location` header |
| Open redirection (DOM-based, reflected) | Current request's URL (query string or fragment) | Client-side JavaScript sink |
| Open redirection (DOM-based, stored) | A value stored earlier (e.g. in a database field) and later rendered into the page | Client-side JavaScript sink |

The DOM-based variants matter for testing methodology because they will never show up in a proxy history as a 3xx response — there may be no extra HTTP request at all. You have to read the JavaScript or watch the DOM, not just watch traffic.

### Common DOM-based sinks

When you're hunting the client-side variants specifically, these are the assignment targets to grep for in page source / bundled JS:

- `location`, `location.href`, `location.hostname`, `location.host`, `location.pathname`, `location.search`, `location.protocol`
- `location.assign()`, `location.replace()`
- `window.open()`
- `element.srcdoc`
- `XMLHttpRequest.open()` / `.send()` (when the URL itself is attacker-controlled and used as a navigation target downstream)
- jQuery's `$.ajax()` / `jQuery.ajax()` (same caveat — relevant when the resolved URL feeds a navigation, not just a background fetch)

If an attacker controls the *start* of a string that reaches one of the `location.*` sinks, the impact can escalate past redirection entirely — a value beginning with the `javascript:` pseudo-protocol can execute arbitrary script when the browser processes it, turning a "mere" open redirect into a same-origin script execution primitive.

## 3. Detection Methodology

### 3.1 Build a parameter wordlist

Open redirect targets are almost always exposed through a small, predictable set of parameter names. When you're auditing login flows, "next step" links, logout buttons, marketing redirectors, or checkout success/cancel callbacks, fuzz these names specifically:

```
url, redirect, redirect_url, redirect_uri, redirectTo, return, returnUrl,
return_to, returnTo, next, continue, dest, destination, target, rurl,
redir, forward, out, view, login_url, logout, callback, checkout_url,
success_url, cancel_url, image_url, domain, data, u, r, link, navigate,
goto, path
```

### 3.2 Confirm with a canary domain

For each candidate parameter:

1. Supply a value pointing at infrastructure you control and can observe — your own Burp Collaborator subdomain or your PortSwigger exploit server.
2. Watch for one of:
   - A `3xx` response whose `Location` header echoes your canary domain (server-side).
   - The browser's address bar actually navigating to your canary domain after a click, with no obvious corresponding network request in the proxy history (DOM-based — confirm by reading the page's JS).
3. Once confirmed, characterize the validation that exists, if any:
   - **None** — your raw domain works unmodified.
   - **Blocklist** — certain literal substrings (`http://`, known bad domains) are stripped or rejected, but the underlying parsing logic isn't replicated. This is the category file 2 in this series is entirely dedicated to defeating.
   - **Allowlist, substring/prefix-based** — the app checks whether your trusted domain's name appears anywhere in the value, or whether the value starts with it. Both are defeatable with the `@` userinfo trick and domain-confusion tricks covered in file 2.
   - **Allowlist, strict/exact-match** — the value must equal (or exactly prefix-match including a trailing slash) one of a small set of fully-qualified registered URLs. This is the only pattern that reliably resists every technique in this series; it is also exactly what PortSwigger's own OAuth guidance recommends for `redirect_uri` validation (see file 3).

## 4. Real-World Industry Framing

### Triage reality in bug bounty

Standalone open redirect is, on its own, usually triaged as **Low or even Informational/Not-Applicable** by most bug bounty programs — plenty of public program policies explicitly state that an unchained open redirect alone is out of scope or will be closed without a bounty, precisely because the only thing it does in isolation is redirect a browser. CVSS scoring of a bare open redirect tends to land in a similar low band for the same reason: no direct data disclosure, no direct account compromise.

That triage reality is also exactly why this vulnerability class deserves serious attention rather than being skipped: severity is almost entirely a function of **what you chain it into**, and the three chains below routinely turn a near-zero-bounty finding into a critical, full-account-takeover report.

### Chain 1 — Phishing credibility and security-gateway evasion

The borrowed-credibility effect described in section 1 is not theoretical. Open redirects on widely-trusted, high-reputation domains (large platforms, ad-tracking redirectors, transactional-email link-wrapping services) get actively hunted by phishing operators for two compounding reasons:

- **Human trust**: a recipient who hovers over or glances at the link sees a domain they recognize and trust, and the TLS certificate on that first hop is genuinely valid for that domain.
- **Automated trust**: email security gateways and URL-reputation engines that scan the *first* hostname in a link will see the same trusted domain and frequently allow the message through, never following the redirect chain far enough to flag the final attacker-controlled destination.

### Chain 2 — OAuth / SSO token theft via `redirect_uri`

Covered in full depth in file 3 of this series. In short: OAuth and OpenID Connect flows hand a highly sensitive artifact (an authorization code, or in the implicit grant, the access token itself) back to the application via a browser redirect to a registered `redirect_uri`. If that redirect_uri validation can be bypassed — and an in-scope open redirect is frequently the missing piece that lets an attacker walk a validated-but-loosely-checked redirect_uri the rest of the way to fully external infrastructure — the result is full account takeover with no password required.

### Chain 3 — Bypassing Referer-based trust checks

Some integrations and internal endpoints decide whether to trust an incoming request partly by checking that the `Referer` header matches an approved domain. Because an open redirect physically lives *on* the trusted domain, a single click through it produces a navigation whose Referer (as seen by whatever receives that first request) is the trusted domain — satisfying a check that was never designed to anticipate the trusted domain immediately forwarding the user elsewhere. Separately, when a victim is redirected away from a page whose own URL carries sensitive data in the query string (a password-reset token, a session identifier passed as a GET parameter), the browser's default behavior of sending the full departing-page URL as the Referer to the next origin means an attacker who controls the open redirect's final destination receives that sensitive query string in their own server logs — leaked by the trusted page that "should" have known better.

## 5. PortSwigger Lab Mapping for This File

| Lab | Topic area | Difficulty | What it actually teaches |
|---|---|---|---|
| DOM-based open redirection | Client-side → DOM-based vulnerabilities | Apprentice | The single Academy-native open redirect lab. A `url` query parameter is read by a client-side script and assigned to `location.href` with no validation at all — pure detection-and-exploitation of the basic DOM-based sink described in section 2. |

**Honest gap disclosure:** PortSwigger's Academy has exactly **one** interactive lab dedicated to open redirect as a standalone topic, and it has zero filtering to defeat — it exists purely to teach the DOM-based sink mechanic. There is no Academy lab for the plain server-side reflected/stored variant in isolation (those issue types are documented in PortSwigger's vulnerability/issue catalog, but not built out as a standalone interactive lab), and there is no Academy lab at all for practicing blocklist bypass on an open redirect in isolation. File 2 and file 4 of this series cover where those bypass techniques actually do show up in the Academy — chained into other topics, not as a dedicated target.
