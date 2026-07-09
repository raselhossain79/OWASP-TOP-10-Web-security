# 03 — SameSite / Cookie-Based Bypass Techniques

## 1. Why this file exists separately from token bypasses

SameSite is a *browser-enforced* defense, not a server-side check. Even an
application with zero CSRF tokens can be partially protected if its session cookie
carries strict-enough `SameSite` restrictions, because the browser itself will
refuse to attach the cookie to certain cross-site requests — the server never even
sees a session-authenticated request to reject.

Since 2021, Chrome (and other major browsers following the same proposed standard)
apply `SameSite=Lax` by default to any cookie that doesn't explicitly declare a
`SameSite` attribute. This means a huge number of applications get *some* baseline
protection without their developers doing anything — which is exactly why testers
need to understand the gaps in that default rather than assume "no explicit
SameSite attribute" means "vulnerable."

## 2. Site vs. origin — the distinction every bypass in this file depends on

This is the single most important concept in this file. Get it wrong and you'll
either miss real findings or chase ones that don't exist.

- **Origin** = scheme + full domain + port. `https://app.example.com` and
  `https://intranet.example.com` are different origins.
- **Site** = scheme + eTLD+1 (effective top-level domain plus one label).
  `https://app.example.com` and `https://intranet.example.com` are the **same
  site**, because both reduce to `example.com`.

| Request from | Request to | Same-site? | Same-origin? |
|---|---|---|---|
| `https://example.com` | `https://example.com` | Yes | Yes |
| `https://app.example.com` | `https://intranet.example.com` | Yes | No (different subdomain) |
| `https://example.com` | `https://example.com:8080` | Yes | No (different port) |
| `https://example.com` | `https://example.co.uk` | No | No |
| `https://example.com` | `http://example.com` | No (scheme mismatch) | No |

The practical consequence: **a cross-origin request can still be same-site.**
SameSite restrictions only block *cross-site* requests — they do nothing to stop one
subdomain attacking a sibling subdomain, because the browser considers that
same-site. This is the foundation of the sibling-domain and on-site-gadget bypasses
below.

## 3. The three restriction levels, and what each actually blocks

```
Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict
```

- **`Strict`** — never sent on any cross-site request, full stop, even top-level
  navigation by clicking a link. Strongest protection; can break legitimate
  cross-site flows like arriving at a logged-in page via an external link.
- **`Lax`** — sent on cross-site requests **only if both** conditions hold: the
  request method is GET, **and** the request is a top-level navigation (the user's
  browser address bar actually changes to the target URL — e.g. clicking a link or
  `document.location = ...`). Crucially, the cookie is **not** sent on cross-site
  POST requests, and not sent on background requests triggered by scripts, iframes,
  `<img>`, or `fetch()` — even if those happen to use GET.
- **`None`** — disables SameSite entirely; sent on every request regardless of
  origin. Must be paired with `Secure` (HTTPS-only) or browsers reject the cookie
  outright.
- **No attribute set at all** — Chrome (and the emerging standard) treats this as
  `Lax` by default. Other browsers may still default to `None`-like behavior, so
  defense reliability varies by target browser — always note which browser the
  victim is expected to use when writing a PoC, since some PortSwigger labs
  explicitly specify "the victim will be using Chrome."

## 4. Bypassing Lax restrictions using GET requests

**The flaw:** the application's `Lax`-restricted session cookie blocks cross-site
POST, but the sensitive endpoint also happens to accept GET — exactly the scenario
in file 02, section 2, except here the *browser* is the thing letting the cookie
through, not a server-side validation gap.

**Simplest form — pure top-level navigation, no form needed:**

```html
<script>
    document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
</script>
```

Breakdown:

- `document.location = '...'` performs a genuine top-level navigation — the
  browser's address bar changes to the target URL, exactly as if the user had typed
  it or clicked a link. This satisfies the second `Lax` condition.
- The request method is GET (the default for a navigation), satisfying the first
  condition.
- Both `Lax` conditions are met, so the browser includes the session cookie even
  though this script is running on the attacker's origin.
- Note this is functionally identical to file 01's GET-CSRF `<img>` example in terms
  of the request that gets sent — the difference is *why* it works here: in file 01
  there was no SameSite defense at all, while here we are specifically defeating a
  `Lax` cookie that would otherwise have blocked a cross-site POST.

**Method-override bypass — when the endpoint genuinely requires POST semantics but
the framework supports method overriding:**

```html
<form action="https://vulnerable-website.com/account/transfer-payment" method="GET">
    <input type="hidden" name="_method" value="POST">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
```

Breakdown:

- `method="GET"` on the `<form>` tag means the browser issues an actual GET request
  — satisfying the `Lax` method condition at the network level, which is what the
  browser's SameSite enforcement inspects.
- `<input type="hidden" name="_method" value="POST">` is a framework-level
  convention (Symfony is the documented example, but many frameworks support similar
  override parameters like `_method`, `X-HTTP-Method-Override`) that tells the
  *application's router* to treat this as a POST for business-logic purposes, after
  the browser has already sent it as a GET.
- The remaining hidden inputs (`recipient`, `amount`) are the actual attack
  parameters, submitted as GET query parameters.
- This combination lets the attacker satisfy the browser's SameSite GET requirement
  while still reaching a route that was written expecting POST.

## 5. Bypassing restrictions using on-site gadgets

**The flaw:** `Strict` cookies are never sent cross-site — but if the attacker can
find any mechanism *on the target site itself* that triggers a secondary, same-site
request on the attacker's behalf, that secondary request is not cross-site from the
browser's point of view, so all cookie restrictions are waived for it.

The canonical gadget is a **client-side redirect** that builds its destination from
attacker-controllable input (a DOM-based open redirect):

1. Attacker finds a page on the target site, e.g.
   `https://vulnerable-website.com/redirect?url=...`, where client-side JavaScript
   reads the `url` parameter and sets `window.location` to it without validation.
2. Attacker crafts a link:
   `https://vulnerable-website.com/redirect?url=/account/transfer-payment?recipient=hacker%26amount=1000000`
3. Attacker delivers this link to the victim (from any origin — it doesn't matter,
   because the *first* hop, to `vulnerable-website.com/redirect`, is itself the
   request that matters for SameSite purposes when it's a top-level navigation; the
   browser then executes the client-side redirect *as the site itself*).
4. As far as the browser is concerned, the resulting navigation to
   `/account/transfer-payment` is a **same-site request initiated by the site's own
   JavaScript**, not a cross-site request from the attacker's page. SameSite cookie
   restrictions — even `Strict` — are not evaluated against this hop at all, because
   there's no cross-site boundary being crossed from the browser's perspective at
   the moment the final request fires.

Critical distinction explained: this works for **client-side** redirects only. A
**server-side** redirect (HTTP 301/302/303 response) does not have this effect — the
browser correctly remembers that the *original* request that triggered the redirect
chain was cross-site, and continues applying the original SameSite restrictions
through the redirect. Only a client-side redirect (JavaScript reassigning
`window.location`, or a meta-refresh) resets the browser's notion of "what triggered
this request" to "the site itself."

## 6. Bypassing restrictions via vulnerable sibling domains

**The flaw:** "site" includes every subdomain under the same eTLD+1. Any
vulnerability that lets an attacker run arbitrary JavaScript or trigger arbitrary
requests on **any** subdomain of the target site compromises SameSite protection for
**every** subdomain.

Concretely: if `https://blog.example.com` has a reflected XSS vulnerability, and the
main application's sensitive cookie is scoped to `.example.com` (so it's sent to
both `blog.example.com` and `app.example.com`), then:

1. Attacker delivers a payload exploiting the XSS on `blog.example.com`.
2. That JavaScript executes in the context of `blog.example.com`, which is
   **same-site** with `app.example.com`.
3. Any `fetch()` or form submission that script makes to `app.example.com` is a
   same-site request as far as the browser is concerned — full cookie inclusion,
   `Strict` included, applies.

This also generalizes to **WebSockets**: if the target application uses
WebSockets and doesn't independently validate the `Origin` header on the WebSocket
handshake, the same same-site trust extends to the handshake request, enabling
**Cross-Site WebSocket Hijacking (CSWSH)** — conceptually a CSRF attack against the
handshake itself, since the handshake is just an HTTP GET request that the browser
will include cookies on, and SameSite restrictions provide the same partial
protection (or lack thereof) as for any other request.

**Why this matters for testing scope:** when auditing SameSite defenses, the audit
boundary is the *entire site*, not just the application you were asked to test. A
vulnerability on a marketing blog subdomain can compromise the security of the
banking subdomain it shares a site with. Always note shared cookie scope (check the
`Domain` attribute on `Set-Cookie`) when scoping a CSRF/SameSite assessment.

## 7. Bypassing Lax restrictions with newly issued cookies

**The flaw:** to avoid breaking single sign-on (SSO) flows when Chrome rolled out
default `Lax` enforcement, Chrome does **not** enforce `Lax` restrictions for the
first 120 seconds after a cookie is set, specifically for top-level POST requests.
This grace period exists only for cookies that received the default `Lax` behavior
(no explicit `SameSite` attribute) — not for cookies explicitly set with
`SameSite=Lax`.

**Exploitation concept:**

1. Find a gadget on the target site that causes the victim's session cookie to be
   **reissued** — most reliably, an SSO/OAuth login flow, since the identity
   provider doesn't necessarily know whether the user already has an active session
   and will often complete the flow and set a fresh session cookie silently.
2. Force the victim through that re-issuance via a top-level navigation (required so
   the browser includes their existing OAuth/IdP session cookies and completes the
   flow without an interactive login prompt).
3. Immediately follow up — within the 120-second window — with the real CSRF attack,
   now riding on a cookie that the browser hasn't started enforcing `Lax` rules on
   yet.

**The popup-blocker problem and its workaround:**

```html
<script>
window.onclick = () => {
    window.open('https://vulnerable-website.com/login/sso');
}
</script>
```

Breakdown:

- A bare `window.open('https://vulnerable-website.com/login/sso')` fired
  automatically on page load is blocked by default popup blockers, because browsers
  only allow `window.open()` as a direct result of genuine user interaction.
- Wrapping the call inside `window.onclick = () => { ... }` defers execution until
  the victim clicks **anywhere** on the attacker's page — satisfying the browser's
  "user interaction" requirement for popups, while still requiring no specific
  target element (any click triggers it).
- The popup opens in a new tab, completes the SSO flow (re-issuing the session
  cookie) without navigating the attacker's main tab away, leaving that main tab free
  to deliver the actual CSRF payload immediately afterward, while still inside the
  120-second enforcement grace window.

This is a narrow, timing-dependent, and somewhat fragile technique in practice — note
this honestly in any report rather than overstating reliability. It's most useful as
a demonstration of defense-in-depth gaps rather than a primary, dependable exploit
path.

## 8. Real-world notes

- The most commonly missed finding in this category during real assessments is
  section 6 (sibling domains) — testers scope their assessment strictly to the
  target subdomain and never check whether other subdomains under the same eTLD+1
  share cookie scope and have their own weaknesses.
- When reporting any SameSite bypass, always state explicitly which browser you
  tested with and its version, since enforcement specifics (the 120-second grace
  period, in particular) are Chrome-specific behavior that may not reproduce
  identically in Firefox or Safari.
- A frequent false-positive mistake: assuming `SameSite=Lax` blocks all cross-site
  CSRF. It only blocks cross-site **POST** and non-top-level requests. Always check
  whether the same action is reachable via GET before concluding `Lax` fully
  mitigates a finding.
- For bug bounty reports specifically, "I bypassed SameSite=Strict via a
  client-side open redirect" is a much stronger and more fundable finding when
  framed as: root cause = the open redirect, demonstrated impact = SameSite/CSRF
  bypass leading to account takeover. Programs pay for impact chains, not isolated
  textbook bypasses.
