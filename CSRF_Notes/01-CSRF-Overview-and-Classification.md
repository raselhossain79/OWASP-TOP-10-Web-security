# 01 — CSRF Overview and Classification

## 1. What CSRF actually is

Cross-Site Request Forgery is **not** an attack that steals data directly. It is an
attack that abuses the trust a server places in a victim's browser to make the
*browser* issue a request the victim never intended to send.

The attacker never sees the response. They cannot read the victim's session cookie.
What they can do is force the victim's authenticated browser to fire off a request —
"change my email," "transfer funds," "add an admin user" — and have the server treat
it exactly as if the real user clicked the button.

This distinction matters because it explains why CSRF needs three things to exist at
the same time, and why fixing any one of them kills the vulnerability.

## 2. The three preconditions

For a CSRF attack to be possible, all three of the following must be true:

1. **A relevant action exists.** Something the attacker has a reason to trigger:
   changing an email/password, transferring money, changing privacy/security
   settings, adding a user, deleting an account. Read-only actions are not
   interesting targets for classic CSRF (there's no state change to abuse), though
   they can still matter for things like cache poisoning or analytics manipulation.

2. **The request relies solely on cookies (or another auto-attached credential)
   for authentication.** If the application uses cookie-based sessions and there is
   no other mechanism — no unpredictable token, no custom header the browser won't
   add automatically — to confirm the request was deliberately issued by the user,
   the browser will silently attach the session cookie to *any* request to that
   domain, regardless of which page triggered it.

3. **No unpredictable parameters.** The attacker must be able to construct the full
   request without needing to know any secret value tied to the victim (such as
   their current password). If the endpoint requires the user's existing password to
   change it to a new one, CSRF against that endpoint is not possible, because the
   attacker cannot supply a value they don't know.

If you remove any one of these — make the action harmless, add a real CSRF token
that's properly tied to the session, or require a value the attacker can't guess —
the vulnerability disappears. Every bypass technique in files 02 and 03 is really an
attack against precondition #2: defeating whatever mechanism the developer added on
top of cookies to try to verify intent.

## 3. Classic CSRF — no defenses at all

This is the simplest and historically most common form, and it's still found
regularly in legacy internal tools, admin panels, and IoT device web interfaces.

**Vulnerable request (what the legitimate user's browser sends):**

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
```

Walking through why this is exploitable:

- `Cookie: session=...` — the browser attaches this automatically on every request to
  `vulnerable-website.com`, regardless of which page initiated the request. The server
  has no way to distinguish "the user clicked Save on my-account" from "some other
  page made this same request in the background."
- `email=wiener@normal-user.com` — this is the only parameter, and the attacker can
  set it to literally anything. There's no second value (a token, a re-typed
  password) that the attacker doesn't already know.
- There is no `csrf` parameter, no custom header, nothing tying this request to a
  specific page load or session-bound secret.

**The attack page:**

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

Piece by piece:

- `<form action="..." method="POST">` — recreates the exact endpoint and HTTP method
  the real form uses. The `action` must match exactly, including scheme.
- `<input type="hidden" name="email" value="pwned@evil-user.net" />` — supplies the
  one unpredictable-to-the-server-but-not-to-the-attacker parameter. The field `name`
  must match the real parameter name exactly, or the server will ignore or reject it.
- `<script>document.forms[0].submit();</script>` — submits the form automatically the
  instant the page loads, with no click required from the victim. `document.forms[0]`
  refers to the first (and only) form on the page.
- The browser, navigating to this page, will **not** attach anything from
  `vulnerable-website.com` to the page itself (this page is on the attacker's own
  domain) — but the *form submission* is a normal cross-site POST to
  `vulnerable-website.com`, and the browser attaches the victim's existing session
  cookie for that domain to that outgoing request, exactly as it would for any
  ordinary navigation. This is the core mechanic: the cookie travels with the
  destination, not the origin of the page that triggered the request.

## 4. GET-based CSRF

If the vulnerable action can be triggered with a GET request instead of POST, the
attack gets simpler — no separate page, no auto-submitting form, no JavaScript
required at all.

```
GET /email/change?email=pwned@evil-user.net HTTP/1.1
Host: vulnerable-website.com
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE
```

A self-contained exploit is just an `<img>` tag:

```html
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```

Why this works without any script:

- The browser treats `<img src="...">` as a resource fetch — it issues a GET request
  to that URL regardless of whether the URL actually returns an image. The browser
  doesn't validate content-type before sending the request; it just fires the GET and
  then fails to render whatever comes back as an image (which the attacker doesn't
  care about).
- Because it's a GET, the entire payload — endpoint and parameter — fits in one URL.
  The attacker can embed this single `<img>` tag in a forum post, a comment field, an
  email body (if it renders HTML), or any other place an unsuspecting victim's browser
  will load it.
- The session cookie is attached the same way as in the POST case: cookies are
  per-destination-domain, not per-referring-page.
- This is exactly why **state-changing actions should never be exposed via GET** —
  it's not just a REST-purity guideline, it directly enables one-line CSRF with zero
  attacker infrastructure beyond getting a victim to load any page containing the tag.

## 5. CSRF and CORS misconfiguration

These are two different vulnerability classes that get confused constantly, and the
distinction is worth being precise about in a report:

- **CSRF** exploits the browser sending cookies automatically with cross-site
  requests. The attacker can make the request happen, but cannot read the response
  due to the Same-Origin Policy. CSRF is a write/state-change attack.
- **CORS misconfiguration** is about whether JavaScript on one origin is allowed to
  *read* the response from a request to another origin. A misconfigured CORS policy
  (e.g. reflecting `Origin` back in `Access-Control-Allow-Origin` combined with
  `Access-Control-Allow-Credentials: true`) lets the attacker's page issue a
  credentialed cross-origin request **and read the response**.

Where they intersect:

- A bad CORS policy effectively upgrades a CSRF-style write into a full
  request-and-read attack. Without the misconfiguration, the attacker could still
  often trigger the state change blind via classic CSRF; with the misconfiguration,
  they can also read back session-bound data such as an API key, a CSRF token value
  embedded in a JSON response, or account details — directly via `fetch()` with
  `credentials: 'include'`.
- A common chaining pattern: the attacker's page issues a credentialed `fetch()` to
  an endpoint that returns the user's current CSRF token in its JSON body (e.g. a
  `/api/user/profile` endpoint). If CORS is misconfigured to allow the attacker's
  origin with credentials, the attacker's JavaScript reads that token out of the
  response, then immediately issues the real state-changing request with the stolen
  token attached — fully defeating a token-based CSRF defense that would otherwise
  have blocked a blind form-submission attack.
- **Reporting note:** when you find this combination, report it as a CORS
  misconfiguration with CSRF-token-theft impact, not as a CSRF finding. The CORS flaw
  is the root cause; the CSRF angle is the demonstrated impact. Triagers on
  HackerOne/Bugcrowd specifically look for impact framed this way — "I can read the
  CSRF token and use it to perform action X" is a much stronger, clearer report than
  two separate vague findings.

## 6. The XSS → CSRF chaining pattern

This is the most common way a "properly defended" application (correct CSRF tokens,
even strict SameSite cookies) still ends up exploitable.

The chain, conceptually:

1. The attacker finds a stored or reflected XSS vulnerability anywhere on the same
   site (or, for SameSite purposes, anywhere on the same *site* per the
   eTLD+1 definition — see file 03 for why a sibling subdomain counts).
2. JavaScript injected via that XSS runs in the victim's browser **in the security
   context of the vulnerable site itself.** This is the critical detail: it is not a
   cross-site request anymore. The script is same-origin (or at minimum same-site)
   with the target application.
3. Because the script executes same-origin, it can read the DOM, including any
   hidden `<input name="csrf" value="...">` field, or call the application's own API
   endpoints with `fetch()`/`XMLHttpRequest` and have the browser attach cookies
   normally — no CORS issue even arises, because the script *is* the site as far as
   the browser is concerned.
4. The script extracts the current, valid CSRF token and immediately submits the
   real state-changing request with that token attached.

Why this defeats every defense covered in files 02 and 03 simultaneously:

- **CSRF tokens** are irrelevant because the script reads the real one directly from
  the page instead of needing to guess or forge it.
- **SameSite cookies**, even `Strict`, are irrelevant because the request the script
  makes is not cross-site at all — it originates from a script running on the
  vulnerable site's own origin.
- **Referer-based validation** is irrelevant for the same reason: the Referer header
  correctly shows the vulnerable site's own domain, because that's genuinely where the
  request came from.

This is precisely why PortSwigger's own materials state that CSRF tokens (and other
CSRF-specific defenses) provide **no protection against XSS**, and conversely, **XSS
defenses are what actually prevent this chain** — there is no CSRF-side fix for it.

**Reporting note:** if you find this chain, the root-cause vulnerability is the XSS.
Report the XSS as the primary finding, and use "successfully exfiltrated the CSRF
token / performed a privileged action through it" as proof of impact and severity
justification, not as a separate CSRF report. Most programs will reject a "CSRF"
report whose only viable trigger is an existing XSS, since fixing the XSS removes the
entire attack path regardless of how the CSRF protection is implemented.

## 7. Real-world notes

- In real engagements, the single most common CSRF finding is on **legacy admin
  panels and internal tools** that were built before the org adopted a framework with
  CSRF protection baked in, or that predate the framework's CSRF middleware being
  enabled.
- A frequent mistake junior testers make: reporting CSRF on an action that doesn't
  actually change meaningful state (e.g. a "search" form, a UI theme toggle with no
  security implication). Always tie the report to a concrete, named impact — account
  takeover, privilege escalation, financial loss — not just "no CSRF token present."
- Another frequent mistake: testing CSRF only with POST and missing that the same
  endpoint also accepts GET (precondition #2 still holds either way) — always check
  both methods against the same endpoint.
- Bug bounty programs increasingly scope out "self-XSS requiring CSRF" or "CSRF on
  logout" as not impactful. Read the program's scope/exclusions before submitting —
  many explicitly exclude low-impact CSRF (e.g. CSRF that only logs a user out).
