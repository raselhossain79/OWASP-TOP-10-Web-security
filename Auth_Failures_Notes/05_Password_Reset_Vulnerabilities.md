# 05 — Password Reset Flow Vulnerabilities

## 1. Why Password Reset Deserves Its Own File

PortSwigger's own authentication-hardening guidance makes this point
directly: a password reset or change flow is just as valid an attack
surface as the main login page, and must be held to the same security bar
— yet in practice it is one of the most under-reviewed flows in real
applications, because it's usually built once, works, and is never
revisited. It maps to two Academy labs (#3 and #11), placed at very
different points in the Academy's difficulty progression (Apprentice and
Practitioner respectively), which itself reflects how this attack surface
ranges from "obvious logic gap" to "subtle infrastructure-level poisoning."

## 2. Password Reset Broken Logic (Lab 3)

### 2.1 The Vulnerability Class

This is a catch-all for password reset flows where the **logic gate**
between "request a reset" and "actually changing the password" is flawed —
the cryptographic strength of the reset token (Section 3) is irrelevant if
the application never properly checks that the token belongs to the account
being reset in the first place. Common concrete patterns:

- The reset confirmation request accepts a `username` or `userId` parameter
  separately from the reset token, and the server uses **that** parameter
  to decide whose password to change — rather than deriving the target
  account strictly from the token itself. An attacker who has *any* valid
  token (even one issued for their own account) can simply change the
  `userId` parameter to a victim's ID and reset the victim's password
  instead.
- The reset flow is multi-step (request → enter token → set new password),
  and a later step doesn't re-verify that the token from an earlier step
  was actually validated, allowing an attacker to skip straight to the
  final step.
- The token is checked for validity but not for **expiry**, so an old,
  long-since-used token still works indefinitely.

### 2.2 How to Test

1. Walk the entire flow once normally on your own test account, capturing
   every request in Burp.
2. Identify every parameter that could plausibly identify *whose* password
   is being reset (username, email, user ID, account ID — sometimes more
   than one of these appears redundantly across different steps).
3. Repeat the flow, but at the final "set new password" step, tamper with
   the account-identifying parameter to point at a different (test) account
   while keeping your own legitimately-issued token — if the reset still
   succeeds against the *other* account, the logic gate is broken.
4. Separately, try replaying an already-used token, and try using a token
   issued long ago (after waiting past any stated expiry window) to test
   invalidation and expiry independently of the identity-binding issue
   above — these are distinct checks and a flow can pass one while failing
   the other.

## 3. Password Reset Poisoning via Middleware (Lab 11)

### 3.1 The Vulnerability

Many password reset emails embed a **full URL** pointing back to the reset
page, and that URL is frequently built dynamically from request headers
rather than a hardcoded domain — most commonly the `Host` header. If the
application (or a piece of middleware/proxy logic in front of it) trusts an
attacker-controlled header to construct that URL, an attacker can manipulate
the reset link sent to a **victim's** inbox so that it points to an
attacker-controlled domain instead of the legitimate one.

### 3.2 Attack Flow

1. Attacker submits a password reset request for the **victim's** email
   address, but manipulates the `Host` header (or `X-Forwarded-Host`, which
   is the specific header implicated in the "via middleware" variant of
   this lab — some reverse proxies/load balancers read `X-Forwarded-Host`
   in preference to `Host` when constructing internal URLs, which is the
   "middleware" part of the name) to point at an attacker-controlled domain.
2. The application generates a valid reset token for the victim's account,
   and embeds it in a reset URL built using the attacker-supplied host
   value — e.g., `https://attacker-controlled.com/reset?token=VICTIM_TOKEN`.
3. This email is sent to the **real victim's real inbox** (the attacker
   never sees it directly) — but if the victim ever clicks the link
   (or, separately, if any automated security scanning/link-preview system
   the victim's mail provider runs visits the link first, which has been a
   real-world amplification factor for this exact bug class), the
   victim's valid token is sent in the request to the **attacker's**
   server, where the attacker can read it from their own access logs.
4. Attacker then takes that captured, still-valid token and uses it on the
   **real, legitimate** reset page to set a new password for the victim's
   account.

### 3.3 How to Test

1. Capture a normal "forgot password" request.
2. Add or modify the `Host` header (and separately, the `X-Forwarded-Host`
   header, testing each independently since an app might trust one and not
   the other) to an arbitrary value you control or can observe traffic to
   (e.g., a Burp Collaborator-style listener, or any domain/webhook
   endpoint you control for the engagement).
3. Trigger the reset email to a test account you control, and inspect the
   actual email body for the reset link's domain.
4. If the link reflects your injected header value rather than the
   application's real domain, the flow is vulnerable — confirm impact by
   actually capturing a token this way and using it to complete a reset
   against the test account from the legitimate domain, proving the full
   chain works end-to-end rather than stopping at "the header is
   reflected."

### 3.4 Why This Is a "Middleware" Issue Specifically

The core technical root cause sits one layer below typical application
code: many applications never directly read the raw `Host` header
themselves for this purpose — instead, a reverse proxy, API gateway, or
framework-level "base URL" helper resolves it on the application's behalf,
often defaulting to trusting `X-Forwarded-Host` because that header exists
specifically to let proxies tell the backend what the original client-facing
hostname was. The vulnerability exists because that trust is extended
without restricting which upstream systems are allowed to set that header
in the first place — exactly the same root-cause pattern as the
`X-Forwarded-For` rate-limit bypass in File 03, just applied to URL
construction instead of IP-based access control. Recognizing this as the
same underlying class of trust misconfiguration, reappearing across two
different impact areas, is useful when writing up findings: it's often
worth flagging both as symptoms of one root architectural issue
(unauthenticated trust in client-supplied forwarding headers) rather than
two unrelated bugs.

## 4. Other Password Reset Token Issues Worth Testing (Beyond the Two Labs)

These don't map to a specific Academy lab but are standard real-world
checks on any reset flow, and are commonly found in bug bounty programs:

- **Token leakage via Referer header**: if the reset page (after a user
  clicks the emailed link) contains any outbound links or loads
  third-party resources (analytics scripts, fonts, ad pixels), the token
  embedded in the current page's URL can leak to that third party via the
  `Referer` header, depending on the page's `Referrer-Policy`. Check
  whether the reset confirmation page sets a strict `Referrer-Policy`
  (e.g., `no-referrer` or `same-origin`) and whether the token is removed
  from the URL (e.g., via a client-side redirect to a token-free URL,
  with the token instead held in a short-lived server-side session) once
  the page has loaded.
- **Token reuse**: confirm a reset token is invalidated immediately after
  one successful use, not just after its time-based expiry.
- **Token entropy**: apply the same Burp Sequencer methodology from File 04
  Section 3.2 to reset tokens specifically — they are frequently weaker
  than session tokens because developers sometimes treat them as a "lower
  stakes," shorter-lived value, when in practice a successful reset grants
  full account takeover, arguably making the token's strength *more*
  critical, not less.
- **Old password not required for change-while-logged-in**: distinct from
  reset-via-email, the "change password while authenticated" flow should
  itself require the current password — without that, a session-hijacking
  or CSRF bug elsewhere becomes a full account-takeover primitive (silently
  changing the victim's password locks the real owner out, escalating an
  otherwise temporary compromise into a persistent one).
