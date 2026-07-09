# 02 — Token Validation Bypass Techniques

## 1. What a CSRF token is supposed to do

A CSRF token is a unique, secret, unpredictable value generated server-side and
delivered to the client (usually as a hidden form field, sometimes as a custom
header value). The client must echo it back exactly when performing the sensitive
action. Because the attacker can't predict this value for the victim's session, they
can't construct a valid forged request — *if the server actually validates it
correctly.*

Almost every real-world CSRF finding against a "protected" application is not "there's
no token at all" — it's one of the five flawed-validation patterns below. The token
exists; the server just doesn't check it the way the developer thinks it does.

## 2. Validation depends on request method

**The flaw:** the server validates the token on POST requests, but the same
business-logic handler also accepts GET — and the GET code path skips token checking
entirely (often because token validation was added as middleware only on the POST
route, or because GET was only meant for rendering a form, not submitting one).

**Legitimate POST request (validated):**

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

csrf=50FaWgdOhi9M9wyna8taR1k3ODOR8d6u&email=wiener@normal-user.com
```

**Bypass — switch to GET, the token check never runs:**

```
GET /email/change?email=pwned@evil-user.net HTTP/1.1
Host: vulnerable-website.com
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
```

Breakdown:

- No `csrf` parameter is included at all — it isn't needed, because the server-side
  route for GET requests to `/email/change` never reaches the token-comparison code.
- This means the attack regresses to plain GET-based CSRF (file 01, section 4) — a
  one-line `<img>` tag exploit is sufficient once you've confirmed the method
  inconsistency.
- **How to find this in testing:** take any token-protected POST request, change the
  method to GET in Burp Repeater (moving the body parameters into the query string),
  and check whether the action still succeeds without a valid token. Always test
  this even on endpoints that "only support POST" according to the front-end — many
  frameworks route both methods to the same handler unless explicitly restricted.

## 3. Validation depends on the token being present

**The flaw:** the server correctly rejects a request with an *incorrect* token, but
fails to reject a request where the token parameter is **missing entirely** — as
opposed to present-but-wrong. This is a classic "checked equality, forgot to check
existence" logic bug (e.g. `if request.csrf and request.csrf != session.csrf: reject`
— note the silent pass-through when `request.csrf` is falsy/absent).

**Legitimate request:**

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

csrf=50FaWgdOhi9M9wyna8taR1k3ODOR8d6u&email=wiener@normal-user.com
```

**Bypass — remove the entire `csrf` parameter, not just its value:**

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

email=pwned@evil-user.net
```

Breakdown:

- The critical detail is the difference between `csrf=` (empty value, parameter
  present) and removing `csrf=...` altogether (parameter absent). Many vulnerable
  implementations only fail this way when the key itself is missing from the request
  body — sending an empty value sometimes still trips the check, while omitting the
  key entirely does not.
- The matching HTML PoC simply omits the hidden input for `csrf` entirely:

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

- **How to find this in testing:** in Burp Repeater, try three variants on a
  token-protected request: (1) wrong token value, (2) empty token value
  (`csrf=`), (3) the parameter deleted entirely (delete the whole `csrf=...&` segment,
  not just the value after `=`). If (1) and (2) are rejected but (3) succeeds, you
  have this flaw.

## 4. Token isn't tied to the user session

**The flaw:** the server maintains a single global pool of "valid tokens it has ever
issued" rather than binding each token to the specific session that received it. Any
token from that pool is accepted, regardless of which session presents it.

**Exploitation:**

1. The attacker logs in using their **own** account.
2. The attacker loads the sensitive form and notes down the token issued to *their*
   session — e.g. `csrf=Tx9f2KpL8eR4hQ6wN1zVbC3jD7sM0aGu`.
3. The attacker builds a CSRF PoC using **their own valid token**, but with the
   victim's intended new value (e.g. an email address the attacker controls):

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="csrf" value="Tx9f2KpL8eR4hQ6wN1zVbC3jD7sM0aGu" />
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

4. When the **victim's** browser submits this form, the server checks "is this token
   in the pool of tokens I've issued?" — yes, it is, because the attacker obtained it
   legitimately from their own session — and accepts the request, applying the change
   to the victim's account because the victim's session cookie (not the attacker's)
   travels with this request.

Breakdown of why this is exploitable:

- The token value is real and was genuinely issued by the server — it's just bound to
  the wrong account. The server's check answers "have I ever issued this token to
  anyone?" instead of "did I issue this token to *this* session?"
- This is why the fix is to tie each token to the session it was issued for (e.g.
  store it server-side keyed by session ID, or sign it with a session-bound secret)
  rather than just checking pool membership.
- **How to find this in testing:** log in with two separate accounts (or two browser
  profiles). Grab a valid token from account A's session, then submit a request using
  account B's session cookie but account A's token. If it's accepted, the binding is
  broken.

## 5. Token tied to a non-session cookie

**The flaw:** a variation of the above. The token *is* tied to a cookie — just not
the session cookie. This often happens when CSRF protection is bolted on from a
separate library/framework than the one handling sessions, and the two were never
properly integrated.

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```

Here, the server checks that `csrf` matches whatever value is associated with
`csrfKey` — but never checks whether that `csrfKey` cookie actually belongs to the
same authenticated session as `session`.

**Exploitation requires one extra capability:** the attacker needs *some* way to set
a `csrfKey` cookie in the victim's browser. This is harder to exploit than the
previous flaw, but still realistic:

1. Attacker logs in with their own account, obtains a valid `csrfKey` cookie value
   and its matching `csrf` token.
2. Attacker finds **any** mechanism on the site (or even a related subdomain within
   the same overall DNS domain, since cookies aren't origin-scoped) that lets them
   set an arbitrary cookie in the victim's browser — for example, a parameter that
   gets reflected into a `Set-Cookie` header, an open redirect with cookie-setting
   side effects, or a vulnerable subdomain like `staging.demo.normal-website.com`
   that can write a cookie scoped broadly enough to also be sent to
   `secure.normal-website.com`.
3. Attacker uses that mechanism to plant **their own** `csrfKey` value into the
   victim's browser.
4. Attacker delivers a standard auto-submitting CSRF PoC using **their own** matching
   `csrf` token value.
5. When the victim's browser submits the form, it sends: the victim's real `session`
   cookie (because the browser auto-attaches all cookies for the domain), the
   attacker-planted `csrfKey` cookie, and the attacker's matching `csrf` token in the
   body. The server checks `csrf` against `csrfKey` — both attacker-controlled and
   matching — and never notices that `session` belongs to someone else entirely.

**Reporting note:** this finding should explicitly call out the cookie-setting
mechanism as a co-requisite vulnerability. A pure "CSRF token isn't session-bound"
report without a demonstrated way to set the cookie is usually marked as theoretical
or informational by triagers — show the full chain.

## 6. Token is simply duplicated in a cookie ("double submit" defense)

**The flaw:** to avoid server-side storage, some implementations set the token value
in *both* a cookie and require it in the request body/header, then simply check that
the two match — with no server-side record of "what token did I originally issue."

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```

The server's entire check is: "does the `csrf` cookie value equal the `csrf` body
value?" It never asks "did *I* generate this value for *this* user?"

**Exploitation:** the attacker doesn't even need a valid token of their own anymore —
they can invent one outright, as long as they can plant it as a cookie in the
victim's browser and supply the matching value in the form body, because the server
only ever compares the two against each other:

1. Attacker picks any arbitrary string, e.g. `csrf=anyValueAttackerLikes123`
   (matching the expected format if the app validates format, e.g. a 32-character
   hex string — even then, the attacker can just choose 32 hex characters of their
   own choosing).
2. Attacker uses a cookie-setting mechanism (same requirement as section 5) to plant
   `csrf=anyValueAttackerLikes123` as a cookie in the victim's browser.
3. Attacker delivers a PoC with that exact same value in the body:

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="csrf" value="anyValueAttackerLikes123" />
      <input type="hidden" name="email" value="pwned@evil-user.net" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

4. The victim's browser sends both the planted cookie and the form's `csrf` value —
   they match (the attacker made sure of that), the server's double-submit check
   passes, and the action executes under the victim's real `session` cookie.

Breakdown of why double-submit cookie validation is structurally weaker than
server-side token storage: it only proves the request and the cookie agree with each
other — never that either of them came from the legitimate server-issued value. The
moment an attacker has any cookie-injection primitive anywhere in the cookie's scope,
the entire defense collapses to "no defense."

## 7. Predictable or weak tokens

Separate from the *validation* flaws above, a token can be cryptographically weak
even when validation logic is otherwise correct:

- **Sequential or incrementing tokens** (`csrf=1001`, `csrf=1002`...) — trivially
  guessable by requesting two tokens close together and observing the pattern.
- **Tokens derived from predictable inputs** — e.g. `MD5(username + date)` with no
  server-side secret/salt. If you can determine the inputs, you can compute the
  token for any user without ever seeing one issued to them.
- **Insufficient entropy / short tokens** — a token space small enough to brute-force
  within the rate limits the application allows.
- **Token reuse across sessions or not regenerated after login** — if the same token
  value remains valid across multiple login sessions for the same user (session
  fixation-adjacent issue), an attacker who captures a token once (e.g. via Wi-Fi
  sniffing on an HTTP page, or a leaked referrer) can replay it indefinitely.

**How to test:** request the protected form/token endpoint multiple times in a row
(same and different sessions) and diff the values. Look for: incrementing patterns,
shared prefixes/suffixes across users, identical token length and character set that
suggests a deterministic hash rather than a CSPRNG, and whether the token changes
after re-authentication.

## 8. Real-world notes

- The single most common pattern found in custom (non-framework) implementations
  during real engagements is section 3 — "validation depends on token being
  present" — because it's an easy off-by-one logic mistake (`if token: check` instead
  of `if not token: reject`).
- Sections 4–6 ("token not properly bound") are common in microservice architectures
  where the auth service and the CSRF-protection layer are different components that
  were never designed together — flag this explicitly in reports as an architectural
  issue, not just a code bug, since it tends to recur across multiple endpoints.
- When writing up any of these for a client report or bug bounty submission, always
  show the *legitimate* request first, then the *modified* request, with the single
  changed element highlighted — triagers and developers fix bugs faster when the diff
  is obvious rather than buried in two long unrelated-looking requests.
- A common mistake: declaring "no session binding" after testing with only one
  account. Always confirm with a second, independent account/session before claiming
  this class of bug — false positives happen when a test harness reuses the same
  session unintentionally.
