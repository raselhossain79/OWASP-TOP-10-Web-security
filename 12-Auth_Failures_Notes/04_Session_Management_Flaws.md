# 04 — Session Management Flaws

## 1. Honest Scope Note

The PortSwigger Web Security Academy's Authentication topic does **not**
currently include a dedicated lab for classic session fixation or for raw
session-token entropy analysis as standalone exercises. The closest related
lab is **#9, "Brute-forcing a stay-logged-in cookie"** (Other mechanisms
sub-topic, Practitioner), which is about a predictable persistent-login
token rather than the session cookie itself — it's referenced below where
relevant, but this file is built primarily from real-world methodology
rather than forced lab mapping. This is stated up front rather than buried,
per this series' standing rule against fabricating lab references.

## 2. Session Fixation

### 2.1 The Vulnerability

Session fixation occurs when an application allows an attacker to set or
predict a victim's session identifier **before** the victim authenticates,
and then continues to honor that same session ID **after** authentication
succeeds — rather than issuing a brand-new session ID at the point of login.

### 2.2 Attack Flow

1. Attacker visits the target site and obtains a valid (but unauthenticated)
   session ID — either issued automatically by the server, or because the
   app accepts a session ID supplied via a URL parameter or cookie value
   the attacker chooses themselves.
2. Attacker plants that session ID on the victim — e.g., by sending a link
   containing the session ID as a URL parameter (`https://target.com/login?
   sessionid=ATTACKER_CHOSEN_VALUE`), or by setting the cookie directly if
   the attacker has any way to write cookies into the victim's browser for
   that domain (e.g., a separate XSS bug on a sibling subdomain, or a
   network position that lets them inject a `Set-Cookie` header over plain
   HTTP before the victim's connection upgrades to HTTPS).
3. Victim logs in normally, using their real credentials, on the session ID
   the attacker planted.
4. If the application does **not** regenerate the session ID at this point,
   the attacker's already-known session ID is now authenticated as the
   victim. The attacker simply uses that same ID in their own browser to
   ride the victim's authenticated session.

### 2.3 Why Modern Frameworks Mostly Prevent This by Default

Most current major frameworks (Django, Rails, ASP.NET Core, modern PHP
session handling) automatically regenerate the session identifier on
privilege-level changes such as login by default, specifically because
session fixation was historically common enough to warrant a framework-level
fix rather than relying on every developer remembering to do it manually.
This is exactly why it persists in:

- Legacy applications built before this became a framework default.
- Custom-rolled authentication layers that manage sessions manually instead
  of using the framework's built-in session middleware.
- Systems that migrate an existing pre-login session object into a
  post-login authenticated state in place, rather than discarding it and
  issuing a fresh one.

### 2.4 How to Test for It

1. Request the login page unauthenticated; record the session cookie value.
2. Submit valid credentials through the normal login flow.
3. Compare the session cookie value **before** and **after** login.
4. If it is identical, the application is vulnerable to session fixation —
   any attacker who can plant that pre-login value on a victim (Section
   2.2, step 2) can hijack the resulting authenticated session.
5. Additionally check whether the app accepts a session identifier supplied
   via a URL parameter or query string at all (`;jsessionid=...` style URL
   rewriting is the classic historical vector, mostly in older Java
   applications) — accepting session IDs from the URL is a fixation risk
   multiplier because URLs are trivially shareable and end up in browser
   history, referrer headers, and server logs.

### 2.5 Real-World Notes

Session fixation shows up disproportionately in:
- Legacy enterprise Java and ColdFusion applications that historically
  relied on URL-based session tracking (`jsessionid`) for clients with
  cookies disabled.
- Custom SSO bridge code, where a session object is created at the
  identity-provider redirect step and then reused, unchanged, once the
  actual login completes on the service provider side.
- Internal/intranet line-of-business applications, which tend to receive
  far less security review than public-facing systems but still hold
  significant authenticated access.

## 3. Session Token Predictability and Weak Entropy

### 3.1 The Vulnerability

If a session token (or any security-critical token — password reset token,
"remember me" / stay-logged-in token, API key) is generated using a weak or
predictable method, an attacker who can observe a number of valid tokens may
be able to predict a different, currently-valid token without ever stealing
it directly. Common root causes:

- Sequential or near-sequential values (`session_1001`, `session_1002`, ...).
- Tokens derived from predictable inputs — timestamp, incrementing user ID,
  or a weak/non-cryptographic hash of those values.
- Insufficient length — e.g., a 4-digit numeric token has only 10,000
  possible values, brute-forceable in seconds even with conservative rate
  limiting.
- Use of a non-cryptographic pseudo-random number generator (PRNG) whose
  internal state can be inferred or reproduced from observed outputs.

### 3.2 Burp Sequencer — The Standard Tool for This

Burp Suite's **Sequencer** tool is purpose-built for statistically
evaluating token randomness, and is the correct tool to reach for whenever
a session, reset, or persistent-login token needs entropy testing:

1. **Capture a token-issuing request** (e.g., the login response that sets
   the session cookie) and send it to Sequencer (right-click in Proxy
   history → **Send to Sequencer**), or configure a **Custom location**
   if the token doesn't arrive via a cookie (e.g., it's in a JSON response
   body field instead).
2. **Live capture** — Sequencer can repeatedly fire the request and pull a
   fresh token from each response automatically; the standard recommendation
   is to gather **at least several thousand samples** (the tool flags when
   it has enough for statistically meaningful results) since small sample
   sizes can produce misleadingly clean-looking entropy results.
3. **Analyze** — Sequencer runs a battery of standard randomness tests
   (character-level analysis, bit-level analysis, and correlation between
   consecutive tokens) and reports an overall **effective entropy estimate**
   in bits.
4. **Interpretation**: as a practical baseline, modern session tokens should
   land in the range of multiple dozens of bits of effective entropy
   (broadly comparable to a 128-bit cryptographically random value, though
   exact acceptable thresholds depend on token lifetime, exposure surface,
   and what the token actually protects). Significantly lower effective
   entropy than the token's nominal length suggests the generation algorithm
   isn't using its full output space randomly — i.e., it's predictable even
   if it *looks* random at a glance.

### 3.3 Manual Analysis When Sequencer Isn't Available

If automated tooling can't be used in-scope, manually collect a sample set
of tokens (ideally 20–50+) issued in quick succession and look for:

- **Visual sequencing**: do consecutive captures differ by a small,
  consistent delta?
- **Timestamp correlation**: does converting part of the token from hex/
  base64 to a Unix timestamp land suspiciously close to the actual request
  time?
- **Character set and length**: a token using only lowercase hex digits at
  a short length has a far smaller possible-value space than its raw
  character count might suggest at first glance — always calculate the
  actual keyspace (`charset_size ^ length`) rather than assuming "long
  string of characters" automatically means "secure."

### 3.4 Cross-Reference: Lab 9, Brute-Forcing a Stay-Logged-In Cookie

PortSwigger Lab 9 demonstrates the practical endpoint of this exact concern:
a persistent "remember me" cookie constructed from predictable components
(in the lab's case, derivable from the username plus a weakly hashed
password) can be reconstructed/brute-forced offline once the construction
method is reverse-engineered from observing the cookie's structure — the
same entropy-analysis mindset from Section 3.2–3.3 applies directly, just
aimed at a persistent-login token rather than the primary session cookie.

## 4. Related Cookie Attribute Hardening (Context, Not a Vulnerability Class on Its Own)

While not session fixation or entropy issues themselves, these attributes
are routinely checked alongside both, since their absence compounds the
impact of either flaw if it's present:

| Attribute | Purpose | Impact if missing |
|---|---|---|
| `HttpOnly` | Blocks JavaScript access to the cookie | Without it, an XSS bug elsewhere on the same origin can directly read and exfiltrate the session token |
| `Secure` | Cookie only sent over HTTPS | Without it, the token can be captured over any accidental plaintext HTTP request (e.g., a mixed-content resource, or a network attacker on the same network segment) |
| `SameSite` | Controls cross-site sending of the cookie | `SameSite=None` (or absence, on older browsers) increases CSRF exposure; `Lax` or `Strict` reduces it |
| Token regenerated on login/privilege change | Prevents fixation (Section 2) | Its absence **is** the session fixation vulnerability itself |
| Session invalidated server-side on logout | Ensures a stolen/predicted token stops working once the user logs out | Without server-side invalidation, "logout" only clears the client-side cookie — the token, if captured beforehand, remains valid until natural expiry |
