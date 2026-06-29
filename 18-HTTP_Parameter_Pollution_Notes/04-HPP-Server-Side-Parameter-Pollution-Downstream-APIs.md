# 04 — Server-Side Parameter Pollution and Downstream API Injection

## 1. Why this file is different from the rest of the series

Every other file in this series describes a technique that PortSwigger Web Security Academy
does **not** have a dedicated lab for. This file is the exception. **Server-side parameter
pollution (SSPP)** is the one sub-class of HPP that the Academy built real, interactive,
hands-on labs around, under its **API Testing** topic. If you only have time to practice one
file of this series on real lab infrastructure, it's this one.

## 2. The core mechanism

SSPP happens when an application takes user-controlled input and embeds it, **unsafely
encoded**, into a second request the application makes to an internal/backend API on the
user's behalf. The user never talks to that internal API directly — but if the front-end
application fails to properly encode special characters (`#`, `&`, `=`) before building the
internal request string, the user can inject an entirely new parameter, or even redirect which
URL path is hit, inside a request they were never supposed to have any control over.

This is the same root idea as classic server-side request forgery, narrowed specifically to
*parameter injection* rather than full URL/host redirection.

## 3. Worked example — query string injection (mirrors the real Academy lab structure)

**Scenario:** A password-reset flow. The front-end app receives a `username` field and, behind
the scenes, queries an internal API to look up that user's reset details.

**The internal request the application builds (not visible to the attacker directly):**

```
GET /internal-api/user-lookup?username=peter&field=email
```

**Step-by-step breakdown of how an attacker discovers and exploits this:**

1. **Baseline.** The attacker submits a normal-looking username, e.g. `administrator`, in the
   public-facing forgot-password form, and observes a clean response (an error like
   `Invalid username` if the account doesn't match, or a success indicator if it does).
2. **Probe with query syntax characters.** The attacker appends a URL-encoded `#`
   (`%23`) to the submitted username:
   ```
   username=administrator%23
   ```
   `#` is a query-string-terminator character. If the application is unsafely concatenating
   the user's raw `username` value directly into the internal request's query string instead
   of encoding it first, the internal request becomes:
   ```
   GET /internal-api/user-lookup?username=administrator#&field=email
   ```
   Everything after `#` is now a URL **fragment**, not part of the query string — meaning the
   internal API never receives `field=email` at all. The error message changes (e.g.
   `Field not specified`), which tells the attacker their injected `#` successfully truncated
   the internal request and that the internal API expects a `field` parameter the attacker
   didn't know about until this moment.
3. **Re-inject the missing parameter under attacker control.** Now that the attacker knows the
   internal API expects a `field` parameter, they add their own version of it, URL-encoding the
   `&` that joins it:
   ```
   username=administrator%23%26field=email
   ```
   Internal request becomes:
   ```
   GET /internal-api/user-lookup?username=administrator#&field=email&field=email
   ```
   Wait — more precisely, the attacker's encoded `&field=x` is now genuinely part of the query
   string (since it comes *before* the `#` truncation point in the final URL), giving:
   ```
   GET /internal-api/user-lookup?username=administrator&field=x#&field=email
   ```
   The original, legitimate `&field=email` is now pushed past the `#` and discarded as part of
   the fragment. The attacker's `field=x` is the **only** `field` parameter the internal API
   actually receives — full server-side parameter pollution achieved. The original parameter
   wasn't duplicated and resolved differently by two parsers (the file `01`–`03` mechanism);
   instead, the attacker used query-syntax characters to make the *backend itself* duplicate-
   and-overwrite the parameter on the attacker's behalf, by hijacking where the query string
   is considered to end.
4. **Brute-force the valid field name.** The attacker doesn't know the internal API's exact
   field-name vocabulary, so they send the candidate `field` value through Burp Intruder using
   a wordlist of plausible internal field/variable names. A response with no error indicates a
   guessed name like `field=reset_token` is valid for this API.
5. **Exfiltrate the sensitive field.** With a valid field name confirmed, the attacker sets:
   ```
   username=administrator%23%26field=reset_token
   ```
   and the internal API call now returns the administrator's password reset token in the
   response — data this internal endpoint was never meant to expose to an external user
   directly, accessed entirely through query-string parameter injection.
6. **Complete the takeover.** The attacker uses the leaked reset token at the genuine
   password-reset endpoint to set a new password for the administrator account.

## 4. Worked example — REST URL path injection (the second real Academy lab pattern)

**Scenario:** Same password-reset flow, but the internal API is RESTful and the username is
embedded in the URL **path**, not the query string:

```
GET /internal-api/v2/users/administrator/field/email
```

**Breakdown:**

1. **Detect path placement.** The attacker submits `administrator?` as the username. If the
   app embeds it unencoded into the path, the resulting internal request becomes:
   ```
   GET /internal-api/v2/users/administrator?/field/email
   ```
   The `?` now starts a query string within what the internal router expected to be a path
   segment, truncating the path the router actually matches against. An "Invalid route"
   response confirms the username is placed directly into the URL path without encoding.
2. **Traverse with relative path sequences.** The attacker tries
   `./administrator` (returns the original, valid response — confirming this resolves to the
   same path) and then `../administrator` (returns "Invalid route" — confirming one level of
   `../` does escape the expected path segment, but lands somewhere invalid). This confirms
   path traversal sequences are not being sanitized either.
3. **Walk upward to the API root.** By incrementally adding more `../` sequences
   (`../../../../#`) the attacker walks up the directory structure until reaching a generic
   "Not found," indicating they've successfully escaped the entire intended API namespace.
4. **Discover the API version/structure.** From the API root, the attacker requests common API
   definition filenames (e.g., OpenAPI/Swagger spec paths) to recover the internal API's actual
   route structure and supported versions/fields — turning a parameter-pollution bug into a full
   internal API reconnaissance primitive.
5. **Pivot the version and field.** Using the recovered structure, the attacker crafts a path
   that swaps the API version and targets the same sensitive field as the query-string example:
   ```
   username=../../v1/users/administrator/field/passwordResetToken%23
   ```
   This downgrades to an older, less-restricted API version (`v1`) that still supports a field
   the current version (`v2`) deprecated for security reasons, and retrieves the password reset
   token directly.
6. **Complete the takeover** exactly as in the query-string example — use the leaked token to
   reset the administrator's password.

## 5. Why both examples ultimately produce the same outcome from different mechanisms

The query-string example exploits **fragment truncation** (`#`) plus **parameter re-injection**
(`&`). The REST URL example exploits **unescaped path traversal** (`../`) plus **query-string
start truncation** (`?`). Both are the identical underlying flaw — *user input reaches a
server-to-server request without being properly encoded for the syntactic context it lands in*
— expressed through whichever syntax characters are relevant to that specific request format
(query string vs. URL path).

## 6. Downstream-API impact beyond password reset

The worked examples above use password reset because that's the literal Academy lab scenario,
but the same mechanism generalizes to any front-end-to-backend-API call built from
unsanitized user input, including:

- **Internal pricing/inventory APIs** — query-string injection into a backend pricing
  microservice call, pulling fields the public-facing API was never meant to expose (cost
  basis, supplier identity, internal SKU metadata).
- **Internal user-directory or HR-system lookups** behind an employee-facing portal.
- **Cloud metadata/internal service endpoints** reached via a backend HTTP client that builds
  its request URL from user input — this is the same family of risk as SSRF, and the two
  should always be tested together on any engagement.
- **OAuth authorization servers** — PortSwigger's own OAuth material recommends testing
  `redirect_uri` specifically for duplicate-parameter handling between the client application
  and the authorization server's backend validation step, since they're typically maintained
  by entirely separate engineering teams.

## 7. PortSwigger Web Security Academy lab coverage — official, full, in progression order

These are the only two labs in the entire HPP technique family that exist as dedicated,
interactive PortSwigger Academy labs. Both sit under the **API Testing** learning topic, and
both must be completed in this order, since the second lab assumes the query-string technique
from the first as prerequisite knowledge:

| Order | Lab name | Technique tested | What "solved" looks like |
|---|---|---|---|
| 1 | **Lab: Exploiting server-side parameter pollution in a query string** | Fragment truncation (`#`) + parameter re-injection (`&`) in a query string, as broken down in section 3 above | Log in as administrator and delete user `carlos` |
| 2 | **Lab: Exploiting server-side parameter pollution in a REST URL** | Unescaped path placement, path traversal (`../`), and API version downgrade, as broken down in section 4 above | Log in as administrator and delete user `carlos` |

Both labs are listed directly under the **API Testing → Server-side parameter pollution**
section of the Academy, and PortSwigger explicitly frames this section as the formal home of
what the wider industry sometimes loosely calls "HTTP parameter pollution" — with the caveat
(repeated from file `01`) that they intentionally use the more precise term "server-side
parameter pollution" to avoid collision with the WAF-bypass usage of the same name.

There is no third or higher-difficulty lab beyond these two for this specific technique on the
Academy at the time of this writing — coverage here is complete but limited to these two labs.

## 8. Real-world note

Server-side parameter pollution against internal APIs is a well-documented finding category in
bug bounty programs that expose any kind of "API gateway in front of microservices"
architecture — which, in 2026, is most mid-to-large SaaS platforms. It's a particularly
efficient technique for bounty hunters because a single successful internal-API field-disclosure
finding (leaking an internal field your application was never meant to expose) is often
reportable on its own merit as an information disclosure / broken access control finding, even
before chaining it into something as severe as the account-takeover outcome shown in the worked
examples above.
