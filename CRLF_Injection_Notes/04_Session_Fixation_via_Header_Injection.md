# 04 — Session Fixation via Injected Headers

## What session fixation is, and how CRLF feeds it

Session fixation is an attack where the attacker forces a victim's browser
to use a session identifier the attacker already knows, then waits for the
victim to authenticate — at which point the attacker can use that same
known session ID to access the now-authenticated session. Session fixation
normally requires the application to accept a session ID supplied by the
client (e.g. via a URL parameter or pre-existing cookie) without
regenerating it on login.

CRLF injection becomes relevant here as a **delivery mechanism**: if an
attacker can inject an arbitrary `Set-Cookie` header into a response the
victim's browser will process, they don't need the application to accept a
client-supplied session ID at all — they can simply set the victim's
session cookie directly via the injected header, achieving the same
end state by a different route.

## Piece-by-piece: forging Set-Cookie via CRLF

Vulnerable sink (same shape as the redirect example in file `02`, but
exploited for a different goal):

```
response.setHeader("Location", "/profile?lang=" + request.getParameter("lang"));
```

Malicious request:

```
GET /profile?lang=en%0d%0aSet-Cookie:%20session=ATTACKER-KNOWN-VALUE;%20Path=/%0d%0a%0d%0a HTTP/1.1
Host: example.com
```

Breaking this down:

| Fragment | Meaning |
|---|---|
| `en` | The expected, benign value for `lang` |
| `%0d%0a` | Terminates the `Location` header early, same mechanism as file `02` |
| `Set-Cookie:%20session=ATTACKER-KNOWN-VALUE;%20Path=/` | A forged cookie-setting header. The attacker chooses `ATTACKER-KNOWN-VALUE` themselves — this is the entire point. `Path=/` ensures the cookie is sent on every subsequent request to the site, not just the redirect target |
| `%0d%0a%0d%0a` | Closes the forged header and terminates the header section, so the response body (if any) isn't accidentally appended to the cookie value |

If this request reaches a victim — typically via a crafted link the
attacker convinces the victim to click, since the attacker needs the
victim's *browser* to process the response, not their own — the victim's
browser stores `session=ATTACKER-KNOWN-VALUE` exactly as if the server had
legitimately issued it. If the victim then logs in and the application does
not regenerate the session ID on authentication, the session now
authenticated as the victim is the *same* session ID the attacker already
holds in their own browser. The attacker simply browses to the
authenticated area using their copy of that cookie.

## Why this matters even when the application "does session fixation
defense correctly"

A well-built application regenerates the session ID on login specifically
to defeat classic session fixation (where the attacker hands the victim a
session ID via a URL parameter, e.g. `?PHPSESSID=...`). CRLF-based
`Set-Cookie` injection bypasses that defense in one important case: **if the
forged cookie isn't the application's own session cookie, but a secondary
cookie the application trusts for something else** — a "remember me" token,
a CSRF token stored in a cookie, a feature flag, or a cookie read by a
client-side script to make trust decisions. Regenerating the *session* ID
on login does nothing to protect a *different* cookie the attacker also
controls via the same injection point.

## Real-world note

Pure session-fixation-via-CRLF findings are uncommon in current bug bounty
programs for two compounding reasons: modern frameworks filter `\r\n` out of
header-setting calls (file `02`'s root-cause discussion applies directly
here), and most session frameworks already regenerate session IDs on login
as a baseline defense. When this does surface, it's almost always in one of
two contexts: (1) a custom auth/SSO integration where a secondary trust
cookie (not the main session) is set via a hand-rolled redirect, or (2) an
internal/legacy system where the CRLF filtering hardening that ships with
modern frameworks was never backported. Document and report it as a
chained finding — "CRLF injection in `X` allows forging `Set-Cookie`,
leading to fixation of cookie `Y`, which the application trusts for `Z`" —
rather than a bare CRLF finding, since the severity rests entirely on what
the forged cookie is trusted to do.

## PortSwigger lab note

There is no dedicated PortSwigger lab for CRLF-driven session fixation —
the technique is a direct extension of the response-splitting mechanism in
file `02`, applied to a `Set-Cookie` sink instead of an arbitrary header,
and PortSwigger's lab back-ends use frameworks that filter raw CRLF from
header APIs by default, so it doesn't reproduce as a clean teaching lab.
For hands-on practice, apply the same byte-level technique from file `02`
against a local hand-rolled HTTP server (e.g. a small Python `socketserver`
or unpatched legacy PHP install) where you control whether CRLF filtering
is present, so you can observe the exact moment the injected `Set-Cookie`
appears in the raw response.
