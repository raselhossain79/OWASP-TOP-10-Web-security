# Authentication Mapping

## 1. Purpose
Understand exactly how the application establishes and maintains a user's identity
— this is a prerequisite for most authorization testing and for several
vulnerability classes (session fixation, JWT manipulation, password reset flaws)
that only make sense once the mechanism is understood.

## 2. When to Use
Right after input-surface analysis, before any authorization or business-logic
testing.

## 3. Prerequisites
A test account on the target (register your own where possible — see
`01-Scope-and-Authorization.md`).

## 4. Methodology
1. Identify the login mechanism: session cookie, JWT, OAuth, API key, or a mix.
2. For session cookies: check flags (`HttpOnly`, `Secure`, `SameSite`) and whether
   the session ID appears predictable or is a long random token.
3. For JWTs: decode the token (without needing the signing key) to see what claims
   it carries and which algorithm it declares.
4. Map every auth-adjacent flow: login, logout, password reset, "remember me",
   multi-factor (if present), and account registration.

## 5. Commands
```bash
# Inspect session cookie attributes
curl -s -I https://target.com/login -c cookies.txt
cat cookies.txt

# Decode a JWT's header and payload (no key needed — this does not verify the signature)
echo "<JWT_HERE>" | cut -d '.' -f1 | base64 -d 2>/dev/null
echo "<JWT_HERE>" | cut -d '.' -f2 | base64 -d 2>/dev/null
```

## 6. Command Breakdown
- `-c cookies.txt`: saves cookies curl receives to a file in Netscape format,
  letting you inspect flags set on the session cookie.
- `cut -d '.' -f1` / `-f2`: a JWT is three base64url-encoded segments joined by
  dots (header.payload.signature) — this extracts the header and payload segments
  separately for decoding. `base64 -d` decodes them to readable JSON. This only
  reveals what the token *claims*; it does not prove the claims are valid or that
  you could forge a new one — that depends on the signing algorithm and whether the
  signing key/secret is weak or exposed, which is a separate, specific hypothesis to
  test (e.g. `alg: none` acceptance, weak HMAC secret) rather than assumed from
  decoding alone.

## 7. Expected Output
A documented auth mechanism: cookie-based session with specific flags, or a JWT
with specific claims/algorithm, plus a map of every related flow (login, reset,
logout).

## 8. Interpretation
Missing `HttpOnly`/`Secure`/`SameSite` flags are worth noting but are not
automatically exploitable findings on their own — they describe *increased risk
under certain other conditions* (e.g. missing `HttpOnly` matters most if an XSS
exists elsewhere to actually steal the cookie). Report them as what they are:
defense-in-depth gaps, not standalone critical findings, unless you can
demonstrate actual impact.

## 9. False Positives
- A JWT claiming `alg: HS256` doesn't mean the secret is weak or guessable — that
  requires separate testing (e.g. against a wordlist) to actually confirm.

## 10. Next Action
Feed the mechanism details into `authorization-mapping.md` (role/permission
testing needs a working, understood auth flow first) and into relevant
`06-Vulnerability-Testing/` files for any specific weakness hypothesis formed here.

## 11. Safety Considerations
Use only your own test account's credentials/tokens for this analysis. Do not
attempt to decode, forge, or manipulate tokens belonging to other real users.

## 12. Documentation
Record the mechanism type, cookie/token flags observed, and every auth-related
flow mapped — this becomes the reference for authorization testing next.
