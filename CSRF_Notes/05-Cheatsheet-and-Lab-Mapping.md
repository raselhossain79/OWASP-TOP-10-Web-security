# 05 — Cheatsheet and PortSwigger Lab Mapping

## 1. Quick decision tree for live testing

```
Is there a state-changing action reachable with only cookie-based auth
and no unpredictable parameter?
  NO  -> not classic CSRF (check if GET-based or chained via XSS/CORS instead)
  YES -> continue

Is there a CSRF token on the request at all?
  NO  -> classic CSRF. Build baseline auto-submit PoC (file 04 §2).
  YES -> continue

Does removing the token PARAMETER ENTIRELY (not just blanking the value)
still let the request succeed?
  YES -> "validation depends on token being present" (file 02 §3)
  NO  -> continue

Does switching POST -> GET on the same endpoint skip validation?
  YES -> "validation depends on request method" (file 02 §2)
  NO  -> continue

Does a token issued to YOUR OWN session work when submitted
under a DIFFERENT account's session cookie?
  YES -> "token not tied to user session" (file 02 §4)
  NO  -> continue

Is the token tied to a SEPARATE cookie from the session cookie,
and can you find any way to set an arbitrary cookie on the target
(reflected Set-Cookie, vulnerable sibling subdomain, etc.)?
  YES -> "token tied to non-session cookie" (file 02 §5) or
         "double-submit token duplicated in cookie" (file 02 §6)
  NO  -> continue

Is the session cookie missing a SameSite attribute, or set to Lax,
and does the sensitive action also accept GET?
  YES -> SameSite Lax bypass via GET / method override (file 03 §4)
  NO  -> continue

Is the cookie SameSite=Strict, and does the site have ANY client-side
(JavaScript-driven) redirect that uses attacker-controllable input?
  YES -> on-site gadget bypass (file 03 §5)
  NO  -> continue

Does ANY subdomain under the same eTLD+1 have XSS, an open redirect,
or another arbitrary-request primitive, and does the cookie's Domain
scope cover that subdomain?
  YES -> sibling-domain bypass (file 03 §6) -- this compromises ALL
         SameSite levels including Strict
  NO  -> continue

Is there a login/SSO flow that reissues the session cookie, and is the
cookie relying on Chrome's default Lax-by-omission behavior?
  MAYBE -> 120-second newly-issued-cookie window (file 03 §7) --
           narrow and timing-dependent, note this honestly

Separately, always check:
  - Does the app have ANY XSS anywhere in the same origin/site?
      -> if yes, that XSS alone defeats every defense above. Report the
         XSS as root cause (file 01 §6).
  - Is CORS misconfigured (reflected Origin + credentials allowed)?
      -> if yes, this can let an attacker READ tokens/data, not just
         trigger writes blind (file 01 §5).
```

## 2. Severity / impact quick reference

| Scenario | Typical severity framing |
|---|---|
| Classic CSRF on email/password change | High — direct path to account takeover |
| Classic CSRF on non-sensitive setting (theme, locale) | Low/Informational — state change with no security impact |
| CSRF on logout only | Usually out of scope on bug bounty programs — confirm in policy |
| Token-validation bypass requiring a second valid account | Medium–High — still exploitable by any registered user, often including the attacker |
| Token-validation bypass requiring a cookie-setting gadget elsewhere | Report as a chain; severity follows the weaker/easier-to-trigger link |
| SameSite bypass via sibling-domain XSS | Report XSS as root cause; CSRF impact strengthens severity justification |
| CORS misconfiguration enabling token theft | Report CORS as root cause with CSRF/token-theft as demonstrated impact |

## 3. PortSwigger Web Security Academy — CSRF lab mapping

Labs are listed in the exact order they appear under the Academy's CSRF topic
structure: **Bypassing CSRF token validation → Bypassing SameSite cookie
restrictions → Bypassing Referer-based defenses**, which is also the Academy's
intended difficulty progression for this topic. One related Clickjacking lab is
included at the end because it directly demonstrates a CSRF-token-protected action
being bypassed through a different mechanism entirely, which is a useful capstone
exercise once token and SameSite bypasses are solid.

### Foundational

| # | Lab name | Maps to |
|---|---|---|
| 1 | CSRF vulnerability with no defenses | File 01 §3 — classic CSRF, no defenses |

### Bypassing CSRF token validation

| # | Lab name | Maps to |
|---|---|---|
| 2 | CSRF where token validation depends on request method | File 02 §2 |
| 3 | CSRF where token validation depends on token being present | File 02 §3 |
| 4 | CSRF where token is not tied to user session | File 02 §4 |
| 5 | CSRF where token is tied to non-session cookie | File 02 §5 |
| 6 | CSRF where token is duplicated in cookie | File 02 §6 |

### Bypassing SameSite cookie restrictions

| # | Lab name | Maps to |
|---|---|---|
| 7 | SameSite Lax bypass via method override | File 03 §4 |
| 8 | SameSite Strict bypass via client-side redirect | File 03 §5 |
| 9 | SameSite Strict bypass via sibling domain | File 03 §6 |
| 10 | SameSite Lax bypass via cookie refresh | File 03 §7 |

### Bypassing Referer-based defenses

| # | Lab name | Maps to |
|---|---|---|
| 11 | CSRF with broken Referer validation (Referer validation depends on header being present) | Not covered in depth in this series — Referer-based validation is a weaker, less common defense than tokens/SameSite. Briefly: if the check only runs when a `Referer` header is present, stripping the header entirely (e.g. via `<meta name="referrer" content="no-referrer">` in the attack page) bypasses it. |
| 12 | CSRF with broken Referer validation (Referer validation can be circumvented) | Same note as above — typically exploited by manipulating the path/query of the attack page's own URL so that a substring match against the expected domain still passes, or by using a redirect to control what Referer value is sent. |

### Related — Clickjacking with CSRF token protection (separate Academy topic)

| # | Lab name | Maps to |
|---|---|---|
| 13 | Basic clickjacking with CSRF token protection | Not directly mapped to any technique file in this series. This lab demonstrates that a correctly implemented CSRF token does **not** protect against clickjacking, because the victim is tricked into genuinely, manually clicking the real button inside an invisible framed page — the token is submitted legitimately by the victim's own real interaction. This is an important conceptual boundary: **CSRF defenses and clickjacking defenses (`X-Frame-Options` / `Content-Security-Policy: frame-ancestors`) are not interchangeable**, even though both are sometimes grouped under "cross-site attacks." This series does not cover clickjacking in depth — it is a distinct vulnerability class — but the lab is listed here because testers frequently encounter it immediately after finishing the CSRF labs and may otherwise assume a token-protected form is fully safe.

### Honest disclosure — gaps with no dedicated PortSwigger lab

The following techniques covered in this series do **not** have a direct, dedicated
PortSwigger Academy lab as of this writing, and are noted as such rather than forced
into an inaccurate mapping:

- **GET-based CSRF as a standalone lab** (file 01 §4) — demonstrated as part of the
  Referer-bypass labs and the foundational concept pages, but there isn't a lab whose
  sole point is "the action is GET, build an `<img>` exploit." The mechanism is
  covered in the main CSRF topic text itself rather than as an isolated lab.
- **Predictable/weak tokens** (file 02 §7) — no dedicated CSRF-topic lab targets
  token entropy directly. Weak-token-style reasoning is more directly exercised in
  the Academy's Authentication and Information Disclosure topics, which target
  similar "predictable secret value" reasoning in a different context.
- **CORS misconfiguration enabling CSRF-token theft** (file 01 §5) — the Academy's
  CORS topic has its own dedicated labs (e.g. "CORS vulnerability with basic
  origin reflection attack," "CORS vulnerability with trusted null origin") which
  are not part of the CSRF lab set and are out of scope for this series; reference
  them separately if you maintain a CORS-focused note series.
- **XSS-steals-CSRF-token chaining pattern** (file 01 §6) — there is no lab that
  specifically packages this as a CSRF lab, because the Academy correctly treats it
  as an XSS finding. The official "XSS vs CSRF" reference page on the Academy site
  discusses this relationship conceptually but does not attach a standalone lab to
  it under the CSRF topic.

## 4. Burp Suite checklist for a CSRF assessment

- [ ] For every sensitive action, capture the legitimate request and note: method,
  full parameter list, presence/absence of a token, `SameSite` attribute on the
  session cookie (check the `Set-Cookie` response header from login).
- [ ] Test method switching (POST → GET) on every token-protected endpoint.
- [ ] Test token removal (full parameter deletion, not blanking) on every
  token-protected endpoint.
- [ ] Test cross-account token reuse using two independent sessions.
- [ ] Identify the `Domain` scope of the session cookie and enumerate sibling
  subdomains for shared attack surface.
- [ ] Check for any client-side redirect gadgets (grep front-end JS for
  `location.href =`, `location.replace(`, `window.location =` patterns fed by
  query parameters).
- [ ] Check whether the application has any known or discoverable XSS — if so, stop
  treating CSRF defenses as relevant for that endpoint and report the XSS as root
  cause.
- [ ] Check CORS headers (`Access-Control-Allow-Origin`,
  `Access-Control-Allow-Credentials`) on any endpoint that returns a CSRF token or
  other session-bound secret in its response body.
