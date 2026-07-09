# Authentication Bypass via LDAP Filter Manipulation

**Prerequisite**: file `02_LDAP_Filter_Syntax_Reference.md`. Every payload below assumes you've internalized why `&`/`|` are prefix operators and why there's no SQLi-style infix OR bypass. If a target filters or strips `* ( ) \` or NUL, see file `03_Filter_Bypass_and_Evasion.md` first — the payloads below assume those characters reach the filter unmodified.

## 1. The Two Authentication Patterns You'll Encounter

Real-world LDAP-backed login flows use one of two patterns. **Identify which one you're facing before choosing a payload** — they require different techniques.

### Pattern A: Single-Filter Bind (the vulnerable pattern)

The application builds one search filter containing both username and password as LDAP attribute checks, retrieves the matching entry (or count of matches), and treats "a match was found" as "login successful" — **without ever performing a real LDAP bind (authentication) using the password.**

```python
filter = "(&(uid=" + username + ")(userPassword=" + password + "))"
result = ldap_connection.search(base_dn, filter)
if result.count > 0:
    login_success()
```

This is the classic vulnerable pattern, and it's vulnerable for the same reason a SQLi login bypass is: **the password is being checked via a search filter, not a real bind/authentication call.** If you can manipulate the filter so it returns true regardless of password, you're in.

### Pattern B: Search-Then-Bind (still attackable, different angle)

The application searches for the username first (e.g., `(uid=username)`) to resolve it to a DN, then performs a **real LDAP bind** with that DN and the supplied password. Here, the password is never part of a filter — it's used in an actual authentication call, so password-side filter injection doesn't apply. **The username-lookup filter is still injectable**, and is most useful for enumeration (file 06) or for influencing *which* DN gets resolved if the filter logic can be tricked into matching an unintended entry — e.g., an account with a known/blank password, or a service account.

**Real-world note**: Pattern A is more common in older, custom-built internal tools and legacy intranet portals — exactly the kind of thing you'll find on an internal AD pentest or in a 10-year-old extranet portal that's never been re-architected. Pattern B is more common in modern SSO/IdP products that wrap a real LDAP bind. Test for Pattern A first; it's the higher-value bug.

## 2. Bypass Payload #1 — Closing the AND Group Early

**Target filter** (Pattern A): `(&(uid=USERNAME)(userPassword=PASSWORD))`

**Payload, username field**: `*)(uid=*))(|(uid=*`

**Resulting filter after concatenation** (assume password field is left blank or garbage):
```
(&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))
```

Piece-by-piece breakdown of the payload `*)(uid=*))(|(uid=*`:

| Fragment | What it does |
|---|---|
| `*` | Wildcard — matches the `uid=` value the developer's template already opened for us, satisfying that first condition trivially |
| `)` | Closes the `(uid=*` term the developer opened |
| `(uid=*)` | A complete, self-contained, always-true presence test we've injected — "any entry that has a uid attribute," which is every user entry |
| `)` | Closes the outer `(&...)` group early. At this point, the AND group is syntactically complete and evaluates true (both its members matched) |
| `(\|` | Opens a brand-new, separate OR group. This is no longer inside the developer's AND — it's a sibling expression |
| `(uid=*` | Opens another always-true presence test inside our OR group, deliberately left with its closing paren omitted because... |
| *(nothing)* | ...the developer's template supplies the rest: `)(userPassword=` + our (empty/garbage) password + `))`, which now closes our injected `(uid=*` term and the `\|` group, and the final `)` closes everything |

**Why this works**: The whole expression is now `(AND-group-that-is-true) (OR-group-that-is-also-true)`. The server returns the union of matches. Since both groups independently match every entry with a `uid`, the search returns every user in the directory — the application's "if any result, login succeeds" logic then logs you in, typically as the **first entry in the result set**, which is often the directory's first/admin-adjacent account depending on directory ordering. This exact bypass concept is the LDAP equivalent of `' OR '1'='1` — not because of an infix OR, but because we restructured two independently-true filter groups side by side.

## 3. Bypass Payload #2 — Targeting a Specific Known Username

If you want to authenticate as a **specific** user (e.g., `admin`) rather than just "whoever comes back first," inject into the password field instead, once you've confirmed the username field resolves correctly:

**Target filter**: `(&(uid=admin)(userPassword=PASSWORD))`

**Payload, password field**: `*)(uid=admin)(|(uid=*`

Actually, the cleaner and more reliable version targets making the AND group's second condition irrelevant:

**Payload, password field**: `*)(&(uid=admin))`

Walking through it: `*` wildcard-matches whatever garbage is already in `userPassword=`, then `)` closes that term, then `(&(uid=admin))` is injected as a brand-new always-true (since we already know `admin` exists) standalone group. The net filter:

```
(&(uid=admin)(userPassword=*)(&(uid=admin)))
```

This makes the password check a wildcard presence test (`userPassword=*`, true as long as the admin account has any password set at all — true for virtually every real account) rather than an exact-value match. **You never learn or need the actual password** — you're converting an equality check into a presence check.

## 4. Bypass Payload #3 — NOT-based Negation (Pattern with `!`)

Some login filters are written defensively-looking but still flawed, e.g. checking that an account is *not* disabled:

**Target filter**: `(&(uid=USERNAME)(!(accountStatus=disabled)))`

If `USERNAME` is injectable: `*)(!(accountStatus=*` 

Breakdown: `*` wildcards the uid match, `)` closes it, `(!(accountStatus=*` opens a NOT wrapping a presence test — "NOT (account has any accountStatus attribute at all)" — which is true for any account that simply doesn't have that attribute set, often the case for accounts provisioned outside whatever workflow sets `accountStatus`. The developer's trailing `))` closes both the `!` and the outer `&`. This demonstrates that **negation can be weaponized just as easily as `&`/`|`** when the application builds defensive-seeming conditions string-by-string instead of with parameterized binds.

## 5. Why Escaping the Password Field Often Isn't Enough

A subtlety worth flagging for your engagement notes: developers sometimes escape the **password** field (since it's "sensitive") but forget the **username** field (since it "looks like just a string"). Always test **both** fields independently — the asymmetry in input handling is common and is exactly the kind of finding that separates a thorough tester from someone who tries one payload and moves on.

## 6. PortSwigger Academy Lab Mapping

**No PortSwigger Academy lab exists for LDAP authentication bypass specifically** — see file 01, section 6, for the full explanation of this gap. PortSwigger's Authentication topic labs (e.g., the password-reset and 2FA-bypass labs) are SQL/logic-backed, not LDAP-backed, so they are not a substitute despite the superficial "auth bypass" similarity.

**Practice alternatives for this exact technique**:
- **OWASP WebGoat → "LDAP Injection" lesson** — includes a login-bypass-style exercise against a simulated LDAP backend; closest direct equivalent to a PortSwigger lab for this technique.
- **Self-hosted lab** (recommended if WebGoat coverage feels too scripted): stand up OpenLDAP locally, seed it with a few `inetOrgPerson` entries via `ldapadd`, then write a 15-line Python/Flask login form using `ldap3` or `python-ldap` that string-concatenates the filter exactly as shown in section 1, Pattern A. This gives you a fully controllable, realistic target to validate every payload in this file against real LDAP server responses rather than theory — and it's a legitimate, defensible "I built this to practice" line for an interview.

## 7. Real-World Note

Authentication-bypass LDAP injection is most dangerous on **internet-facing SSO, VPN, and extranet login portals** that bind to internal Active Directory — because a successful bypass here is frequently a **direct, pre-authentication foothold into the internal network**, not just "logged into a website." When you find this on an engagement, flag it as critical and prioritize it in your report regardless of how minor the front-end application itself seems — the value is the AD trust relationship behind it, not the web app.
