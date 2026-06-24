# LDAP Filter Syntax Reference

Every payload in files 03–05 is built from the grammar in this file. Read this first — this is the single most important file in the series, because LDAP injection is fundamentally a **grammar manipulation attack**, not a "magic string" attack like classic SQLi.

## 1. The Filter Grammar (RFC 4515)

An LDAP search filter is defined by this grammar (simplified from RFC 4515):

```
filter     = '(' filtercomp ')'
filtercomp = and / or / not / item
and        = '&' filterlist
or         = '|' filterlist
not        = '!' filter
filterlist = 1*filter
item       = simple / present / substring
simple     = attr filtertype assertionvalue
filtertype = '=' / '~=' / '>=' / '<='
present    = attr '=*'
substring  = attr '=' [initial] '*' [final] ['*' middle]* 
```

Translate that into plain English, piece by piece:

| Symbol | Meaning | SQL analogy |
|---|---|---|
| `&` | Logical AND — **prefix** operator, applies to ALL conditions that follow it in parentheses | `AND` (but infix) |
| `\|` | Logical OR — **prefix** operator | `OR` (but infix) |
| `!` | Logical NOT — negates the single filter that follows | `NOT` |
| `=` | Equality match | `=` |
| `>=` `<=` | Greater/less than or equal | `>=` `<=` |
| `~=` | Approximate ("sounds like") match | `LIKE` (loosely) |
| `*` | Wildcard — matches zero or more characters | `%` in `LIKE` |
| `(attr=*)` | "Presence" test — true if the attribute exists on the entry, regardless of value | `IS NOT NULL` |

**The critical structural difference from SQL**: in SQL, `AND`/`OR` sit *between* two operands (`a=1 AND b=2`). In LDAP, `&`/`|` sit *before* a list of operands, and the whole list is wrapped in parens: `(&(a=1)(b=2))`. This is **Polish/prefix notation**. It means you cannot "break out" of a filter with something like `' OR '1'='1` the way you would in SQL — there's no infix operator to hijack. Instead, you manipulate the filter by **closing parentheses early and opening new filter terms**, which is why every LDAP injection payload is built around counting and placing `)`  and `(` characters correctly. Internalize this now — it's the reason files 03–05 spend so much time on parenthesis bookkeeping.

## 2. Example Filter, Fully Decomposed

```
(&(objectClass=person)(uid=jsmith)(department=Sales))
```

Read this from the outside in:

1. `(&...)` — outermost operator is AND: every condition inside must be true.
2. `(objectClass=person)` — condition 1: the entry's `objectClass` attribute equals `person`.
3. `(uid=jsmith)` — condition 2: the entry's `uid` attribute equals exactly `jsmith`.
4. `(department=Sales)` — condition 3: the entry's `department` attribute equals exactly `Sales`.

All three must be true for the entry to be returned. This is the kind of filter a "find employee by username and department" feature builds server-side, typically as a string-concatenated template like:

```python
filter = "(&(objectClass=person)(uid=" + user_input + ")(department=" + dept_input + "))"
```

That concatenation — user input dropped directly between parentheses with no escaping — is the vulnerability. Everything in files 03–05 is about what you put into `user_input` to change the *structure* of this filter, not just its values.

## 3. Characters You Need to Control, and What Each One Does

| Character | Effect when injected unescaped | Why it matters offensively |
|---|---|---|
| `)` | Closes the current filter group early | Lets you terminate the developer's intended condition before they expected, so your own injected term takes over from that point |
| `(` | Opens a new filter group | Lets you start a new condition the developer didn't write |
| `&` | Forces everything that follows (until matching parens close) to be AND'd together | Used to inject additional must-be-true conditions, or — critically — to "absorb" a leftover/broken trailing filter term so the whole expression stays syntactically valid |
| `\|` | Forces everything that follows to be OR'd together | Used to add an alternative condition that, if true, makes the whole filter true regardless of the original condition |
| `!` | Negates the next filter | Used to flip a known-true condition to false, or vice versa, during blind boolean testing |
| `*` | Wildcard / presence test | Used to enumerate attribute existence and values without knowing them in advance (see file 05) |
| `\00` (NUL byte) | In some older or native-code-backed LDAP bindings (notably .NET's `System.DirectoryServices` over ADSI), a NUL byte can truncate the filter string entirely at the native layer even though the managed string still "contains" trailing characters | Historically used to bypass appended trailing conditions entirely — covered as a technique note in file 03; success depends heavily on the specific LDAP binding library and is not universal |

## 4. Why There Is No `OR 1=1` Equivalent — Read This Carefully

This is the single most common misconception ported over from SQL injection experience, and PortSwigger's own research has made the point directly: in SQLi, `' OR '1'='1` works because `OR` is infix and short-circuits the whole `WHERE` clause to true. In LDAP, if the developer's filter is conjunctive (built with `&`), then **any condition you inject inside that same `&` group can only make the result more restrictive, never less** — because `&` requires every member to be true. You cannot inject an OR-true condition *inside* an existing AND group and have it loosen the AND; AND doesn't work that way regardless of what's inside it.

The actual bypass technique (detailed fully in file 03) is different: you don't try to make an existing AND-group evaluate true despite a false term — you **close the AND group early with `)`, then open your own new term**, so your injected content is no longer logically inside the developer's restrictive filter at all. That's a structural injection, not a logical short-circuit, and it's why payloads look like:

```
*)(uid=*))(|(uid=*
```

— a deliberate sequence of "close what's open, inject what I want, then neutralize what's left over" rather than a single magic boolean phrase.

## 5. Filter Encoding Rules You'll See Referenced

RFC 4515 requires these characters to be represented as their hex escape (`\XX`) when they appear as **literal data** inside an assertion value (not as filter syntax you're injecting — these are for completeness/defense awareness):

| Character | Escape |
|---|---|
| `*` | `\2a` |
| `(` | `\28` |
| `)` | `\29` |
| `\` | `\5c` |
| NUL | `\00` |

A correctly defended application escapes these five characters on every user-controlled value before insertion into a filter. **If you can inject any of `) ( * \` unescaped into a filter, the application is vulnerable** — this is your single fastest manual test: submit a lone `*` or `)` into a suspected LDAP-backed field and watch for a change in behavior (error, empty result set, unexpectedly broad result set).

## 6. Quick Self-Check Before Moving On

You should now be able to answer, for any LDAP filter shown to you:
- Which operator is outermost, and what scope (which parenthesis group) it governs
- What happens if you append a stray `)` after a given input position
- Why injecting `*` into a `uid=` field behaves like a wildcard search rather than an exact match

If any of that is unclear, re-read sections 1 and 4 before continuing — files 03, 04, and 05 build directly on this without re-explaining the grammar.
