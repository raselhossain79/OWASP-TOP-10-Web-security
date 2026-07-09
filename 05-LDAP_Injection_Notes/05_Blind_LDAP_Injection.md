# Blind LDAP Injection

**Prerequisite**: files 02 and 04. This file assumes you already understand filter grammar and basic structural injection; here we apply that to situations where you get **no direct visibility** into query results — only a binary true/false signal (or a timing/error difference) — exactly the blind-SQLi mindset, translated into LDAP's prefix-notation operators.

## 1. When You're in "Blind" Territory

You're doing blind LDAP injection whenever:
- A login form gives you "success" vs "failure" but no enumerable result set (most auth bypass scenarios from file 04 are technically already a form of blind boolean testing)
- A search feature returns "0 results" vs "results found" without showing you the actual data
- An application returns a generic error page for malformed filters vs. a normal page for well-formed ones (error-based blind)
- Response timing differs measurably between valid and invalid filter logic (time-based blind — rare for LDAP compared to SQLi, but possible if the directory does expensive nested searches)

The goal in every case is the same: build a **true/false oracle** out of the application's observable behavior, then use that oracle to extract data one inference at a time.

## 2. Establishing the Oracle — Step One, Always

Before extracting anything, confirm you have a reliable true/false signal. Inject a filter you *know* is true, then one you *know* is false, and record the difference in response (status code, response length, specific text, redirect target, timing).

**Known-true injection** (append to an existing filter term, e.g. a search box feeding `(cn=INPUT)`):
```
*)(objectClass=*
```
Breakdown: `*` wildcards the existing `cn=` comparison to a trivial match, `)` closes that term, `(objectClass=*` opens a presence test for `objectClass` — every LDAP entry has an `objectClass` attribute by protocol definition, so this is unconditionally true. The trailing `)` the application appends closes it.

**Known-false injection**:
```
*)(objectClass=ThisAttributeValueDoesNotExist12345
```
Same structure, but the asserted value is deliberately nonsensical, so the presence-with-value match fails for every entry.

Submit both. Whatever distinguishes their responses — that's your oracle for every subsequent question.

## 3. Boolean-Based Extraction — Character by Character

Once you have an oracle, you extract unknown attribute values (e.g., another user's password hash, an internal attribute, a hidden `description` field) by asking the directory a yes/no question per character, using the **substring match operator**.

**Goal example**: extract the value of `attribute_to_leak` for a known entry, one character at a time.

**Step 1 — confirm the length isn't needed first** (LDAP substring matching doesn't require knowing length in advance, unlike some blind SQLi techniques — you just test character-by-character with a trailing wildcard).

**Step 2 — test the first character**:
```
*)(attribute_to_leak=a*
```
Breakdown: `*` neutralizes whatever the existing filter term was checking, `)` closes it, `(attribute_to_leak=a*` is a substring filter — "the attribute's value starts with `a`, followed by anything." If this returns true (per your oracle), the first character is `a`. If false, try `b`, `c`, etc.

**Step 3 — once the first character is confirmed, anchor it and test the second**:
```
*)(attribute_to_leak=av*
```
("Starts with `av`, followed by anything") — continue extending the known prefix and testing the next character against the full alphanumeric + symbol set until you hit a character that, when appended, the attribute no longer starts with that prefix (signal: you've reached the end of the value, confirm with a presence-without-suffix test or simply by trying every character and getting no match).

**Practical alphabet for the brute-force loop**: lowercase, uppercase, digits, and common symbol characters depending on what the attribute is likely to contain (e.g., password hashes are typically base64/hex alphabet only — narrow your character set to speed up extraction).

## 4. Why This Is Slower Than Blind SQLi, and What To Do About It

Pure linear substring extraction (testing one character at a time against ~70 possible characters) is `O(n * alphabet_size)` queries — workable for short values but painful for long ones (e.g., a 32+ character hash). Two mitigations, both standard in real engagements:

1. **Burp Intruder with a payload list = your alphabet, positioned at the character slot, and a grep-match rule on your confirmed "true" signal.** This automates exactly the loop described above without scripting — covered with a concrete Intruder configuration in file 07.
2. **Binary search isn't directly available the way it is in blind SQLi** (you can't easily ask "is character > 'm'?" with a single LDAP substring operator the way SQL's `>` lets you compare strings directly) — `>=`/`<=` in LDAP filters apply to ORDERING matching rules which are attribute-syntax-dependent and not reliably usable for arbitrary string bisection across all directory implementations. **In practice, linear alphabet iteration via Intruder is the accepted, real-world method** — don't over-engineer a binary search approach unless you've confirmed the specific attribute's matching rule supports ordered comparison.

## 5. Error-Based Blind: When Malformed Syntax Leaks Information

Some applications don't cleanly catch LDAP syntax exceptions, and a malformed filter (mismatched parentheses, for example) causes a distinguishable error (stack trace, 500 status, different error page) compared to a well-formed-but-empty-result filter. Test this distinction directly:

**Deliberately malformed** (extra unmatched closing paren):
```
*))
```
**Well-formed but empty-result**:
```
*)(uid=NonexistentUser99999
```

If these two produce different observable behavior (one throws, one doesn't), you've got an error-based oracle that's often *more* reliable than a content-based one, because exceptions are harder for developers to accidentally mask than "0 results found" text.

## 6. Time-Based Blind (Rare, But Know It Exists)

Unlike SQL (`SLEEP()`, `pg_sleep()`), the LDAP filter language has **no native delay function** — this is a meaningful difference from SQLi and SSTI you should note explicitly. Time-based blind LDAP injection, when it's possible at all, relies on making the *directory server itself* do expensive work — e.g., a deeply nested wildcard substring search across a large attribute set, or a search scoped to a huge subtree — rather than an injected sleep primitive. This is unreliable, environment-dependent, and rarely your first choice; **default to boolean or error-based oracles** and only explore timing if neither is available.

## 7. PortSwigger Academy Lab Mapping

**No PortSwigger Academy lab exists for blind LDAP injection** — consistent with the gap noted in file 01. There is no "Blind LDAP injection (boolean-based)" or "(time-based)" lab pairing the way SQLi has multiple blind labs in a clear Apprentice → Practitioner progression.

**Practice alternatives**:
- **Self-hosted OpenLDAP + minimal vulnerable search app** (same setup as file 04, section 6) — modify the app to return only a generic boolean/empty-result page instead of full search output, which turns it into a genuine blind-injection practice target. This is the most realistic way to drill the extraction loop in section 3 against real server behavior.
- **TryHackMe/HackTheBox rooms tagged LDAP injection** — check current catalogs; coverage of blind variants specifically is inconsistent across rooms, so verify a given room actually exercises blind extraction (not just auth bypass) before relying on it for this technique.

## 8. Real-World Note

Blind LDAP injection is the technique most likely to actually appear in a real corporate engagement, because most production LDAP-backed features (staff search, password reset lookups) are deliberately built to **not** dump full directory contents — they show a generic "user found" / "not found" or success/failure state, which is exactly a blind oracle. Treat "the app doesn't show me data" as the *start* of the assessment, not a dead end.
