# LDAP Filter Bypass — Evading Sanitization & Character Blocking

**Prerequisite**: file `02_LDAP_Filter_Syntax_Reference.md`. This file assumes you already know what `* ( ) \` and NUL each do structurally in a filter (file 02, sections 1–5) — here we cover what happens when an application tries to **stop** you from injecting them, and how to test whether that defense actually holds.

Files `04_Authentication_Bypass.md`, `05_Blind_LDAP_Injection.md`, and `06_Data_Extraction_Search_Filters.md` all assume the five special characters reach the filter unmodified. Read this file first whenever your initial Step-0 test (file 07, section 1) shows that raw `* ( ) \` characters are being altered, stripped, or blocked — it walks through how to confirm exactly what kind of filtering is in place and which evasion techniques are realistic against each kind.

## 1. Identify the Sanitization Type Before Choosing an Evasion

Don't guess — applications block/sanitize LDAP metacharacters in fundamentally different ways, and the right evasion depends entirely on which one you're facing. Submit each of `* ( ) \` and a NUL byte (`%00`) individually, one field at a time, and classify the response into one of these four buckets:

| Behavior observed | What's likely happening | Section to use |
|---|---|---|
| The character is silently removed from the reflected value/behavior (e.g., `a*b` becomes `ab`) | **Blacklist stripping** — the app deletes specific characters | Section 2 |
| The character causes a generic "invalid input" rejection (400, validation error, form re-displayed with an error) | **Blacklist rejection / WAF-style filtering** — the app rejects the whole request if a blocked character is present | Section 3 |
| The character appears in output as `\2a`, `\28`, `\29`, `\5c`, or similarly escaped | **Proper RFC 4515 escaping is in place** — this is correctly implemented; evasion is much harder and you should shift focus to section 6 | Section 6 |
| Only a subset of input is allowed at all (e.g., regex `^[a-zA-Z0-9]+$` enforced) | **Whitelist/allowlist validation** | Section 5 (usually not bypassable — explained why) |

This classification step is the actual skill here — most testers jump straight to "try double encoding" without first confirming which defense they're up against, and waste time on techniques that can't possibly work against the defense actually present.

## 2. Bypassing Blacklist Stripping (Character Removal)

If a specific character is deleted rather than rejected, the classic evasion is to **supply it twice, expecting the filter to remove only one layer**, or to **wrap your real payload inside decoy instances of the blocked character** so that after stripping, what remains reassembles into your intended payload.

**Example**: suppose the app strips every literal `)` character once (a naive `input.replace(")", "")` rather than a loop that strips repeatedly).

Intended payload: `*)(uid=*`

Double-up technique: `*))(uid=*`

Walk through it: the naive single-pass `.replace(")", "")` removes the first `)` it finds and stops (depending on implementation — some `replace` calls remove *all* occurrences in one pass, which defeats this immediately; **this technique only works against a single-removal or single-pass-but-non-global implementation**, which you confirm empirically in section 1's Step-0 test by submitting `))` and checking whether both, one, or neither survive). If only one `)` is stripped, `*))(uid=*` becomes `*)(uid=*` after stripping — your original intended payload, intact.

**Important honesty note for your engagement reports and your own learning**: most real-world stripping implementations use a global replace (`re.sub`, `str.replace` in languages where it removes all instances, or a loop until no instances remain) specifically *because* developers learned from exactly this bypass being well-documented. **Test this empirically every time — do not assume it works.** If `))` submitted comes back as a clean empty string (both stripped), this technique is dead and you should move to section 4 (alternate character encodings) or section 6 (confirm proper escaping and pivot to a different field/feature).

## 3. Bypassing Whole-Request Rejection (WAF-Style Blacklists)

If submitting a blocked character causes the *entire request* to be rejected (rather than just that character being silently removed), you're likely facing a pattern-matching filter — either application-level input validation or a WAF/security middleware rule. Three evasion angles, in order of how often they actually work in practice:

**3a. Alternate encoding of the same byte.** Many naive filters check the literal raw character in the *decoded* parameter but the web server/framework double-decodes URL encoding, or the filter checks before a later decoding step occurs. Try URL-encoding the character: `%28` for `(`, `%29` for `)`, `%2a` for `*`, `%5c` for `\`. If the filter inspects the raw query string before the framework decodes percent-encoding, but the LDAP query is built *after* decoding, your encoded character sails through the filter and arrives at the LDAP layer as the live metacharacter.

**3b. Double URL-encoding.** If single encoding is also caught (because the filter normalizes/decodes once before checking), try double-encoding: `%252a` decodes once to `%2a` (which might pass a filter looking for the literal `*` or `%2a` pattern) and then decodes a second time at a deeper layer to `*`. This relies on there being two distinct decoding stages in the request pipeline (e.g., a reverse proxy/WAF decodes once, the application framework decodes again) — confirm this is architecturally plausible for your target before spending time here; it's a real, documented technique but environment-dependent.

**3c. Unicode/overlong encoding variants.** Some older or poorly-configured stacks accept overlong UTF-8 encodings or fullwidth Unicode lookalikes (e.g., U+FF0A FULLWIDTH ASTERISK `＊` instead of ASCII `*`) that get normalized to the ASCII equivalent at some point in the processing pipeline but aren't caught by a filter that only checks for the literal ASCII byte. This is increasingly rare against modern stacks (most frameworks normalize Unicode before validation now) but worth a quick test — it costs one request to rule in or out.

**Reality check**: WAF-style rejection on a well-maintained target is often genuinely not bypassable through encoding tricks alone, especially if the WAF normalizes before pattern-matching. If 3a–3c all fail, that's a legitimate, correct finding to write up as "input validation appears effective against direct metacharacter injection" rather than something to keep brute-forcing — knowing when a defense actually holds is as valuable a skill as knowing how to break one.

## 4. The NUL Byte Bypass — Mechanism and Honest Limitations

File 02 flagged that a NUL byte (`\00`, sent as `%00` in a URL or raw `0x00` in a POST body) can, in some LDAP client bindings, truncate the filter string at the native/unmanaged layer even though the managed application code still believes the full string (including anything after the NUL) is present. This matters for bypass specifically when an application's *validation* check happens in managed code scanning the full string for blocked characters, but the *actual LDAP query construction* happens via a native call that stops reading at the first NUL.

**Concretely**: if a validator checks "does this input contain `)`?" by scanning the whole managed string, and your input is `goodvalue\x00)(uid=*`, the validator sees the `)` later in the string and may either pass it (if its blocklist check is satisfied with what's *before* the NUL, depending on how it scans) or — more usefully — if the validator itself also truncates at NUL when reading the string (common in C-derived string-handling assumptions leaking into managed wrappers), it validates only `goodvalue` and never inspects the malicious suffix at all, while the LDAP layer downstream processes the full string up to its own native truncation point.

**Honest limitation**: this is binding- and platform-specific (most reliably discussed in the context of older .NET `System.DirectoryServices`/ADSI-backed applications) and is not a universal technique against modern `ldap3` (Python), Java JNDI, or current .NET `System.DirectoryServices.Protocols` implementations, which generally handle embedded NULs more consistently than the legacy ADSI path. **Test it, don't assume it** — submit a NUL byte alone first (Step 0, file 07) and observe whether the response differs at all from a normal request; if there's zero observable effect, this avenue is closed for that target and you should say so plainly rather than implying broader applicability than you've verified.

## 5. Why Allowlist Validation Usually Can't Be Bypassed (And What To Do Instead)

If the application enforces a strict allowlist (e.g., a regex like `^[a-zA-Z0-9 ]{1,50}$` applied server-side, rejecting anything outside that character set), **there is generally no character-encoding trick that defeats this**, because the check isn't pattern-matching for *known-bad* characters (which encoding can disguise) — it's only *permitting known-good* characters, and an encoded special character still decodes to something outside the allowed set before it ever reaches the LDAP layer, assuming the allowlist check happens after decoding (which is the correct, common implementation).

What's actually worth testing here instead of forcing an encoding bypass:
- **Check every other input field independently** — allowlist validation is frequently applied inconsistently across a multi-field form (e.g., username field is strictly validated, but a "department" dropdown-turned-free-text field, or a hidden field, is not).
- **Check for validation that exists client-side only** — if the allowlist regex lives in JavaScript and the server doesn't re-validate, submitting the request directly (via Burp Repeater, bypassing the browser/JS entirely) defeats it completely. This is the single most common real-world "bypass" of allowlist validation — not a clever encoding trick, just skipping the browser.
- **Report it accurately**: if server-side allowlist validation is correctly implemented and consistently applied, that is a legitimately strong control, and your finding should reflect that rather than forcing a marginal bypass narrative to justify the time spent.

## 6. Confirming Proper RFC 4515 Escaping (and What's Left to Test When It's Solid)

If you observe `* ( ) \` being correctly transformed to `\2a \28 \29 \5c` in reflected output or behavior, the application is implementing the standard defense correctly for that field. At that point:
- **Don't keep hammering the same field with encoding tricks** — properly implemented escaping (using a real LDAP library's filter-escaping function rather than hand-rolled string replacement) is not bypassable through any technique in this file.
- **Pivot to checking every other field that touches the same LDAP query** — escaping is sometimes applied to the primary search term but forgotten on a secondary parameter (a hidden sort field, a filter-scope dropdown value, an API parameter that feeds the same backend search but isn't part of the visible form).
- **Check whether escaping is applied consistently across the whole application**, not just the field you first tested — a staff-search feature might escape correctly while an unrelated password-reset lookup, built by a different developer or at a different time, does not.

## 7. PortSwigger Academy Lab Mapping

**No PortSwigger Academy lab exists for LDAP filter sanitization bypass specifically** — consistent with the gap noted throughout this series (file 01, section 6). This is a natural extension of the general lab-coverage gap, since even the base LDAP injection technique has no dedicated lab track, let alone a bypass-the-defenses variant.

**Practice alternatives**:
- **Self-hosted OpenLDAP lab** (setup in file 07, section 4) — modify your practice Flask/Python app to add a deliberately naive sanitization layer (e.g., a single-pass `.replace(")", "")`, or a regex-based blocklist) in front of the vulnerable filter-construction code, then test sections 2–4 of this file against your own implementation. This is the only realistic way to validate bypass techniques against ground truth, since you control both the defense and the oracle.
- **OWASP WebGoat → LDAP Injection lesson** — does not currently include a dedicated sanitization-bypass step distinct from the base injection exercise; useful for the underlying technique but not this specific evasion angle.

## 8. Real-World Note

In real engagements, partial/naive sanitization is far more common than either "completely open" or "perfectly escaped" — most LDAP-backed features you'll encounter have *some* input handling, usually added reactively after a previous finding or a generic security-awareness pass, rather than a deliberate, complete RFC 4515-compliant escaping implementation. That means **section 1's classification step is usually the highest-value five minutes of testing this vulnerability class** — identifying exactly which partial defense is in place tells you immediately which of sections 2–4 is worth pursuing, rather than spraying every encoding trick at every field.
