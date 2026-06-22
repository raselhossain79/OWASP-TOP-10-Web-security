# Filter and WAF Bypass Techniques

## 1. What's Being Filtered, and Why

Applications and WAFs defend against command injection using some combination of:
- **Character blacklists** — blocking specific characters like `;`, `|`, `&`, backticks, `$`.
- **Keyword blacklists** — blocking command names like `whoami`, `cat`, `nc`, `curl`.
- **Space stripping/blocking** — many naive filters assume removing or blocking literal spaces prevents multi-word commands.
- **Pattern-matching WAF rules** (e.g., ModSecurity OWASP CRS) — regex-based detection of common payload shapes.

None of these address the root cause (shell invocation with untrusted input) — they're surface-level mitigations, which is exactly why bypasses are so often possible. This is also why your report language should always tie back to "the underlying root cause is unaddressed" rather than treating a successful bypass as a one-off curiosity.

## 2. Bypassing Character Blacklists

### If `;` Is Blocked — Use Alternative Operators

Try, in order: `|`, `&&`, `||`, `&`, or a literal newline character (`%0a` URL-encoded). Each was already explained mechanically in earlier files — the bypass technique here is simply **operator substitution**: a filter that blocks one specific separator character is trivially defeated by using a functionally equivalent one it didn't anticipate.

### If Backticks Are Blocked — Use `$()`

Since both achieve command substitution on Linux, blocking one but not the other is a common, incomplete filter. Conversely, if `$()` specifically is blocked (e.g., a filter targeting the `$` character broadly, since `$` is also used for variable expansion and is a common blacklist target), fall back to backticks.

### If `$` Is Blocked Entirely — Use Variable-Free Substitution

Payload: `` ; `whoami` `` (no `$` character involved at all, since backticks alone perform substitution).

## 3. Bypassing Space Filtering/Blocking

This is one of the most common naive defenses, and one of the most reliably bypassable.

### Technique: `${IFS}` (Internal Field Separator)

Payload: `;cat${IFS}/etc/passwd`

**Breakdown:**
- `${IFS}` — expands to the shell's Internal Field Separator variable, whose default value is a space (and also includes tab/newline). The shell substitutes this variable's value *before* parsing the command, so `cat${IFS}/etc/passwd` becomes, after expansion, `cat /etc/passwd` — a literal space is produced, but the actual character you typed in your payload was never a literal space, so any filter doing a simple substring check for the space character (`" "`) never sees one.
- This bypasses filters that block the literal space character but don't account for shell variable expansion happening before execution.

### Technique: Tab Character

Payload: `;cat%09/etc/passwd` (URL-encoded tab, `%09`)

**Breakdown:**
- `%09` decodes to a literal horizontal tab character. Many shells treat tabs as a valid word-separator equivalent to spaces. If a filter specifically blocks the space character (` `, `%20`) but doesn't normalize/block tabs, this passes straight through.

### Technique: Brace Expansion (Bash-Specific)

Payload: `;{cat,/etc/passwd}`

**Breakdown:**
- Bash brace expansion `{a,b,c}` expands into multiple separate words passed as arguments — `{cat,/etc/passwd}` expands to two separate tokens, `cat` and `/etc/passwd`, functioning as `cat /etc/passwd` without ever using a literal space character in your payload at all. This only works on shells with brace-expansion support (Bash specifically; not plain POSIX `sh` or `dash`), so confirm the underlying shell first if this fails unexpectedly.

## 4. Bypassing Command/Keyword Blacklists

### Technique: Wildcard/Glob Insertion

Payload: `;w?oami` or `;wh*ami`

**Breakdown:**
- `?` matches any single character, `*` matches any sequence of characters, in standard shell globbing. If exactly one file in the current directory matches the glob pattern after expansion (which the shell resolves before execution), it gets substituted in as the literal command name. This is fragile (depends on filesystem contents matching your glob uniquely) but defeats simple exact-string keyword matching like a regex looking for the literal substring `whoami`.

### Technique: Character Insertion/Splitting With Quotes

Payload: `;who'am'i` or `;who"am"i`

**Breakdown:**
- Adjacent quoted empty-content segments are concatenated by the shell into a single token before execution — `who'am'i` is parsed as the single word `whoami` (the quotes themselves contribute no characters, they just don't break word boundaries). A keyword filter doing exact substring matching for `whoami` never matches this literal payload text, but the shell still executes the intended command.

### Technique: Variable Concatenation

Payload: `;a=wh;b=oami;$a$b`

**Breakdown:**
- `a=wh` and `b=oami` assign two shell variables.
- `$a$b` expands to the concatenation of both variables' values — `wh` + `oami` = `whoami` — and the shell then attempts to execute this concatenated string as a command. This fully avoids the literal substring `whoami` appearing anywhere in your payload.

### Technique: Base64 Encoding the Full Payload

Payload: `` ;echo d2hvYW1p | base64 -d | sh ``

**Breakdown:**
- `d2hvYW1p` is the Base64 encoding of the string `whoami`.
- `echo d2hvYW1p` prints the encoded string.
- `| base64 -d` pipes that output into the `base64` utility with the `-d` ("decode") flag, converting it back to plaintext `whoami`.
- `| sh` pipes the decoded plaintext into a new shell instance, which then executes it as a command.
- This defeats any filter or WAF performing keyword matching on the literal command name, since the actual sensitive string never appears in cleartext in the transmitted request — only its encoded form does.

## 5. Windows-Specific Bypass Techniques

### Technique: Caret (`^`) Escape Character Insertion

Payload: `& w^hoami`

**Breakdown:**
- In `cmd.exe`, `^` is an escape character that, when placed before most characters, is simply consumed/ignored without altering the following character's meaning in many contexts — `w^hoami` is interpreted as `whoami` after `cmd.exe`'s parsing. A keyword filter checking for the literal substring `whoami` doesn't match `w^hoami`, but `cmd.exe` still executes it correctly.

### Technique: Environment Variable Substring Extraction

Payload: `%PROGRAMFILES:~10,-5%` style substring tricks (advanced, environment-dependent)

**Breakdown:**
- Windows batch syntax `%VAR:~start,length%` extracts a substring from an environment variable's value. By choosing variables and offsets carefully, attackers can construct arbitrary command strings character-by-character without ever typing the sensitive keyword directly. This is more fragile/environment-specific (depends on exact variable values on the target) and primarily relevant for advanced WAF evasion in CTF-style or heavily filtered Windows scenarios — mentioned here for completeness, but note it requires per-target customization, unlike the more portable Linux techniques above.

## 6. Bypassing WAF Pattern-Matching Rules (e.g., ModSecurity CRS)

- **Case manipulation:** Some weak custom WAF rules are case-sensitive; trying `WhoAmI` or mixed case can occasionally bypass naive regex rules (rare on well-configured CRS, but seen in custom/homegrown filters).
- **Comment insertion (Bash):** Payload `;who$()ami` — an empty command substitution `$()` inserted mid-word expands to nothing, so the shell still sees `whoami` after expansion, while the literal payload text contains an injected `$()` that may break a naive regex looking for the contiguous substring.
- **Encoding the entire request parameter:** URL-double-encoding (`%2570` etc.) can sometimes pass through a WAF inspecting only single-decoded input while the application's own deeper decoding layer still resolves it correctly.

## 7. PortSwigger Lab Mapping

The core OS Command Injection topic on PortSwigger Academy does not include a dedicated "WAF bypass" lab (unlike SQL injection, which has several dedicated filter-bypass labs) — these labs use straightforward unfiltered injection points by design, to teach the underlying mechanism clearly. The techniques in this file are primarily **real-world/CTF-applicable** rather than mapped to a specific Academy lab. If you want hands-on practice for these specific bypasses, suitable platforms include OverTheWire (Bandit/Natas-style filter challenges), HackTheBox machines tagged with command injection, and DVWA's command injection module at "High" security level, which deliberately implements blacklist-style filtering you can practice bypassing using the techniques above.

## 8. Real-World Notes

- Blacklist-based filters in production are almost always incomplete — testers should systematically enumerate operator variants (`;`, `|`, `&&`, `||`, `&`, newline) and substitution variants (backtick vs `$()`) rather than giving up after the first blocked attempt.
- WAFs (ModSecurity, Cloudflare, AWS WAF) frequently block the *most common* textbook payloads (`; cat /etc/passwd`, `; whoami`) outright via signature matching, but allow encoded/obfuscated variants through — this is precisely why automation tools like commix (next file) maintain large libraries of bypass "tamper scripts," since manually trying every combination is impractical at scale.
- Always test **each filtered character individually** to map out exactly what's blocked rather than assuming an entire payload failed for one specific reason — a payload can fail due to multiple independent filtering rules stacked together.

## 9. Common Mistakes

- Giving up after one or two blocked attempts and concluding "the input is properly sanitized," when in reality only the most obvious payload pattern was blocked.
- Using `${IFS}` bypass on a target running `dash` (Debian's default `/bin/sh`) without confirming it behaves identically to `bash` — minor POSIX shell differences can occasionally affect more advanced obfuscation techniques (brace expansion in particular is Bash-only).
- Forgetting that successful WAF bypass at the network layer doesn't matter if the application itself (not the WAF) is also independently filtering — both layers need to be tested and documented separately.

## 10. Report-Writing Notes

- When a WAF bypass was required, document **both** the original blocked payload and the final successful bypass payload — this demonstrates due diligence and gives the client's security team concrete data on what their current rules do and don't catch.
- Explicitly recommend that remediation target the **application layer root cause** (avoid shell invocation, or strict allowlist validation) rather than "add this specific pattern to the WAF block list" — WAF-only fixes are a stopgap, not a resolution, and a competent reviewing engineer will expect this distinction to be made.

---
**Previous file:** `04_OutOfBand_Command_Injection.md`
**Next file:** `06_Commix_Automation.md`
