# 04 — Adapting Known Techniques to Unknown/Custom Scenarios

Every lab you've completed teaches a pattern that was deliberately built to be
recognizable once you know what to look for. Real targets frequently present
something that doesn't cleanly match SQLi, XSS, SSRF, or any single category you've
studied — a custom serialization format, a proprietary auth scheme, an internal API
with no public documentation anywhere. This file covers how to approach that
situation methodically instead of giving up or guessing randomly.

## Start from primitives, not from vulnerability names

When a target's behavior doesn't match a named vulnerability class you know, stop
trying to name it and instead ask the same primitive-level questions from file `01`:

- What exact input am I controlling here, character by character?
- Where does that input end up — is it concatenated into a query, a command, a file
  path, a template, a deserialization stream, a log line, an HTTP request the server
  makes elsewhere?
- What's the *destination context* — and does that destination context have its own
  syntax/escaping rules I could break out of?

A huge fraction of "novel" vulnerabilities are just a known primitive (string
concatenation into an interpreter) applied to an interpreter you haven't specifically
studied a named CVE for. The mechanism-first approach from every series in this
library — understanding *why* a payload works, not memorizing that it works — is
exactly what transfers here.

## Systematic fuzzing methodology

Fuzzing on a real target needs structure or it just generates noise and rate-limit
bans. A practical sequence:

1. **Establish a baseline.** Send the request unmodified, multiple times, and record
   response time, status code, response length, and any reflected values. You cannot
   detect an anomaly without knowing what "normal" looks like for *this specific
   endpoint* — baselines vary wildly between apps.
2. **Single-character probes first.** Before throwing a payload list at a parameter,
   send individual special characters (`'`, `"`, `<`, `>`, `{`, `}`, `;`, `|`, `` ` ``,
   `../`, `%00`, a literal newline) one at a time and diff each response against the
   baseline. A changed status code, a changed response length, a new error message,
   or a changed response time on any single character narrows down the destination
   context fast — an unescaped `'` causing a 500 with a SQL-flavored error message
   tells you more, faster, than a generic SQLi payload list would.
3. **Differential fuzzing across parameters.** If an endpoint takes multiple
   parameters, fuzz one at a time while holding the others constant — simultaneous
   fuzzing of multiple parameters makes it impossible to attribute which input caused
   which behavior change.
4. **Targeted payload lists only after step 2 narrows the context.** Once a single
   character suggests SQL, template, command, or path context, *then* bring in the
   context-specific technique from the relevant series in this library (the SQLi
   series' boolean/time-based detection, the SSTI series' polyglot detection string,
   etc.) rather than blind-firing every payload type at every parameter.
5. **Automate the comparison, not the thinking.** Tools (Burp Intruder with
   Grep-Match/Grep-Extract, or a custom script) are for *running* the fuzzing pass and
   surfacing the diffs — they are not for deciding what the diff means. That
   interpretation step is the actual skill.

## Behavioral inference without source code

Black-box testing means you're inferring server-side logic purely from observable
behavior. Useful inference techniques:

- **Timing differences.** A request that takes measurably longer when a username
  exists vs. doesn't (even with an identical "invalid credentials" message) reveals a
  user-enumeration oracle even though the response *text* gives nothing away. This
  same timing-oracle thinking generalizes to blind SQLi, blind SSRF (does the app
  hang while it tries to connect to an internal-only port?), and blind SSTI.
  
- **Error message archaeology.** Even "generic" error pages often leak a stack trace
  fragment, a framework name, a file path, or a database error class under specific
  malformed input, even when well-formed malformed input produces a clean generic
  error. Try input that's malformed in *unusual* ways (wrong content-type with valid
  JSON body, deeply nested objects, unexpected null vs. empty string) — edge cases in
  the error-handling code itself are a separate, frequently-untested code path from
  the main error-handling logic.

- **Response structure consistency.** Compare the *shape* (not just content) of
  responses across different inputs — an API that returns `{"error": "..."}`  for
  most invalid input but `{"error": "...", "debug": {...}}` for one specific
  malformed case reveals a conditional debug/verbose path you can try to trigger
  deliberately elsewhere.

- **Indirect confirmation for blind vulnerabilities.** When you suspect a primitive
  but get no direct response evidence (blind SSRF, blind XXE, blind command
  injection), use out-of-band channels — a request to a domain you control (via
  Burp Collaborator or a self-hosted equivalent), DNS lookups, or timing delays
  (`sleep`-equivalent commands/queries) as your confirmation signal instead of
  response content.

## When nothing matches anything — the fallback process

If after the above you still can't classify what you're looking at:

1. **Re-read the application's own client-side code** (JS, mobile app decompilation
   if in scope) for the matching server-side handler name or library identifiers —
   developers leave naming clues even when documentation doesn't exist.
2. **Search for the specific error strings or response headers verbatim** — a
   distinctive error message or an unusual header often identifies the exact
   framework/library version, which lets you go research *that specific library's*
   known behavior even if there's no public CVE for this exact app.
3. **Treat it as a custom protocol and apply the primitive questions from the top of
   this file anyway.** Even fully custom binary protocols or proprietary
   serialization formats are still, underneath, taking attacker input and doing
   *something* with it server-side — the "what context does this land in" question
   still applies, it just takes more probing to map the format itself first (length-
   prefixed fields, delimiter characters, checksum/signature fields you may be able
   to recompute once you understand the algorithm).

## Tying this back to chaining

The reason this methodology matters for a *chaining-focused* series specifically:
unknown/custom features are disproportionately likely to be the "Bug B" half of a
chain, precisely because they're the parts of the application too obscure or too
custom for automated scanners and casual testers to have already found and fixed the
obvious issues in. A known bug class on a heavily-tested public endpoint is likely
already patched or well-defended; an unknown, custom, rarely-tested internal feature
is exactly where the *missing* half of a chain tends to survive.
