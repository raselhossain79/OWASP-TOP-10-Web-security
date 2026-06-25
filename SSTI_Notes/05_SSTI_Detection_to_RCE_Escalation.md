# 05 — Detection-to-RCE Escalation: The Full Methodology

This file ties everything from files `01`–`04` into a single continuous workflow — the way you'd actually
run an engagement against an unknown target, start to finish, rather than as separate isolated topics.

## Phase 1 — Reconnaissance: Find Every Candidate Input

Before sending a single payload, map every point where user-controlled data might be flowing into
server-side rendered output:

- URL parameters and path segments
- Form fields and JSON body values
- HTTP headers the app might log or reflect (`User-Agent`, `X-Forwarded-For`, custom headers)
- File upload metadata (filenames, EXIF-style metadata fields)
- Any "preview," "template," "report generation," or "email notification" feature — these are
  disproportionately likely to involve template rendering of user-influenced content
- Profile fields that get echoed back into rendered pages (name, bio, comments)

**Real-world note:** "report generation" and "custom email template" features are among the highest-yield
targets for real-world SSTI in bug bounty programs, because they frequently involve exactly the anti-pattern
described in file `01` (concatenating user input into a template string) for legitimate-seeming reasons —
the developer wanted the user's custom text to be "merged" with placeholders.

## Phase 2 — Broad Detection

For each candidate input:

1. Send the universal polyglot fuzz string from file `01`:
   ```
   ${{<%[%'"}}%\
   ```
2. Observe the response for any of:
   - A server error / stack trace (best case — likely names the engine)
   - A 500-class status code that differs from the app's normal "bad input" handling
   - Garbled/partial output suggesting partial parsing occurred
3. If nothing interesting happens, don't immediately give up — test a clean math probe:
   ```
   {{7*7}}
   ```
   and
   ```
   ${7*7}
   ```
   separately, since some inputs get HTML-encoded or sanitized in ways that specifically break the
   polyglot's mixed-character soup but leave a clean, simple expression intact.

## Phase 3 — Determine Context (Plaintext vs Code)

If a math probe evaluates, determine which context you're in, since the next steps diverge:

- If your raw input appears nowhere near existing template syntax in the page (you're injecting into a
  brand-new position the developer never intended to be "template-like") → **plaintext context**, per
  file `01` section 3.1. Proceed straight to Phase 4.
- If your input is being inserted *inside* an existing `{{ }}`/`${ }`-style expression the developer wrote
  (e.g., a `greeting=data.username`-style parameter) → **code context**, per file `01` section 3.2. You
  must first confirm the break-out technique works:
  ```
  data.username}}<tag>
  ```
  before you can inject fresh statements. Confirm `<tag>` renders as live HTML before proceeding.

## Phase 4 — Identify the Engine

1. Try to provoke an engine-naming error first (file `01` section 5.1) — this is the fastest path and
   skips the rest of this phase entirely if it succeeds.
2. If errors are suppressed, run the syntax-based decision tree (file `01` section 5.2):
   - `${7*7}` only → FreeMarker-family
   - `{{7*7}}` only → Jinja2/Twig/Tornado family → disambiguate with `{{7*'7'}}`
     - `7777777` → Jinja2 or Tornado (Python-backed)
     - `49` → Twig (PHP-backed)
   - `<%= 7*7 %>` only → ERB
   - Logic-less behavior (arithmetic doesn't evaluate at all, but `{{variable}}` substitution works) →
     suspect Handlebars or another logic-less engine; pivot to documented-exploit research per file `04`
     section 6.

## Phase 5 — Engine-Specific Exploitation

Jump to the matching file:

- Jinja2 → `02_SSTI_Jinja2_Exploitation.md`, starting from the `__class__`/`__mro__`/`__subclasses__()`
  chain (section 4), or the `request.application.__globals__` pivot if `request` is exposed in context.
- Twig → `03_SSTI_Twig_Exploitation.md` — try the classic `_self.env.registerUndefinedFilterCallback`
  one-liner first (section 4); if that's blocked/removed by version, move to manual object-method
  enumeration and chaining (section 5).
- FreeMarker/Velocity/Smarty/Tornado/ERB/Handlebars → `04_SSTI_Other_Engines.md`, matching section.

## Phase 6 — Escalation Mindset When the First Attempt Fails

This is the part most write-ups skip, but it's where real engagements actually live.

### 6.1 If a known one-liner is blocked outright (not erroring, just not executing)

Suspect a **sandbox or substring blocklist**. Test:
- Does the *exact same payload, slightly reworded* (e.g., constructing `"class"` via string concatenation
  instead of typing it literally) succeed? → naive blocklist, bypassable.
- Does any dunder/reflection access at all throw a specific, named security exception (e.g., Jinja2's
  `SecurityError`)? → genuine sandbox; research version-specific escape gadgets rather than continuing
  to brute-force generic payloads.

### 6.2 If no documented one-liner exists for this object/context at all

This is the **custom-exploit mindset** from the Twig file (`03`, section 5):
1. Force an error to disclose the exact class name of any object exposed to you in the template context.
2. Enumerate that class's real public methods/properties through further deliberate errors (wrong
   argument counts, calling nonexistent methods) — PHP, Java, and Python error messages all tend to leak
   real method signatures when triggered this way.
3. Read up on what each disclosed method is *intended* to do (check public docs, decompiled/leaked source
   if available, or just reason from the method name and parameters).
4. Look for a combination of two or more legitimate methods that, chained together, achieve file
   read/write/delete or command execution — even though neither method was designed for that purpose on
   its own (the `setAvatar()` + `gdprDelete()` pattern from file `03`).

### 6.3 If you only achieve information disclosure, not RCE

Don't force an RCE narrative that isn't there. Some real-world (and lab) scenarios — like Django's
sandboxed template language — are deliberately built to prevent arbitrary code execution while still
permitting attribute traversal into objects you weren't meant to read (e.g., reaching a `settings` object
and reading `SECRET_KEY` or database credentials). Document the actual achieved impact precisely; a
disclosed secret key is itself frequently a critical-severity finding on its own (it can enable session
forgery, signed-cookie tampering, or further pivoting), without needing to also claim code execution that
wasn't actually achieved.

## Phase 7 — Confirm Impact and Move to Verified Execution

Once you have a working expression that calls into OS command execution or file I/O:

1. Run a harmless, unambiguous confirmation command first — `id`, `whoami`, or `pwd` — never jump straight
   to anything destructive or noisy.
2. Confirm the output actually appears in the HTTP response (or via an out-of-band channel if the
   injection point is blind — e.g., trigger a DNS lookup or HTTP callback to a server you control using
   the same execution primitive, substituting `id` for something like `curl http://your-collaborator-domain/`).
3. Only after confirming clean, verifiable execution should you escalate further (reading specific files,
   establishing a reverse shell, etc.), and only within the scope and rules of engagement you've been
   given.

## Phase 8 — Automate Confirmation Going Forward

Once you understand this manual methodology, `tplmap` (covered fully in
`07_tplmap_Automation.md`) automates Phases 2–5 for known engines, and is the appropriate tool to run
early on subsequent inputs/targets once you've validated the manual approach works against at least one
input — exactly the same relationship `sqlmap` has to manual SQL injection technique.
