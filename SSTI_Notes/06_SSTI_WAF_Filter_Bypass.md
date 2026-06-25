# 06 — SSTI WAF / Filter Bypass Techniques

This file assumes you've already worked through files `01`–`05` and have a working manual exploitation
chain for your target engine. It covers what happens when that chain gets blocked by a Web Application
Firewall (WAF) or an application-level input filter, why it gets blocked, and how to vary the payload so
it still does exactly the same thing while no longer matching the detection logic.

## 1. How WAFs and Filters Actually Detect SSTI

Before bypassing anything, understand what's actually being checked, since every bypass technique below
is a direct answer to one of these detection methods.

### 1.1 Signature / regex matching on delimiters

The cheapest and most common form of detection: a regex looking for known template delimiter sequences
appearing in user input — `{{`, `}}`, `${`, `<%`, `[%`, `<#`. Many WAF rulesets (including generic
injection-pattern rules in widely deployed commercial and open-source rule sets) flag any of these
sequences in a parameter value, because legitimate user input essentially never contains them.

**Why this catches naive payloads:** the canonical detection polyglot from file `01`
(`${{<%[%'"}}%\`) is now itself a well-known indicator of compromise — it has been published in enough
research and tooling that it's frequently a literal signature in WAF rule sets, not just a generic
pattern. Sending it verbatim against a monitored target is more likely to get *you* blocked/flagged than
to usefully fingerprint the engine.

### 1.2 Keyword / substring blocklists

A step up from raw delimiter matching: the filter also blocks specific dangerous substrings commonly seen
in exploitation payloads — `class`, `subclasses`, `mro`, `globals`, `builtins`, `import`, `exec`,
`system`, `popen`, `Runtime`, `getRuntime`, double underscores (`__`), and similar. These are often
checked **in addition to** delimiter matching, specifically to catch payloads that smuggle past
custom/incomplete delimiter filtering.

### 1.3 Character-class / structural blocklists

Some filters don't block specific words at all — they block *characters* that are disproportionately
used in exploitation syntax but rare in normal input: `.` (dot, used for attribute access), `[`/`]`
(brackets, used for subscript access and indexing), `(`/`)` (parentheses, used for any function/method
call), and backslash. This is more disruptive to exploitation than keyword blocking, because it doesn't
just block *one path* to an attribute — it blocks the *syntax category* of attribute access itself.

### 1.4 Anomaly / statistical detection

Rather than matching specific strings, some WAFs (and custom anomaly-scoring middleware) flag input based
on the **density of special characters** relative to alphanumeric characters, on the theory that
legitimate names, comments, and form fields rarely look like `${{<%[%'"}}%\`. This is a behavioral
signal, not a signature — meaning bypassing it requires reducing the special-character density of your
payload, not just rewording specific blocked words.

### 1.5 Behavioral / response-based detection

The most sophisticated detection doesn't inspect the request at all — it inspects whether a math
expression like `{{7*7}}` actually got evaluated in the *response* (looking for `49` appearing where the
raw payload was submitted). This is harder to evade with payload obfuscation alone, since it's detecting
the *effect*, not the *syntax* — the practical answer is to avoid using literal, well-known detection
probes during the recon phase against monitored targets, and instead use less conspicuous confirmation
values.

## 2. Universal Bypass Strategies (Apply Across All Engines)

### 2.1 Don't use the published canonical polyglot verbatim

Instead of sending the exact published string from file `01`, build a **custom, shorter, targeted
polyglot** once you already have a reasonable guess at the backend's language stack (from response
headers, cookie names, error pages, job postings, or technology fingerprinting tools). For example, if
you already suspect a Python/Flask or PHP/Symfony stack from other recon, there's no reason to include
ERB's `<%` or Template Toolkit's `[%` fragments at all:

```
{{1*1}}
```
- This is deliberately reduced to *only* the `{{ }}` fragment relevant to Jinja2/Twig/Tornado, with `1*1`
  instead of `7*7`.
- Why `1*1` instead of `7*7`: `49` is the single most commonly cited "proof of SSTI" value in every
  public write-up and automated scanner signature; `1*1` evaluating to `1` is a far less distinctive,
  lower-signal result that's still unambiguous proof of evaluation (a literal `1` appearing where
  `{{1*1}}` was submitted cannot be explained by anything other than expression evaluation), while being
  much less likely to match a response-based signature specifically trained on `49`.

### 2.2 Pad with whitespace inside delimiters

Template engines almost universally ignore whitespace, tabs, and newlines between tokens inside an
expression block. A naive signature anchored to an *exact* substring like `{{7*7}}` (no spaces) can be
defeated trivially:

```
{{
7*7
}}
```
- The newlines between `{{`, `7*7`, and `}}` are functionally invisible to the parser — Jinja2, Twig, and
  Tornado all tokenize past whitespace/newlines the same way they would tokenize past single spaces.
- A regex like `\{\{7\*7\}\}` (anchored to the literal substring with no whitespace) fails to match this
  variant, while a properly engineered signature using `\{\{\s*7\s*\*\s*7\s*\}\}` would still catch it —
  this distinction matters because many real-world deployed rules are written exactly as naively as the
  first example, not the second.

### 2.3 Split the attack across multiple statements

Instead of one dense, single-request payload that matches a known "complete exploit" signature, build the
same result across multiple `{% set %}` assignments (Jinja2/Tornado) or multiple `{% set %}` Twig
statements, each individually looking unremarkable:

```
{% set a = ''.__class__ %}
{% set b = a.__mro__[1] %}
{% set c = b.__subclasses__() %}
{{ c[396]('id', shell=True, stdout=-1).communicate() }}
```

- Each line in isolation is a much weaker signal than the single-line chained version from file `02`
  section 4.1 — a signature looking for the *entire* `''.__class__.__mro__[1].__subclasses__()` substring
  as one continuous string will not match across `a`, `b`, `c` being separately assigned and later
  referenced.
- This also works across **separate HTTP requests** if the application maintains template state between
  renders (e.g., a multi-step "edit template, then preview" admin workflow) — sending the assignment in
  one request and the trigger in a later request defeats any WAF rule that only inspects a single request
  in isolation rather than correlating a session's full history.

### 2.4 Obfuscate numeric literals used for indices

Public write-ups frequently cite exact subclass indices (e.g., `[396]` for `subprocess.Popen` on a
specific Python version). If a filter has been specifically hardened against a known published payload
(including its exact index), express the same index as an equivalent arithmetic expression instead of a
literal:

```
[19*20+16]
```
- `19*20+16` evaluates to `396` — identical numeric result, but the literal substring `396` never appears
  in your raw request, defeating any rule written against that specific public write-up's exact payload.

## 3. Jinja2-Specific Bypass Techniques

### 3.1 Subscript notation instead of dot notation

Jinja2's `Environment` implements attribute resolution so that `foo['bar']` and `foo.bar` are
**interchangeable** — Jinja2 internally tries `obj[name]` first (via `__getitem__`) and falls back to
`getattr(obj, name)` if that fails. This means any blocklist that specifically pattern-matches dot-style
attribute access (e.g., a regex anchored on `\.__\w+__`) can be bypassed by rewriting the exact same
attribute chain using bracket/subscript syntax instead:

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
becomes
```
{{ ''['__class__']['__mro__'][1]['__subclasses__']() }}
```
- Every `.attr` has been mechanically rewritten as `['attr']`.
- The final result and execution path is **identical** — this is purely a syntax substitution Jinja2
  itself treats as equivalent, not a different technique.
- This specifically defeats filters that block the literal dot character or that pattern-match
  `\.__class__` style sequences but don't separately account for bracket-based access to the same names.

### 3.2 The `|attr()` filter — when both `.` and `[]` are blocked

Jinja2 ships a built-in filter, `attr`, whose sole purpose is attribute lookup by string name — meaning it
provides a *third* syntactic path to the same attribute access, useful when a filter blocks both `.` and
`[`/`]`:

```
{{ ''|attr('__class__')|attr('__mro__') }}
```
- `''|attr('__class__')` — the `|` pipe applies the `attr` filter to the empty string, passing
  `'__class__'` as the attribute name to look up. Functionally identical to `''.__class__`, but the
  actual character sequence `.` never appears, and neither does `[`/`]`.
- Chaining `|attr()` repeatedly walks the same object graph from file `02`, one hop at a time, using only
  pipe characters and function-call parentheses — useful against filters that specifically block `.` and
  `[`/`]` but don't think to block `|attr(`.

### 3.3 Hex-escaping blocked substrings inside string literals

Jinja2's string-literal lexer supports backslash hex-escape sequences (`\xNN`), meaning a blocked literal
substring like `__class__` or `__globals__` can be written so that the substring **never appears in the
raw request at all**, while still evaluating to the exact same string once Jinja2 parses the literal:

```
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}
```
- `\x5f` is the hex byte value for the underscore character (`_`).
- `'\x5f\x5fclass\x5f\x5f'` is parsed by Jinja2's string lexer into the literal Python string
  `'__class__'` at evaluation time — but the raw bytes sent over the wire spell `\x5f\x5fclass\x5f\x5f`,
  not `__class__`.
- This defeats any blocklist matching the literal substring `__class__` (or even just the double
  underscore `__` on its own), because that substring is never present in transit — it only comes into
  existence *after* the engine's own string-literal parser decodes the escape sequence, which happens
  after the WAF/filter has already inspected (and passed) the request.
- This technique composes directly with section 3.2 — combine `|attr()` with hex-escaped attribute names
  to defeat filters blocking `.`, `[`/`]`, **and** the literal dunder substrings simultaneously.

### 3.4 String concatenation to rebuild blocked substrings dynamically

When even the hex-escape trick is blocked (some filters normalize/decode common escape patterns before
matching), build the target string at *runtime* from smaller, individually-unremarkable fragments using
Jinja2's `~` concatenation operator or the `|join` filter:

```
{{ ('_'*2 + 'class' + '_'*2) }}
```
- `'_'*2` — Jinja2 supports Python's string-repeat operator, producing `'__'` from a single
  non-suspicious underscore character repeated twice.
- `+ 'class' +` — plain string concatenation joining the fragments.
- The full expression evaluates to `'__class__'` at runtime, but no contiguous substring in the raw
  request spells out `__class__`, `class` is the only recognizable fragment, and it appears with no
  surrounding underscores to trigger a `__\w+__` pattern.
- For values spread across multiple input points (URL parameters, headers, cookies), Jinja2's `|join`
  filter can recombine a list of separately-submitted fragments into the final target string at template
  evaluation time — meaning no single inspected input location ever contains the complete blocked
  substring, only an isolated fragment of it.

### 3.5 Smuggling fragments through `request.args`

If `request` is exposed in your template context (common in Flask apps using
`render_template_string()`), you can retrieve attacker-controlled strings indirectly through
`request.args` (the query string) rather than typing them directly into the primary injection point:

```
{{ ''|attr(request.args.a) }}
```
with a separate query parameter `?a=__class__` (or `?a=\x5f\x5fclass\x5f\x5f` for extra obfuscation)
- The actual blocked substring/attribute name now lives in a *different* parameter (`a`) than the one the
  filter is actively inspecting for template syntax, splitting your payload's "dangerous" content across
  two separate, individually-unremarkable-looking request locations.

## 4. Twig-Specific Bypass Techniques

### 4.1 String concatenation via the `~` operator

Twig's dedicated string concatenation operator is `~` (distinct from PHP's own `.` concatenation
operator, since Twig has its own expression grammar). Use it the same way as Jinja2's `+`/`*` tricks in
section 3.4, to avoid a literal blocked substring appearing intact in the request:

```
{{ _self.env.registerUndefinedFilterCallback('ex' ~ 'ec') }}
```
- `'ex' ~ 'ec'` concatenates to the literal string `'exec'` only once Twig evaluates the expression.
- The raw request contains `'ex'` and `'ec'` as two separate short fragments, neither of which alone
  matches a blocklist entry for the full word `exec`.

### 4.2 Dynamic attribute/method access via `attribute()`

Twig provides a built-in `attribute()` function specifically intended for accessing an object's
property or method when the name itself is a *variable* rather than a literal — exactly the scenario a
dot-notation blocklist is designed to catch, and exactly what this function is built to bypass:

```
{{ attribute(_self.env, 'reg' ~ 'isterUndefinedFilterCallback') }}
```
- `attribute(object, name)` — calls the given method/property on `object` using `name` resolved at
  runtime, functioning identically to `object.name` but without ever writing a literal `.` followed by
  the target method name in the raw request.
- Combined with the `~` concatenation trick from section 4.1, the actual method name
  (`registerUndefinedFilterCallback`) never appears as a contiguous substring anywhere in the request.

### 4.3 Case variation on the smuggled PHP function name

Because PHP resolves function names **case-insensitively** at the language level (this applies to global
function name resolution generally, including when a function name is supplied as a dynamic string and
invoked indirectly, as Twig's filter-callback mechanism does internally), the *argument string* you
register as a callback doesn't need to match the function's canonical lowercase spelling:

```
{{ _self.env.registerUndefinedFilterCallback("ExEc") }}
```
- PHP will still resolve `"ExEc"` to the real `exec()` function when it's eventually invoked, because PHP
  function name lookups ignore case.
- This defeats any filter blocklist performing an exact, case-sensitive string comparison against the
  literal lowercase function name `exec`.

## 5. FreeMarker-Specific Bypass Techniques

### 5.1 Alternative square-bracket tag syntax

FreeMarker supports two **interchangeable tag syntaxes**: the default angle-bracket syntax (`<# >`,
`<@ >`) and an alternative square-bracket syntax (`[# ]`, `[@ ]`), intended originally so FreeMarker
directives don't visually collide with literal HTML angle brackets in templates that mix the two heavily.
Where the hosting application has this alternate syntax enabled (check by testing `[=7*7]` instead of
`${7*7}`), a WAF rule written specifically against angle-bracket directive syntax (`<#`, `<@`) will not
recognize the equivalent square-bracket form at all:

```
[#assign ex="freemarker.template.utility.Execute"?new()]
[=ex("id")]
```
- `[#assign ...]` is functionally identical to `<#assign ...>` from file `04` section 1.2 — same
  `?new()` mechanism, same `Execute` utility class.
- `[=ex("id")]` is the square-bracket equivalent of `${ex("id")}`.
- **Important caveat:** this alternate syntax must already be enabled by the application's own FreeMarker
  `Configuration` (`setTagSyntax`) — it is not universally available on every FreeMarker deployment by
  default. Test for it explicitly before relying on it; don't assume it's present.

## 6. Transport/HTTP-Layer Bypass Techniques

These apply regardless of engine, because they target the *delivery mechanism* rather than the payload
syntax itself.

### 6.1 Relocating the payload to a less-inspected request location

Many WAF rule sets apply their most thorough inspection to URL query parameters and standard form fields,
with comparatively lighter coverage of JSON request bodies, custom headers, or cookie values (coverage
gaps vary significantly by specific WAF product and rule set version — always verify rather than assume).
If your injection point is reachable through more than one input method (e.g., the same parameter
accepted via query string or JSON body), submitting through the less-scrutinized path can avoid detection
entirely without changing the payload at all.

### 6.2 URL encoding and double encoding

Standard URL-encoding the delimiter characters (`%7B%7B` for `{{`, `%24%7B` for `${`) is decoded by the
web server/framework before reaching the template engine, but some WAFs only decode once. If the
application's own decoding pipeline performs an additional decode pass beyond what the WAF accounted for
(for example, a reverse proxy that decodes once and an application framework that decodes again), a
**double-encoded** payload (`%257B%257B`) can pass the WAF's single-decode inspection while still
resolving to the correct literal characters once it reaches the template engine. This is environment- and
stack-dependent — confirm the actual decode behavior of the specific proxy/WAF/application chain in front
of your target rather than assuming any particular encoding depth.

## 7. Putting It Together — A Layered Approach

When a straightforward payload from files `02`–`04` gets blocked, work through these layers in order
rather than randomly trying everything at once:

1. **Identify which layer is blocking you** — delimiter signature, keyword blocklist, character-class
   block, or transport-level WAF — by testing minimal probes (file `05` Phase 6.1 methodology applies
   here too).
2. **Apply the matching technique**: subscript/`attr()`/`attribute()` substitution for syntax-category
   blocks, hex-escaping or concatenation for keyword blocks, alternate engine syntax (FreeMarker
   square-bracket) or transport relocation for delimiter-signature blocks.
3. **Re-test incrementally** — change one variable at a time so you know exactly which substitution
   defeated the filter, rather than shipping a maximally-obfuscated payload blind and not understanding
   why it worked (or didn't) if the target's filtering changes later in the engagement.
4. **Document the exact bypass in your report** — the specific filter weakness you exploited (e.g.,
   "blocklist checks for `.` but not `|attr()`-based access") is itself valuable remediation information
   for the client, distinct from the underlying SSTI finding.

**Real-world note:** in real engagements, blocklist-based "WAF" protection in front of SSTI is almost
always either (a) a generic commercial WAF product applying broad injection-pattern rules with no
SSTI-specific tuning, or (b) a custom, often naive, regex-based filter the development team bolted on
after a previous finding. Neither is a substitute for fixing the root cause (never concatenating user
input into template source). When you successfully bypass either, frame your report's remediation
section around that root cause, not just "tune the WAF rule" — the underlying SSTI primitive remains
exploitable through some bypass even after any single filter is patched, until the actual data/template
separation issue from file `01` section 1 is fixed.
