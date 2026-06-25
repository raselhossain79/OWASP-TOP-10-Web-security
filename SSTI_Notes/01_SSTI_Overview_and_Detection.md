# 01 — SSTI Overview and Detection

## 1. What Server-Side Template Injection Actually Is

Template engines exist to separate *presentation* (HTML structure) from *data* (the values that get
dropped into that structure). A template engine takes a template string containing placeholders, merges
it with data, and renders final output server-side, before the response ever reaches the browser.

SSTI happens when **user input is concatenated into the template itself**, instead of being passed in as
a *data value* to an already-defined template. That distinction is the entire vulnerability.

**Safe (data context) — Twig example:**
```php
$output = $twig->render("Dear {first_name},", array("first_name" => $user->first_name));
```
Here `$user->first_name` is data. The template structure (`"Dear {first_name},"`) is fixed and never
touched by the user. No amount of weird input in `first_name` lets you escape into template syntax,
because it's only ever inserted as a value, not parsed as template source.

**Vulnerable (template context):**
```php
$output = $twig->render("Dear " . $_GET['name']);
```
Now the user's `name` parameter is concatenated directly into the *template source string* before that
string is compiled and rendered. If `name` contains `{{7*7}}`, the Twig compiler sees:
```
Dear {{7*7}}
```
and evaluates `7*7` as a real template expression, because by the time Twig parses this string, your
input is indistinguishable from code the developer wrote.

**Real-world note:** This is conceptually identical to SQL injection arising from string-concatenated
queries instead of parameterized ones. The fix in both cases is the same shape: keep user input as data,
never let it become part of the executable structure.

## 2. Why SSTI Is More Dangerous Than XSS

A reflected `{{7*7}}` that renders `49` looks like nothing — at first glance it can look like a basic
templating quirk or even get dismissed as harmless. The danger is that most template engines expose far
more than string interpolation: many allow attribute access, method calls, and in unsandboxed engines,
arbitrary code execution. Because the payload runs **server-side**, a successful SSTI chain frequently
escalates to:

- Remote Code Execution (RCE) on the back-end server
- Full filesystem read/write
- Access to environment variables, secrets, config objects, and internal source code
- Pivoting into the internal network from the compromised host

**Real-world note:** SSTI was first formally documented by PortSwigger Research in the 2015 paper/talk
*"Server-Side Template Injection: RCE for the Modern Web App"* by James Kettle (@albinowax). That paper
is still the foundational reference most real-world write-ups and tooling (including `tplmap`) build on.

## 3. The Two Injection Contexts

SSTI vulnerabilities arise in two structurally different contexts. You must identify which one you're in,
because the detection method — and the eventual exploit — differs.

### 3.1 Plaintext Context

The user's input lands in a position where the template engine would otherwise just render plain text or
HTML. Example vulnerable code:

```
render('Hello ' + username)
```

Here the developer's *intent* was for `username` to just be a string. But because it's concatenated into
the template source before rendering, you can break out of "plain text mode" using the engine's own
expression syntax.

**Detection technique:** inject a mathematical expression using the target engine's expression syntax
into the parameter, for example:

```
http://vulnerable-website.com/?username=${7*7}
```

- `${ ... }` — the expression-delimiter syntax for many JVM-based engines (FreeMarker uses this exact
  form). This tells the engine "evaluate what's inside these braces, don't just print it literally."
- `7*7` — a math operation with no other purpose than producing a value (`49`) that is extremely
  unlikely to appear by coincidence if the input were just being echoed back as plain text.

If the response shows `Hello 49` instead of `Hello ${7*7}`, the math was evaluated server-side — the
expression syntax was parsed as code, not displayed as a literal string. That is a strong, low-noise
signal of SSTI (as opposed to XSS, which would just reflect the raw string back into HTML).

**Why this also gets mistaken for XSS:** if you only test with an HTML payload like `<script>` and it
reflects back, you might log it as "XSS" and move on, missing the deeper SSTI primitive sitting right
behind it. Always also probe with a math expression even when a reflected-XSS payload already worked,
since the two can co-exist and SSTI is the far higher-impact finding.

### 3.2 Code Context

Here, the user-controllable value is placed *inside* an already-existing template expression, rather than
in plain rendered text. Example vulnerable backend logic:

```
greeting = getQueryParameter('greeting')
engine.render("Hello {{" + greeting + "}}", data)
```

A normal, "intended" request looks like:
```
http://vulnerable-website.com/?greeting=data.username
```
which the engine compiles into `Hello {{data.username}}` and renders as `Hello Carlos`. From the outside
this looks exactly like a harmless object/property lookup — almost indistinguishable from a hashmap
lookup — which is why this context is so easy to miss during a manual audit.

**Detection technique, step by step:**

**Step 1 — rule out plain reflected XSS first:**
```
http://vulnerable-website.com/?greeting=data.username<tag>
```
- `<tag>` here is *not* a template-breakout attempt yet — it's a control test. If the app is just doing a
  naive string lookup with no template parsing involved, this either errors, gets HTML-encoded, or
  produces a blank/garbled result, because `<tag>` isn't a valid property path.

**Step 2 — attempt to break out of the expression and inject raw markup after it:**
```
http://vulnerable-website.com/?greeting=data.username}}<tag>
```
- `data.username` — the expected/legitimate property path the developer intended.
- `}}` — this is the critical part. It is the *closing delimiter* of the engine's expression block
  (Jinja2/Twig-family syntax). If the engine is naively concatenating your raw string into
  `"Hello {{" + greeting + "}}"`, injecting your own `}}` here causes the **real** closing `}}` (the one
  the developer's code appends afterward) to become orphaned plain text instead of a delimiter, while
  *your* `}}` becomes the one that actually closes the expression.
- `<tag>` — arbitrary HTML placed immediately after your injected `}}`, now sitting completely outside
  any template expression, in raw template body context.

**Interpreting the result:**
- If you get an error or blank output → either you used syntax from the wrong engine, or template
  injection isn't reachable here at all.
- If the output renders as `Hello Carlos<tag>` with `<tag>` actually parsed as live HTML in the response
  → this confirms the engine parsed your `}}` as the real closing delimiter, proving you have a working
  SSTI primitive in code context, and that you can now inject real template directives (not just data)
  after the break-out point.

## 4. The Universal Polyglot Detection Payload

When you don't yet know if SSTI exists at all, start broad before you start engine-specific. The
canonical fuzzing payload used across the industry is:

```
${{<%[%'"}}%\
```

This is intentionally a **garbage soup of nearly every special character used across different template
engines' expression syntax**, not a payload that's meant to "work" on its own. Breaking it down character
group by character group:

| Fragment | Belongs to / triggers |
|---|---|
| `${ ... }` | FreeMarker, some EL/JSP-style engines — expression delimiter |
| `{{ ... }}` (the `{{` half here) | Jinja2, Twig, Tornado, Handlebars — expression delimiter |
| `<% ... %>` (the `<%` half here) | ERB (Ruby), JSP, ASP-style tags — code/scriptlet delimiter |
| `[% ... %]` (the `[%` half here) | Template Toolkit (Perl) — directive delimiter |
| `'` and `"` | String terminators in virtually every engine — used to break out of quoted string literals if your input lands inside one |
| `}` `%` `\` | Stray closing/escape characters meant to unbalance whatever delimiter pair is actually in use, forcing a parse error |

**Why this works as a detection probe:** if none of this syntax is being interpreted, the server will
simply reflect the garbage string back verbatim, or HTML-encode it, with no server-side error. But if
*any* of these fragments matches the real engine's syntax, you will typically get one of:

1. A parse/syntax error revealing internal stack traces (often naming the engine and even its version).
2. A partial/garbled render showing that some sub-fragment was evaluated while the rest broke parsing.
3. A 500-class error page that differs from the application's normal error handling.

**Real-world note:** in live engagements, this fuzz string is frequently thrown at *every* user-controllable
input as a cheap, low-effort first pass (URL parameters, form fields, file upload metadata, custom
headers, JSON body values) — the same way `'` or `1=1` gets thrown at parameters during early-stage SQL
injection recon. It's noisy but extremely fast at surfacing whether template parsing is happening at all.

**PortSwigger lab:** *Basic server-side template injection* (ERB engine, plaintext context) is the
canonical entry point for this exact workflow — see `08_SSTI_Cheatsheet_and_Lab_Mapping.md` for the full
step sequence and lab order.

## 5. Identifying the Template Engine

Once you've confirmed template parsing is happening, you need to know *which* engine you're dealing with
before you can pick the right RCE payload — Jinja2 and Twig look deceptively similar but have completely
different object models and gadget chains.

### 5.1 Error-message fingerprinting (fastest method)

Submitting clearly invalid syntax is often the single fastest way to identify the engine, because the
resulting stack trace frequently names the engine and library path directly. For example, submitting:
```
<%=foobar%>
```
to a Ruby ERB-backed template produces an error referencing `erb.rb`, the `NameError` class, and the
literal undefined variable name — instantly confirming both the language (Ruby) and the engine (ERB).

**Real-world note:** never assume "production has error messages disabled, so this technique is useless."
Many real-world targets leak partial stack traces through logging integrations, debug-mode misconfig in
staging-like environments, or verbose 500 pages that were never meant to ship to production. Always try
this step even if you expect a generic error page back.

### 5.2 Syntax-based decision tree (when errors are suppressed)

If error messages are sanitized, fall back to testing engine-specific syntax variants for the same
mathematical operation, observing which one actually evaluates:

| Payload | Evaluates successfully in |
|---|---|
| `${7*7}` | FreeMarker (and other `${ }`-style JVM engines) |
| `{{7*7}}` | Jinja2, Twig, Tornado |
| `<%= 7*7 %>` | ERB |
| `#{7*7}` | Some JSP/EL-style contexts |
| `{{7*'7'}}` | Distinguishes Twig from Jinja2 — see below |

**Critical pitfall — don't stop at the first match:** the *same* payload can validly evaluate in more
than one engine, giving a false sense of certainty. The textbook example: `{{7*'7'}}` returns `49` in
Jinja2 (because Python's `*` operator on a string repeats it... actually returns `'7777777'` in Jinja2,
and `49` in Twig, because PHP's `*` operator coerces the string `'7'` to the integer `7` before
multiplying). The exact behavior:

- **Twig** (PHP-backed): `{{7*'7'}}` → `49` — PHP type-juggles the string `'7'` into the integer `7`.
- **Jinja2** (Python-backed): `{{7*'7'}}` → `7777777` — Python's `*` operator on a `(int, str)` pair
  performs **string repetition**, not arithmetic, producing `'7'` repeated 7 times.

This single payload is one of the most reliable one-shot disambiguators between the two most common
real-world engines, precisely because the *type coercion rules of the underlying language* (PHP vs
Python) leak through the template syntax.

### 5.3 Identification decision summary

```
Garbage polyglot reflected/encoded with no error
        → template syntax likely not parsed → re-test other input points

Error names the engine directly
        → engine confirmed, skip to engine-specific exploitation file

${...} evaluates, {{...}} does not
        → likely FreeMarker or another JVM EL-style engine
        → go to 04_SSTI_Other_Engines.md

{{...}} evaluates
        → disambiguate Jinja2 vs Twig vs Tornado using {{7*'7'}}
        → 49        → Twig            → 03_SSTI_Twig_Exploitation.md
        → 7777777   → Jinja2          → 02_SSTI_Jinja2_Exploitation.md
        → confirm via {% %} block tag support and Python-specific keywords → Tornado
        → go to 04_SSTI_Other_Engines.md for Tornado

<%= ... %> evaluates
        → ERB (Ruby) → 04_SSTI_Other_Engines.md
```

## 6. Next Steps

Once you've confirmed (a) SSTI exists and (b) which engine you're facing, move to the matching
exploitation file:

- Jinja2 confirmed → `02_SSTI_Jinja2_Exploitation.md`
- Twig confirmed → `03_SSTI_Twig_Exploitation.md`
- Anything else (FreeMarker, Velocity, Smarty, Tornado, ERB, Handlebars) → `04_SSTI_Other_Engines.md`

For the complete end-to-end escalation narrative (detection → identification → RCE as a single
continuous workflow, the way you'd run it live), see `05_SSTI_Detection_to_RCE_Escalation.md`.
