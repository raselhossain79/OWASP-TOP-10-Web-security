# 01 — Overview & Classification

## 1. What "file inclusion" actually means

In PHP (and equivalent constructs in other languages), there's a family of
functions whose entire job is: *take a file path, pull in its contents, and
hand that content to the interpreter to execute as code* — not just display it.

```php
include($_GET['page'] . '.php');
```

That single line is the entire vulnerability class. Walk through what it does:

- `$_GET['page']` — pulls a value straight from the URL query string, attacker-controlled, no validation shown here.
- `. '.php'` — the developer appends a fixed extension, presumably expecting the parameter to only ever contain a filename like `home` or `contact`.
- `include(...)` — this is the critical part. `include()` doesn't just read bytes and print them. It loads the target file and **parses it as PHP**, executing any `<?php ... ?>` blocks found inside, in the same process, with the same privileges as the web application itself.

If an attacker can influence the path passed to `include()` (or `require()`,
`include_once()`, `require_once()`), and can get *any* content they control onto
a path the server will read, that content gets executed. That's the entire
difference from path traversal, and it's worth stating precisely because the two
classes get confused constantly.

## 2. File inclusion vs. path traversal — precisely

| | Path Traversal | File Inclusion |
|---|---|---|
| Underlying function | `file_get_contents()`, `fopen()`, `readfile()`, an `<img src>` handler, etc. | `include()`, `require()`, `include_once()`, `require_once()` (or a templating engine's "include" directive) |
| What happens to the file content | Returned/displayed as data | **Parsed and executed** as code |
| Worst case if you can only traverse outside the web root | Read arbitrary files the process has permission to read | Read arbitrary files **and** execute any code embedded in them |
| Can it become RCE on its own? | Only indirectly (e.g., if you can also write a file somewhere, like an upload, and then read+execute it via a *separate* inclusion bug) | Yes, directly — that's the entire point of this vulnerability class |

The practical consequence: every File Inclusion bug already gives you the read
primitive that a path traversal bug gives you (`?page=../../../etc/passwd` works
against a vulnerable `include()` just like it works against a vulnerable
`readfile()`). But File Inclusion additionally gives you a *write-then-execute*
problem to solve, and most of this series (files 3–5) is about exactly that: how
do you get attacker-controlled PHP code onto a path the application will
`include()`, when you usually can't write files to the server directly?

## 3. The PHP functions and settings that create this risk

### Inclusion functions

- `include()` / `include_once()` — emits a warning and continues execution if the file doesn't exist.
- `require()` / `require_once()` — throws a fatal error and halts execution if the file doesn't exist. Functionally identical for exploitation purposes; the difference only matters for how loud the failure is.

### The two `php.ini` directives that matter most for this series

- **`allow_url_fopen`** — controls whether PHP's filesystem functions (`fopen()`, `file_get_contents()`, and friends) can treat a URL (`http://`, `ftp://`) as a "file" at all. Defaults to **On** in most PHP installs, because a lot of legitimate code depends on it.
- **`allow_url_include`** — controls specifically whether **inclusion functions** (`include`/`require`) are allowed to fetch a *remote* URL as their source. This has defaulted to **Off** since PHP 5.2 (released 2006) precisely because of how dangerous RFI is. You'll see in file 5 why this single setting is the entire gatekeeper for classic RFI.

These two directives are independent. `allow_url_fopen=On` with
`allow_url_include=Off` (today's overwhelmingly common default) means: the app
can fetch a remote URL's *contents* as data, but `include()` will refuse to treat
a remote URL as its source. That distinction is exactly why files 3–5 spend so
much time on wrappers that work *without* needing `allow_url_include` at all.

## 4. Where this shows up in real applications

File inclusion bugs are rarely "the developer wrote `include($_GET[...])` and
shipped it" in isolation anymore — egregiously obvious cases like that mostly got
weeded out of major frameworks years ago. Where they persist in 2026:

- **Legacy/unmaintained PHP applications** — small business sites, internal
  tools, abandoned WordPress/Joomla plugins, anything still running PHP 5.x or
  early 7.x code that was never refactored.
- **Multi-language / templating selection** — a "language" or "template" query
  parameter selects which file to `include()` for localization or theming.
  This pattern (`?lang=fr` → `include("lang/$lang.php")`) is one of the single
  most common real-world LFI sources, and it's exactly how it's framed in most
  bug bounty writeups.
- **Plugin/module loading systems** — CMSs and frameworks that let a parameter
  pick which "module" or "widget" file to load. WordPress and Joomla both have
  a long CVE history of exactly this pattern in third-party plugins.
- **File managers / document viewers** — internal admin tools that "preview" a
  document by including or rendering it server-side.

## 5. Why bug bounty programs and pentest reports treat this as high/critical

A reflected XSS might be "medium." A File Inclusion finding that's reachable
with attacker-controlled input is treated as **critical** by default in almost
every bug bounty triage process, because the realistic worst case isn't "I can
read a config file" — it's full RCE, and the path from disclosure to RCE is
usually short (this whole series walks that path). Triagers will generally
escalate severity the moment you can demonstrate code execution, even a simple
`phpinfo()` or `whoami` proof, rather than stopping at file read.

## 6. Classification used for the rest of this series

This series is organized around **how you get from "I found an inclusion point"
to "I have code execution,"** because that's the actual decision tree you walk
through in a real assessment:

1. **Can I read sensitive files at all?** → File 2 (basic LFI, bypasses, null
   byte/truncation).
2. **Can PHP's own stream wrappers turn this into execution without needing to
   write anything to disk?** → File 3 (`php://filter`, `php://input`,
   `data://`, `expect://`).
3. **If wrappers are restricted, can I get my own code onto a file the server
   already controls, then include that?** → File 4 (log poisoning, session
   poisoning, `/proc/self/environ`).
4. **Is the remote-URL path open at all?** → File 5 (RFI, `allow_url_include`,
   the SMB/UNC trick).

Each file builds on the one before it. File 6 consolidates everything into a
single cheatsheet once you've internalized the mechanisms.
