# 06 — tplmap: SSTI Automation (the sqlmap-equivalent for Template Injection)

## 1. What tplmap Is

`tplmap` is an open-source tool, written by Emilio Cobos / maintained under the `epinna/tplmap` GitHub
repository, that automates exactly the manual workflow described in files `01` and `05`: detecting SSTI,
identifying the engine, and where possible, escalating straight to code execution or file read/write —
the same relationship `sqlmap` has to manual SQL injection.

**Real-world note:** `tplmap` should be used the same way you use `sqlmap` in a SQLi engagement — as a
confirmation and exploitation accelerator *after* you've manually identified a candidate injection point,
not as a blind "throw it at every input" first step. Running automated tools against every parameter on a
production target without first manually triaging likely candidates is noisy, slow, and a common mistake
that can also trip WAFs/rate-limits unnecessarily.

## 2. Installation

```bash
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip2 install -r requirements.txt
```

- `tplmap` was originally written for Python 2; some modern installs require a `python2` interpreter and
  `pip2` available on the attack host. If your Kali install only ships Python 3 by default, install
  `python2` and `python2-pip` first, since `tplmap`'s dependency set (notably its use of certain
  engine-specific Python libraries for local verification) assumes a Python 2 environment in the original
  project.
- There are also actively maintained Python 3 forks circulating; if you use one, confirm its flag syntax
  matches what's documented here, since some forks rename or restructure flags.

## 3. Core Usage Pattern

```bash
python2 tplmap.py -u 'http://target.com/page?name=John'
```

- `-u` — the target URL, with the parameter you suspect is vulnerable already present with a placeholder
  value (`John` here). `tplmap` will automatically try injecting its own detection payloads into every
  parameter present in the URL (and into POST data, if supplied via `--data`), the same way `sqlmap`
  probes every parameter in a request unless you scope it down.

When run, `tplmap` performs essentially the same Phase 2–4 process from file `05` automatically:

1. Sends a battery of engine-specific detection payloads (its own internal equivalents of the polyglot
   and math-probe payloads from file `01`).
2. Compares responses to determine which payload(s) actually evaluated.
3. Reports back the identified engine, and if a known code-execution technique exists for that engine,
   confirms it automatically.

## 4. Key Flags, Broken Down

| Flag | Purpose |
|---|---|
| `-u <url>` | Target URL. Required unless using `--data` only for a POST-based target. |
| `-d, --data <data>` | Supply POST body data (form-encoded or raw), marking the injectable parameter the same way you would for GET. |
| `--cookie <cookie>` | Send a specific Cookie header — required for any injection point gated behind authentication. |
| `-X, --os-shell` | Once SSTI with code execution is confirmed, drop into an interactive pseudo-shell, letting you run further OS commands through the confirmed injection point without re-supplying payloads manually each time. |
| `--upload <local_path>` | Upload a local file to the remote server through the confirmed code-execution primitive, useful for delivering payload scripts, webshells, or further tooling once execution is established. |
| `--download <remote_path>` | Download a file *from* the remote server through the confirmed execution primitive — useful for pulling config files, source code, or credential files once you've identified interesting paths. |
| `-e, --engine <engine>` | Force `tplmap` to assume a specific template engine instead of auto-detecting, useful when you've already manually confirmed the engine (per files `01`–`04`) and want to skip detection straight to exploitation. |
| `--level <1-5>` | Controls how exhaustive the detection payload set is — higher levels send more payloads, covering more obscure engines and edge cases, at the cost of more requests and more time/noise. |
| `-p, --param <name>` | Restrict injection attempts to a specific named parameter, instead of trying every parameter in the request — directly equivalent to `sqlmap`'s `-p` flag, and the recommended approach once you've already manually narrowed down the vulnerable parameter. |
| `--os-cmd <command>` | Run a single specified OS command through the confirmed execution primitive and print its output, without dropping into a full interactive shell — useful for quick, scripted confirmation (e.g., in automated recon pipelines). |

## 5. Example Full Workflow

```bash
python2 tplmap.py -u 'http://target.com/page?name=John' -p name --level 5
```
- `-p name` — tells `tplmap` to focus exclusively on the `name` parameter, since you've already manually
  confirmed (per file `01`'s detection methodology) that this is the injectable point — this avoids
  wasting requests probing parameters you've already ruled out or confirmed are not part of the
  vulnerable flow.
- `--level 5` — maximizes payload coverage, appropriate once you've narrowed scope to a single parameter
  and want the most thorough detection pass against it.

Once `tplmap` reports a confirmed engine and code-execution primitive:

```bash
python2 tplmap.py -u 'http://target.com/page?name=John' -p name -X
```
- `-X` — drops into the interactive OS shell, letting you run further commands (`id`, `cat /etc/passwd`,
  `ls -la /var/www`, etc.) directly through the injection point, exactly as if you had SSH access, without
  needing to manually re-craft a fresh template payload for every single command.

## 6. Interpreting tplmap's Output

A successful detection run reports back something resembling:

```
[+] Tplmap 0.5
[+] Testing if GET parameter 'name' is injectable
[+] Smarty plugin is testing rendering with tag '{*BLIND*}'
[+] Jinja2 plugin is testing rendering with tag '{{*BLIND*}}'
[+] Jinja2 plugin has confirmed injection with tag '{{*BLIND*}}'
[+] Tplmap identified the following injection point:

  GET parameter: name
  Engine: Jinja2
  Injection: {{*INJECT*}}
  Context: text
  OS: Linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, python code
```

Breaking down what each reported field actually means and why it matters:

- **`Testing if GET parameter 'name' is injectable`** — confirms `tplmap` is iterating engine-detection
  plugins one by one against this specific parameter, the same logical process as the manual decision
  tree in file `01` section 5.2, just automated.
- **`Engine: Jinja2`** — `tplmap` has already done the work of file `01`'s engine identification phase
  for you; you can now go straight to `02_SSTI_Jinja2_Exploitation.md` if you want to continue manually,
  or trust `tplmap`'s own built-in Jinja2 exploitation logic.
- **`Injection: {{*INJECT*}}`** — shows you the exact template syntax wrapper `tplmap` determined works
  for this context; this tells you precisely how your raw input is being placed relative to the engine's
  delimiters, which is useful diagnostic information even if you choose to continue exploiting manually.
- **`Context: text`** — confirms this is plaintext context (per file `01` section 3.1), not code context
  — meaning `tplmap` had to supply its *own* full `{{ }}` wrapper around your payload, rather than relying
  on an already-existing expression block to break out of.
- **`Capabilities` block** — this is the most operationally important section. Each line reports whether
  `tplmap` successfully verified a specific exploitation primitive:
  - `Shell command execution: ok` — confirms the same OS-command-execution capability you'd manually
    achieve via the `__subclasses__()` chain or `request.application.__globals__` pivot from file `02`.
  - `Bind and reverse shell: ok` — confirms `tplmap` was able to set up a working reverse/bind shell
    through this injection point, which it can do automatically via its `--reverse-shell`/related flags.
  - `File write: ok` / `File read: ok` — confirms arbitrary file I/O is achievable, corresponding to the
    same class of primitive as the FreeMarker file-read chain in file `04`.
  - `Code evaluation: ok, python code` — explicitly tells you the underlying language context is Python,
    confirming your manual Jinja2 identification was correct and that raw Python expressions (not just a
    fixed set of `tplmap`-internal payloads) can be evaluated through this point.

**Real-world note:** always cross-check `tplmap`'s reported engine and capabilities against your own
manual confirmation from files `01`–`04` before relying on it for further exploitation steps. Automated
tools occasionally misidentify an engine when two engines' detection payloads happen to both evaluate
successfully (the same ambiguity problem described in file `01` section 5.2, e.g., Jinja2 vs Tornado both
accepting `{{ }}` syntax) — manual confirmation with a targeted probe like `{{7*'7'}}` remains the
authoritative tie-breaker.

## 7. When to Prefer Manual Exploitation Over tplmap

- **Custom-exploit scenarios** (file `03` section 5, file `05` Phase 6.2) — `tplmap` has no way to
  automatically discover application-specific object methods like `setAvatar()`/`gdprDelete()`; this
  requires manual enumeration and reasoning every time.
- **Heavily sandboxed engines** — `tplmap`'s built-in payload set targets common, known bypasses; a
  custom or patched sandbox configuration may require manually researching version-specific escape
  techniques that aren't in `tplmap`'s payload library yet.
- **Engagements with strict noise/request-budget constraints** — manual, targeted payloads (one or two
  precise requests, per files `01`–`04`) generate far less traffic than `tplmap`'s full multi-engine
  detection sweep, which matters against rate-limited or heavily monitored targets.

`tplmap` is best used as a fast confirmation and exploitation accelerator once you already understand the
manual mechanics — exactly the way experienced SQL injection testers still use `sqlmap` heavily, but only
after (or alongside) understanding what it's actually doing under the hood.
