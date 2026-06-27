# Supply Chain and Dependency Attack Techniques

## 1. Dependency confusion

### 1.1 The mechanism

Most companies use a mix of **private/internal packages** (e.g. `@acme/internal-auth`
or `acme-internal-utils`) and **public packages** (e.g. `express`, `requests`).
Build tools (npm, pip, etc.) need to know where to look for each package. The
vulnerability exists when:

1. A company has an internal package name that is **not also registered on the
   public registry** (npm/PyPI/RubyGems/etc.).
2. The build/CI configuration does not strictly pin that name to the *private*
   registry — either because of a missing or misconfigured scope mapping, or because
   the tool's default resolution order checks the public registry at all, or resolves
   "whichever registry has the higher version number."
3. An attacker registers a package under that exact internal name on the public
   registry, with a deliberately very high version number (e.g. `99.99.99`), and
   `postinstall`/`setup.py` code that exfiltrates environment data or opens a reverse
   shell.
4. The next time *any* engineer, build server, or CI runner resolves that dependency
   without strict private-registry pinning, it installs and **executes** the
   attacker's package instead of (or as a higher-version "upgrade" over) the real
   internal one.

This is what Alex Birsan's 2021 research weaponized against Apple, PayPal, Microsoft,
and others — not by breaking any cryptography, but by registering names that
internal teams had simply never claimed publicly.

### 1.2 Reconnaissance — finding candidate internal package names

```bash
grep -r "require(['\"]@" ./src --include="*.js" -o | sort -u
```

Breakdown:
- `grep -r` — recursive search through the `./src` directory tree.
- `"require(['\"]@"` — matches Node.js `require()` calls where the imported module
  name starts with `@` (npm's "scoped package" syntax, e.g. `@acme/utils`). Scoped
  names are a strong signal of an internal/private package, since public scopes are
  almost always well-known (`@types`, `@babel`, etc.).
- `--include="*.js"` — restricts the search to JavaScript source files, avoiding
  noise from minified bundles or `node_modules`.
- `-o` — tells `grep` to print *only the matched portion* of each line, not the whole
  line, so the output is a clean list of import statements.
- `sort -u` — deduplicates the results so each unique import string appears once.

Why this is exploitable recon: any internal scope/package name an attacker finds this
way (via a leaked internal repo, a public open-source repo that imports an internal
helper, a `package-lock.json` accidentally committed, a job posting referencing
internal tool names, or a `.npmrc` config file) becomes a candidate to register
publicly and squat on.

```bash
npm view @acme-internal/auth-utils versions --json
```

Breakdown:
- `npm view <package> versions` — queries the **public npm registry** and asks for
  every published version of the given package name.
- `--json` — returns machine-parseable output.
- The exploit-relevant outcome: if this command returns `404 Not Found`, the name is
  **unclaimed on the public registry** — meaning it is a viable dependency confusion
  target. If it returns a version list, either the company already defends this name
  publicly (good) or someone else has already squatted it (worth investigating
  further, carefully, and only within authorized scope).

```bash
pip index versions acme-internal-pkg
```

Breakdown:
- Same idea applied to Python's package index (PyPI). `pip index versions` queries
  PyPI directly for the named package; an error response indicates the name is open.

### 1.3 Detecting confusion-vulnerable resolution in a codebase

```bash
cat .npmrc
npm config get registry
npm config list -l | grep -i registry
```

Breakdown:
- `cat .npmrc` — shows project-level registry configuration. The critical thing to
  look for is whether the scope used for internal packages (e.g. `@acme:registry=`)
  is explicitly pinned to a private registry URL. If it's absent, npm falls back to
  the public registry for *every* scope it doesn't have an explicit mapping for.
- `npm config get registry` — shows the **global default registry** npm will use when
  no scope-specific mapping exists. If this is `https://registry.npmjs.org/` and there
  is no scope override for the internal package's scope, that's the confusion gap.
- `npm config list -l` — lists the full effective configuration (including defaults),
  piped through `grep -i registry` to isolate every registry-related setting across
  global, project, and user config layers, since npm merges configuration from
  multiple files and the *effective* resolution can be non-obvious.

```python
# setup.py / requirements.txt review — look for absence of --index-url pinning
pip install -r requirements.txt --index-url https://pypi.org/simple
```

The real-world finding here isn't a single command output — it's confirming that the
build process resolves package names through a registry that an attacker can publish
to, without an explicit, enforced private-index-first policy
(`--index-url`/`--extra-index-url` ordering matters: pip's `--extra-index-url` does
**not** guarantee the private index is checked first or that higher-version public
packages are excluded — this exact ambiguity is itself a known confusion vector for
pip specifically).

### 1.4 Detection tooling

There is no single "sqlmap-equivalent" automation tool for the entire A08 category —
this is fundamentally a methodology-and-process problem, not a single payload-class
problem. That said, dependency-confusion specifically does have purpose-built
tooling worth knowing:

```bash
git clone https://github.com/visma-prodsec/confused.git
cd confused
go build
./confused -l npm ../target-repo/package.json
```

Breakdown:
- `confused` is an open-source tool (Visma's product security team) built
  specifically to automate dependency confusion discovery.
- `-l npm` — tells the tool which package manager's manifest format to parse
  (npm, pip, gem, and others are supported).
- It parses the manifest file (`package.json` here), extracts every declared
  dependency name, queries the public registry for each, and flags any name that
  **does not exist publicly** — i.e., every name on this list is a potential
  squatting target for an attacker, and a potential confusion vulnerability for the
  organization if their internal registry configuration isn't airtight.

```bash
npm audit signatures
```

Breakdown:
- This is npm's built-in **provenance verification** command (introduced as part of
  npm's supply-chain security push following the incidents above). It checks every
  installed package against cryptographic attestations published via Sigstore,
  confirming the package was built from the source and workflow it claims to be
  built from — directly relevant defensive control against both dependency confusion
  and outright package takeover, since a forged/squatted package will not have a
  valid provenance attestation tied to the real maintainer's build pipeline.

```bash
pip install pip-audit
pip-audit
```

Breakdown:
- `pip-audit` (maintained with backing from Google and PyPA) scans installed Python
  packages against the **Python Packaging Advisory Database (PyPA Advisory DB)** and
  OSV (Open Source Vulnerabilities) feeds.
- Run with no arguments, it audits the currently active virtual environment's
  installed packages and reports known CVEs by package and version — this won't
  catch a *brand-new* squatting package directly, but it is the standard
  first-line defensive scan industry teams run in CI specifically to catch known
  malicious or vulnerable package versions.

### 1.5 Defensive fix (what a remediation report should recommend)

- Explicitly scope every internal package name to a private registry in `.npmrc`
  (`@acme:registry=https://npm.internal.acme.com/`) — never rely on default
  resolution order.
- Pre-emptively register placeholder packages under your internal names on every
  public registry you use, even if they're never published with real code — this is
  the simplest, lowest-effort mitigation and is what most large tech companies did
  immediately after Birsan's 2021 disclosure.
- Use `pip install --index-url <private> --no-index` (force private-only resolution)
  rather than `--extra-index-url` for fully internal packages.
- Enforce lockfiles (`package-lock.json`, `poetry.lock`, `Pipfile.lock`) with
  registry-pinned, hash-verified entries, and fail CI builds on lockfile drift.

---

## 2. Typosquatting

### 2.1 The mechanism

Instead of exploiting a *missing* registration, the attacker exploits **human and
tooling error in spelling**. They register a package with a name deliberately close
to a popular legitimate package:

- Character substitution: `python-dateutil` → `python-dateutll`
- Hyphen/underscore confusion: `django-rest-framework` → `djangorestframework` vs
  `django_rest_framework`
- Common misspelling: `requests` → `request`, `colorama` → `colourama`

Real-world incidents in this category include `crossenv` (a malicious typosquat of
`cross-env` on npm, 2017) and dozens of PyPI typosquats caught and removed by
PyPI's malware-detection pipeline (`pypi.org`'s "Project malware reports" feed is
public — worth periodically reviewing as a research source).

### 2.2 Reconnaissance commands

```bash
pip download --no-deps -d /tmp/audit acme-pkg
unzip -p /tmp/audit/acme_pkg*.whl '*/setup.py' 2>/dev/null
```

Breakdown:
- `pip download --no-deps -d /tmp/audit <pkg>` — downloads the package archive
  *without installing it or its dependencies*, into an isolated directory. This is
  the safe way to inspect a suspicious package without letting any `setup.py`
  install-time code execute on your machine.
- `unzip -p ... '*/setup.py'` — extracts and prints the `setup.py` file's content
  directly from the wheel archive without fully unpacking it, so you can manually
  review for suspicious code (network calls, `os.system`, `eval`, base64-encoded
  blobs) before ever running `pip install` against the real package.

```bash
npm pack acme-pkg --dry-run
```

Breakdown:
- `npm pack --dry-run` — shows exactly what files *would* be included in the
  package tarball without actually downloading/installing it, letting you review
  file listing and `package.json` `scripts` block (specifically `preinstall`,
  `install`, and `postinstall` hooks — the most common code-execution vector in
  malicious npm packages) before committing to an install.

## 3. Malicious package takeover (maintainer account compromise / ownership transfer)

This is the `event-stream` and `ua-parser-js` pattern: the package name and history
are completely legitimate, but control of publishing has been hijacked or socially
engineered away from the real maintainer.

### 3.1 What a defender/tester checks

```bash
npm view express maintainers
npm view express time --json | tail -5
```

Breakdown:
- `npm view <pkg> maintainers` — lists the npm accounts currently authorized to
  publish new versions of the package. A sudden, unexplained addition of a new
  maintainer account (especially one with little to no other published history) on a
  high-impact package is the single biggest leading indicator in real incidents like
  `event-stream`.
- `npm view <pkg> time --json` — returns a timestamp for every published version.
  Piped through `tail -5`, this surfaces the most recent publish events. An
  unscheduled, undocumented release of a stable, low-churn package is a strong
  red flag worth manually diffing against the previous version's source.

```bash
diff -ru node_modules/acme-pkg-v1.2.3 node_modules/acme-pkg-v1.2.4 | less
```

Breakdown:
- A straightforward recursive diff between two extracted versions of the same
  package. In a real review, you are specifically looking for new `postinstall`
  scripts, new outbound network calls, base64/hex-encoded strings that decode to
  executable code, or unrelated-to-the-changelog file changes — exactly the pattern
  that exposed the `flatmap-stream` payload bundled inside `event-stream`.

### 3.2 Tooling that operationalizes this at scale

```bash
npx socket-security/cli@latest npm audit
```

Breakdown:
- Socket (and similar commercial/open tools like **OSSF Scorecard** and
  **Snyk Advisor**) run static and behavioral analysis across an entire dependency
  tree, flagging packages that introduce *new* dangerous capabilities between
  versions — install scripts, native code (`.node` binaries), filesystem/network
  access patterns, and known-bad maintainer/publish anomalies — without requiring a
  human to manually diff every transitive dependency by hand. This class of tooling
  exists specifically because manual review (section 3.1) doesn't scale past a
  handful of direct dependencies, let alone hundreds of transitive ones.

## 4. Real-world note: this is where "shift left" actually pays off

Every named incident in this file (`event-stream`, `ua-parser-js`, `crossenv`,
Birsan's dependency confusion research, `xz-utils`) was caught — when it was caught
at all — by either: a maintainer noticing unexplained build behavior, a researcher
deliberately probing for unclaimed namespaces, or automated scanning flagging a
behavioral anomaly. None of them were caught by a traditional web-app penetration
test of the *running application*. This is the practical argument for why supply
chain review belongs in the build/CI phase, not just the runtime testing phase —
which leads directly into the next file.
