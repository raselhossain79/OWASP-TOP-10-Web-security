# 03 — Automation Tools: Retire.js and OWASP Dependency-Check

There is no single "sqlmap-equivalent" automated exploitation tool for A06,
because A06 isn't an exploitation technique — it's a detection/inventory
problem. The closest industry-standard automation tools are **Software
Composition Analysis (SCA)** tools. The two most relevant for a web app
pentester (one client-side, one server-side/build-level) are Retire.js and
OWASP Dependency-Check.

## 1. Retire.js — client-side JavaScript dependency scanning

Retire.js detects known-vulnerable JavaScript libraries by scanning either
live web pages/URLs or local JS files/directories, matching against its own
vulnerability repository (`jsrepository.json`).

### When to use it
Black-box-friendly — you don't need source code access, just the ability to
load the page (or download its JS assets), making it usable in almost every
web app engagement, including pure external/black-box tests.

### Core command — scanning a live URL

```bash
retire --jspath /tmp/target_js_dump --outputformat json --outputpath retire_results.json
```

Flag-by-flag breakdown:

- `retire` — invokes the CLI tool (installed via `npm install -g retire`).
- `--jspath /tmp/target_js_dump` — tells Retire.js to scan a **local directory**
  of JS files rather than crawling a live site directly. In practice, for a
  black-box web app test, you first download the target's JS assets (e.g. via
  `wget -r -A js https://target.example.com` or by saving them from Burp's
  site map) into a local folder, then point Retire.js at that folder. This
  avoids hammering the live target with Retire.js's own crawling and lets you
  control exactly what gets scanned.
- `--outputformat json` — sets the output format to JSON instead of the
  default human-readable text, which makes it scriptable and easy to merge
  into a larger findings dataset.
- `--outputpath retire_results.json` — writes the JSON output to this file
  instead of just printing to stdout, so you have a persistent evidence
  artifact for the report.

### Scanning a live site directly

```bash
retire --path https://target.example.com --severity medium
```

- `--path <url-or-dir>` — Retire.js accepts either a local path or, in some
  builds/wrappers, a URL to fetch and scan directly. Behavior depends on the
  exact Retire.js distribution — the npm CLI primarily scans local
  filesystem paths; for true live-URL scanning many testers instead use the
  Retire.js **browser extension**, which scans whatever JS the browser
  actually loads (including dynamically injected scripts the CLI's static
  download might miss).
- `--severity medium` — filters output to only show findings rated medium
  severity or above, cutting down noise from low-impact/informational
  findings when you just want the actionable list.

Other flags worth knowing:

- `--ignorefile <path>` — points to a file listing libraries/paths to exclude
  from scanning (e.g. known false positives already triaged and accepted by
  the client), keeping repeat scans clean.
- `--verbose` — shows additional detail per finding, including the matched
  vulnerability info entry from the JS repository.
- `--exitwith 0` — forces the tool to always exit with code 0 regardless of
  findings, useful when wiring Retire.js into a CI pipeline where you don't
  want a vulnerable-dependency finding to hard-fail the build (used carefully,
  and usually only during an initial baseline/triage period).

### Reading the output

Each finding reports: the library name, the detected version, the matched
vulnerability identifier(s) (often a CVE or a vendor advisory ID), and a
severity rating. Treat the version Retire.js reports as a *lead* — confirm
it against the actual file (e.g. check for a version string in a comment at
the top of the minified file, or the file's known hash) before writing it
into a report, since some sites rename or repackage libraries in ways that
can confuse static signature matching.

**Real-world note:** Retire.js is widely embedded into CI/CD pipelines by
dev teams themselves (and into Burp Suite as an extension), so it's common
to find that a security-mature client has already run it internally. As a
pentester, your value-add is catching what their CI scan missed — e.g. JS
loaded dynamically at runtime, third-party-hosted scripts (CDNs, ad/analytics
tags) that aren't part of their own build pipeline, or libraries with a
vendor-patched-but-not-version-bumped fork.

## 2. OWASP Dependency-Check — server-side / build dependency scanning

OWASP Dependency-Check (ODC) scans a project's dependency artifacts (JARs,
DLLs, `package-lock.json`, `requirements.txt`, etc.) and cross-references them
against the NVD CVE feed to flag known-vulnerable components. Unlike
Retire.js, this is squarely a grey-box/white-box tool — it needs access to
the application's actual build artifacts or dependency manifests, not just
the live website.

### Core command

```bash
dependency-check --project "TargetApp" --scan ./target_source --format "HTML" --out ./odc_report --nvdApiKey $NVD_API_KEY
```

Flag-by-flag breakdown:

- `dependency-check` — invokes the CLI (the actual executable name is
  typically `dependency-check.sh` on Linux/macOS or `dependency-check.bat`
  on Windows, depending on install method).
- `--project "TargetApp"` — sets a human-readable project name, which appears
  in the report header — purely organizational, useful when you're running
  scans across multiple client applications and need to tell reports apart.
- `--scan ./target_source` — specifies the **path to scan**: this can be a
  directory containing the application's source code, compiled artifacts, or
  dependency manifest files. ODC walks this path looking for recognizable
  dependency files (e.g. `pom.xml`/JARs for Java, `package.json`/
  `package-lock.json` for Node, `requirements.txt` for Python).
- `--format "HTML"` — sets the output report format. ODC also supports `XML`,
  `JSON`, `CSV`, `SARIF`, and `ALL` (generates every format at once) —
  `HTML` is usually best for client-facing report excerpts, `JSON`/`SARIF`
  for feeding into other tooling or ticketing systems.
- `--out ./odc_report` — sets the output directory where the report file(s)
  will be written.
- `--nvdApiKey $NVD_API_KEY` — supplies an NVD API key (read as an environment
  variable here) to authenticate ODC's vulnerability database update requests
  against the NVD API. Without a key, ODC is heavily rate-limited when
  downloading/updating its local copy of the NVD CVE feed, which can make the
  first scan extremely slow or fail outright on a fresh install. Getting a
  free NVD API key (see File 04) before running ODC for the first time is a
  practical necessity, not optional polish.

Other flags worth knowing:

- `--suppression <path>` — points to an XML suppression file listing findings
  to exclude (confirmed false positives, or risks the client has formally
  accepted) — same purpose as Retire.js's `--ignorefile` but in ODC's own XML
  schema.
- `--failOnCVSS <score>` — makes the scan exit with a non-zero (failing) code
  if any finding meets or exceeds the given CVSS score — mainly a CI/CD gate
  feature, but useful in a pentest context if you're scripting a "did this
  introduce anything critical" check across multiple builds/branches the
  client gave you access to.
- `--enableExperimental` — turns on experimental analyzers (e.g. for less
  common ecosystems), which can surface more findings at the cost of a higher
  false-positive rate. Use deliberately, not by default.
- `--data <path>` — sets a custom local path for ODC's downloaded NVD data
  cache, useful for offline/air-gapped engagement environments where you
  pre-stage the NVD database once and reuse it across scans without
  re-downloading.

### Reading the output

ODC reports each dependency along with: the file path/artifact it was found
in, its detected version, any CPE (Common Platform Enumeration) matches, the
associated CVE(s), CVSS score, and a confidence level for the match itself
(ODC explicitly flags low-confidence matches — don't report those as
confirmed findings without manual verification via File 04's workflow).

**Real-world note:** ODC's CPE-matching can produce false positives when a
library's internal version string doesn't follow standard semantic versioning,
or when a vendor has forked/renamed a library. This is the single most common
ODC complaint in industry use — always spot-check a sample of "Critical"
findings manually before they go into a final report, especially for any
component with an unusual versioning scheme.

## 3. Where these two tools sit relative to each other

| | Retire.js | OWASP Dependency-Check |
|---|---|---|
| Layer | Client-side JS | Server-side / build dependencies (Java, .NET, Node, Python, etc.) |
| Access needed | None — works against live, deployed JS (black-box friendly) | Source code, build artifacts, or manifest files (grey/white-box) |
| Typical engagement fit | External web app pentest, even with zero source access | Code review, DevSecOps assessment, white-box pentest with repo access |
| Data source | Retire.js's own curated JS vulnerability repository | NVD CVE feed via CPE matching |

In a pure black-box external pentest, Retire.js (or its browser extension) is
usually all you can run yourself. If the engagement includes any code/CI
access, layering in OWASP Dependency-Check gives you the full picture —
report this distinction explicitly in the engagement scope section of your
findings, since clients often assume "we ran a dependency scanner" covers
everything when it may have only covered one layer.
