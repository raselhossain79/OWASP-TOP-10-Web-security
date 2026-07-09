# 08 — Automation Tools: XSStrike & dalfox

## Why This File Exists

SQLi has `sqlmap` as the dominant, near-universal automation tool. XSS has no single equivalent with that level of dominance — instead, **XSStrike** and **dalfox** are the two most-cited open-source tools that attempt to automate XSS discovery. Both have real value and real, important limits. This file covers both in depth, plus an explicit breakdown of what each can/cannot reliably detect versus what still requires manual testing (files 02-07).

**Versions and flags for both tools change between releases** — always run `--help` against your installed version before relying on this file's flag list verbatim; the mechanisms described (what each flag *does conceptually*) are stable even when exact flag spellings drift.

## XSStrike

### What It Is
A Python-based XSS detection tool (github.com/s0md3v/XSStrike) that combines **fuzzing**, a **context-aware payload generator**, and a basic **DOM XSS scanner**. Notably, XSStrike doesn't just throw a static payload list — it analyzes how the application reflects/encodes a probe string and then generates a payload tailored to that specific context, conceptually similar to the manual methodology in files 01-02 but automated.

### Installation
```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip3 install -r requirements.txt --break-system-packages
python3 xsstrike.py
```
Breakdown:
- `git clone` — pulls the tool's source since it's distributed as a Python script repository, not a packaged binary.
- `pip3 install -r requirements.txt` — installs its Python dependencies (e.g. `fuzzywuzzy` for similarity scoring used in its context-detection logic, `requests`, `tld`).
- `--break-system-packages` — required on modern Debian/Ubuntu (PEP 668 externally-managed-environment protection) to allow `pip` to install into the system Python environment directly, consistent with your existing pip workflow.

### Core Usage
```bash
python3 xsstrike.py -u "https://target.com/search?q=test"
```
- `-u` — target URL. XSStrike automatically identifies which parameter(s) to fuzz from the URL's query string (here, `q`).

### Key Flags and What They Actually Do

| Flag | Mechanism |
|---|---|
| `--data "param=value"` | Switches the request to **POST**, sending the given body — necessary because the default `-u` mode only tests GET parameters present in the URL itself; many real injection points are POST-only form fields. |
| `--crawl` | Enables XSStrike's built-in crawler to discover additional in-scope URLs/parameters from the target site rather than testing only the single URL given — useful for quick recon coverage, but shallow compared to a dedicated crawler (Burp's spider, or `katana`). |
| `--params` | Restricts testing to only the parameters explicitly visible in the supplied URL/data, skipping XSStrike's own automatic parameter-discovery heuristics — useful when you already know exactly which parameter is interesting and want to avoid noisy/slow exploration of others. |
| `--skip-dom` | Disables XSStrike's DOM XSS scanning module — useful to speed up a run when you only care about reflected/server-side behavior and already plan to do DOM analysis manually with Burp's DOM Invader (file 04). |
| `--blind <url>` | Injects an out-of-band (Blind XSS, file 05) payload pointing at the given Collaborator/webhook URL into every tested parameter, instead of (or alongside) trying to detect a directly-visible reflection — operationally automates the "shotgun seed many contexts" approach described in file 05. |
| `-t / --threads <n>` | Number of concurrent fuzzing requests — raising this speeds up scanning but increases load on the target and risk of triggering rate-limiting/WAF blocking; tune conservatively on production targets during real engagements. |
| `--fuzzer` | Runs XSStrike's raw fuzzing mode (tries a battery of special characters/payload fragments and reports exactly which ones are reflected unmodified) rather than its full context-aware payload-generation pipeline — useful as a faster first-pass equivalent to the manual "Step Zero" character-probing described in file 07. |
| `-l / --level <n>` | Controls how aggressive/exhaustive the payload generation is — higher levels try more payload variants and context permutations at the cost of more requests and runtime. |
| `--headers` | Allows including custom HTTP headers (e.g. `Cookie`, `Authorization`) in the scan — necessary for testing authenticated areas of an application, since without session credentials, XSStrike (like any scanner) can only reach unauthenticated endpoints. |

### What XSStrike Can Reliably Detect
- Classic Reflected XSS in URL/POST parameters with straightforward HTML-body or simple-attribute contexts.
- Many common filter-bypass scenarios via its context-aware generator, since it actively probes which characters survive (similar logic to file 07's Step Zero) before selecting a payload shape.
- Basic DOM XSS via its built-in (limited) DOM scanning module, primarily for straightforward source→sink patterns reachable via URL parameters.

### What XSStrike Cannot Reliably Detect (Manual Testing Still Required)
- **Stored XSS** generally — it has no concept of "submit now, check a different page/session later," since that requires application-specific knowledge of where stored data resurfaces (file 03's methodology is inherently manual/semi-manual).
- **Complex DOM XSS** involving non-URL sources (`postMessage`, `localStorage`, custom event listeners) — its DOM scanning is meaningfully shallower than Burp's DOM Invader for these cases (file 04).
- **mXSS** (file 04) — requires sanitizer-specific, parser-internals-level analysis no generic fuzzer performs.
- **CSP bypass reasoning** (file 06) — XSStrike does not parse/reason about CSP headers to determine bypass feasibility; it has no concept of allowlisted-host JSONP chains, AngularJS sandbox escapes, etc.
- **Authentication-gated multi-step flows** (e.g. a feature reachable only after completing a multi-page wizard) — automated tools generally can't navigate complex UI flows without significant custom scripting/session setup.

## dalfox

### What It Is
A Go-based, actively maintained XSS scanner (github.com/hahwul/dalfox) generally regarded as faster and more actively developed than XSStrike as of recent years, with stronger parameter-mining and reporting features, and tighter integration into bug-bounty/CI-style automated workflows.

### Installation
```bash
go install github.com/hahwul/dalfox/v2@latest
```
- `go install` compiles and installs the tool directly from source via Go's package manager, placing the binary in your Go bin path (`$GOPATH/bin` or `$HOME/go/bin` — ensure this is in your `PATH`).

### Core Usage Modes
```bash
dalfox url "https://target.com/search?q=test"
dalfox file urls.txt
echo "https://target.com/search?q=test" | dalfox pipe
```
Breakdown:
- `dalfox url <single-url>` — scans one specific URL.
- `dalfox file <path>` — batch-scans every URL listed in a text file, one per line — useful after generating a URL list from a crawler (e.g. `katana`, `gau`, or Burp's exported site map).
- `dalfox pipe` — reads target URLs from **stdin**, letting you chain it directly after other recon tools in a single shell pipeline (e.g. `cat urls.txt | grep "?" | dalfox pipe`), which is a deliberate design choice favoring Unix-philosophy tool-chaining.

### Key Flags and What They Actually Do

| Flag | Mechanism |
|---|---|
| `-b / --blind <url>` | Equivalent concept to XSStrike's `--blind` — injects an OOB callback payload (file 05) pointing at your Collaborator/webhook URL, useful for automated Blind XSS sweeping across many URLs at once. |
| `--mining-dom` | Enables active DOM-based parameter mining — dalfox parses the page's rendered DOM (via a headless browser component) to discover **additional parameters used by client-side JS** that wouldn't be visible from the URL/HTML source alone, directly relevant to DOM XSS discovery (file 04). |
| `--mining-dict` | Supplements parameter discovery using a built-in dictionary of commonly-used parameter names (e.g. `redirect`, `url`, `next`, `search`, `q`) — tests these even if they aren't present in the original URL, catching hidden/undocumented parameters. |
| `-X / --method <verb>` | Sets the HTTP method (GET/POST/PUT etc.) explicitly, needed for testing non-GET endpoints. |
| `-d / --data <body>` | Supplies a POST body, analogous to XSStrike's `--data`. |
| `-H / --header <header>` | Adds a custom header (repeatable flag) — used for session cookies, auth tokens, or custom headers required to reach authenticated functionality. |
| `-C / --cookie <cookie>` | Shorthand specifically for setting the `Cookie` header, used to scan as an authenticated session. |
| `--custom-payload <file>` | Supplies your own payload list/file rather than relying solely on dalfox's built-in payload set — important once you've identified (via manual Step Zero analysis, file 07) the specific context/filter behavior of your target and want dalfox to confirm/sweep a tailored payload across many parameters rather than its generic defaults. |
| `--waf-evasion` | Enables dalfox's built-in WAF-evasion payload variants (encoding/casing tricks similar in spirit to file 07's Technique 3/5) — still subject to the same caveat as manual WAF evasion: not guaranteed against any specific real-world WAF, since WAF vendors update signatures independently of dalfox's release cycle. |
| `--skip-bav` | Skips dalfox's "Basic Another Vulnerability" auxiliary checks (it opportunistically also flags some non-XSS issues like exposed `.git`, certain misconfigurations, during a scan) — use this to keep a run strictly focused on XSS and reduce noise/runtime. |
| `-w / --worker <n>` | Concurrency level, analogous to XSStrike's `--threads` — same tuning caveat regarding target load/rate-limiting. |
| `-o / --output <file>` | Writes results to a file rather than (or in addition to) stdout — useful for feeding results into a reporting pipeline or diffing between scan runs. |
| `--follow-redirects` | Makes dalfox follow HTTP redirects during testing rather than stopping at the first redirect response — relevant when a target's normal flow involves a redirect before reaching the actual vulnerable page. |
| `--silence` | Suppresses verbose/banner output, useful when scripting dalfox as part of a larger automated pipeline where you only want to parse the final results programmatically. |

### What dalfox Can Reliably Detect
- Reflected XSS across a wide range of HTML/attribute/JS-string contexts, generally with stronger context-detection accuracy than older XSStrike releases due to more active ongoing development.
- DOM XSS reachable via its headless-browser-backed `--mining-dom` feature, covering a meaningfully wider set of source/sink combinations than XSStrike's scanner, though still not a full replacement for Burp's DOM Invader plus manual source code review (file 04) on complex SPAs.
- Blind XSS sweeping at scale via `-b`, making it well-suited to bug-bounty-style "submit Blind XSS payloads across many discovered parameters quickly" workflows.

### What dalfox Cannot Reliably Detect
- **Stored XSS requiring multi-step application logic** (submit on page A, view as a different role/session on page B) — same fundamental limitation as XSStrike; dalfox has no innate concept of your application's specific stored-data display logic.
- **mXSS / sanitizer-specific parser-confusion bugs** (file 04) — no generic scanner reasons about a specific sanitizer library's internal parse/reserialize behavior; this remains research/manual-analysis territory.
- **CSP-aware bypass reasoning** (file 06) — dalfox can tell you a payload *would* execute absent CSP, but doesn't itself reason through allowlisted-host JSONP chains or AngularJS sandbox escapes as a strategy; you still apply file 06's manual methodology once dalfox/XSStrike confirms an injection point exists.
- **Business-logic-gated injection points** — any field only reachable after a complex auth/workflow sequence generally needs you to script the session setup yourself (via `-C`/`-H` for static session reuse, or pre-authenticating and exporting cookies) rather than expecting the tool to navigate the flow itself.

## XSStrike vs. dalfox — Practical Comparison

| Aspect | XSStrike | dalfox |
|---|---|---|
| Language/speed | Python, generally slower | Go, generally faster, better suited to large-scale scanning |
| Maintenance activity | Slower/less frequent releases in recent years | More actively maintained as of recent releases |
| DOM XSS capability | Basic, lighter-weight | Stronger, via headless-browser-backed DOM mining |
| Workflow fit | Good for focused, single-target deep dives | Good for both focused scans and large-scale automated sweeps (CI pipelines, bug bounty recon at scale) |
| Blind XSS support | Yes (`--blind`) | Yes (`-b`), commonly used for scale |

## Why Neither Tool Replaces Manual Testing (Industry Reality)

Both tools operate primarily on **black-box request/response analysis** (plus dalfox's DOM-mining add-on). Neither tool:
- Understands your application's **business logic** (which page displays which stored field, which role sees what).
- Reasons about **CSP bypass strategy** the way file 06 requires.
- Detects **mXSS / sanitizer-internals bugs** the way file 04's mechanism walkthroughs require.
- Replaces **reading actual client-side JavaScript source** for non-obvious DOM sinks.

In real engagements, the professional workflow is: run dalfox (or XSStrike) early for broad, fast coverage of straightforward Reflected/simple-DOM cases and Blind-XSS sweeping, then spend the majority of manual testing time on Stored XSS flows, DOM XSS in complex SPA logic, CSP bypass reasoning, and mXSS/sanitizer-specific research — exactly the areas automation structurally cannot cover.

## Real-World Engagement Notes
- Both tools generate significant request volume quickly — always confirm rate-limit/load tolerance with the client before running either against a production target, and prefer staging/test environments when available.
- Treat tool output as **candidate findings requiring manual confirmation**, not final report-ready results — both tools can produce false positives (e.g. a payload that's "reflected" but lands somewhere that's actually correctly encoded once rendered in a real browser) and false negatives (especially for anything in the "cannot reliably detect" lists above).
- Logging full request/response pairs (`-o` in dalfox, or Burp sitting as an upstream proxy for either tool) is good practice so you can manually re-verify any flagged finding before reporting it.

## Common Mistakes
- Running either tool unauthenticated and concluding "no XSS found" without ever testing logged-in functionality.
- Treating a tool's "vulnerable" verdict as report-ready without manually re-confirming execution in an actual browser.
- Forgetting `--mining-dom`/DOM-aware flags exist and missing DOM XSS entirely because the default scan mode is reflection-focused.

## Report-Writing Notes
- If a finding was initially surfaced by XSStrike/dalfox, say so for transparency, but the report's actual evidence should be your **manually reproduced** request, response, and browser PoC — not just a copy of the tool's raw output.
- Note the tool name/version used for any automated-discovery credit, since reproducibility steps may differ slightly between tool versions.

---
**Next:** `09_Exploitation_Impact.md`
