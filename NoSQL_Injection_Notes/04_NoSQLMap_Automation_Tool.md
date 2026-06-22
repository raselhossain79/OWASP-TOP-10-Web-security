# NoSQLMap — The sqlmap-Equivalent Automation Tool for NoSQL Injection

## 1. What It Is

**NoSQLMap** is an open-source Python tool that automates discovery and exploitation of NoSQL injection vulnerabilities and NoSQL database misconfigurations. It was originally authored by a researcher under the handle `tcstool` and is now maintained by `codingo` on GitHub. The name is a deliberate tribute to **sqlmap** (the tool authored by Bernardo Damele and Miroslav Stampar) — NoSQLMap aims to be "the sqlmap of the NoSQL world," automating the manual techniques covered in File 02 of this series. Its underlying exploitation concepts are based on and extend Ming Chow's DEF CON 21 presentation, *"Abusing NoSQL Databases."*

Repository: `github.com/codingo/NoSQLMap` (the actively maintained fork; several older forks of the original `tcstool` repo exist under other GitHub usernames and are largely unmaintained).

NoSQLMap has two fundamentally different attack surfaces, and it's important to keep them separate in your head because they target different things:

1. **NoSQL DB Access Attacks** — directly attacks an exposed, often misconfigured/unauthenticated MongoDB or CouchDB **database server** (default ports 27017 for MongoDB, 5984 for CouchDB), independent of any web application.
2. **NoSQL Web App Attacks** — attacks a **web application's** input parameters for the injection patterns covered in this series (operator injection, JS injection via `$where`, timing-based blind injection), the same way sqlmap attacks a web app's SQL-backed parameters.

For this note series — which is about *web application* NoSQL injection — the Web App Attacks mode is the relevant one, but it's worth understanding the DB Access mode exists, because real-world engagements frequently turn up both issues on the same target (an exposed app *and* a directly reachable, unauthenticated database instance behind it).

---

## 2. Installation

```bash
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
python setup.py install
```

Flag/command breakdown:
- `git clone ...` — pulls the maintained repository locally.
- `python setup.py install` — runs the project's setup script, which installs NoSQLMap's Python dependencies (it's an older-style Python tool, predating widespread `pip install -r requirements.txt` conventions, so expect to troubleshoot dependency versions on a modern Python 3 install — this is a known practical friction point with the tool, covered in §6).

The project also ships a `setup.sh` script for Debian/Red Hat-based systems intended to be run as root, which automates dependency installation, and supports a Docker Compose-based workflow (used in the usage examples in §4) which sidesteps local dependency issues entirely by running the tool inside a container — this is the more reliable installation path on a modern system and is recommended over the raw `setup.py install` route if you hit dependency conflicts.

---

## 3. Core Interface: The Menu-Driven CLI

Unlike sqlmap (which is almost entirely flag-driven for a single invocation), NoSQLMap's primary interface is an **interactive menu-based wizard**, launched with:

```bash
python nosqlmap.py
```

Main menu:
```
1-Set options (do this first)
2-NoSQL DB Access Attacks
3-NoSQL Web App attacks
4-Scan for Anonymous MongoDB Access
x-Exit
```

Breakdown of each option:
- **1 — Set options**: configures the target before anything else runs. You must do this first; the attack modes below depend on this state being populated. Sub-options include setting the target host/IP, the web app port, the URI path (e.g., `/app/acct.php?acctid=102` — the page name and parameters, *not* including the hostname), the HTTP request method, and (if attacking a database directly) your local MongoDB/Meterpreter listener IP and port for cloning data or catching a shell.
- **2 — NoSQL DB Access Attacks**: directly probes/exploits an exposed MongoDB or CouchDB instance — authentication checks against the database's own listener, web management interface, and REST interface.
- **3 — NoSQL Web App attacks**: the mode relevant to this note series — sends crafted injection payloads through application input parameters to detect and exploit operator/JS injection (mirrors sqlmap's role for SQL).
- **4 — Scan for Anonymous MongoDB Access**: given an IP, IP list, or subnet, scans for MongoDB/CouchDB servers listening on their default ports **without authentication enabled at all** — a distinct misconfiguration-discovery feature, not an injection-exploitation feature. This single capability has driven a large share of NoSQLMap's real-world relevance, because unauthenticated, internet-exposed MongoDB instances have been directly responsible for some of the largest data-exposure incidents on record (e.g., the 2019 exposure of over 275 million records from an unsecured MongoDB instance).
- You can also **load previously saved options** (from a prior session) or **import target details directly from a saved Burp Suite request file** — this second option is the most efficient real-world workflow: capture the vulnerable request in Burp, save it, and hand it straight to NoSQLMap instead of manually re-entering every header and parameter into the wizard.

---

## 4. Web App Attack Mode — Flag-Driven (Docker Compose / Scripted) Usage

For scripted or CI-style usage, NoSQLMap also accepts direct command-line flags (most commonly run via the project's provided `docker-compose` setup, which avoids local dependency headaches entirely). A representative invocation:

```bash
docker-compose run --remove-orphans nosqlmap \
  --attack 2 \
  --victim host.docker.internal \
  --webPort 8080 \
  --uri "/userdata.php?usersearch=test" \
  --httpMethod GET \
  --params 1 \
  --injectSize 4 \
  --injectFormat 2 \
  --doTimeAttack n
```

Flag-by-flag breakdown:
- `docker-compose run --remove-orphans nosqlmap` — runs the `nosqlmap` service defined in the project's `docker-compose.yml`, inside a disposable container; `--remove-orphans` cleans up any containers from services no longer defined in the compose file, keeping repeated test runs tidy.
- `--attack 2` — selects attack mode 2, corresponding to the **Web App Attacks** menu option described in §3 (as opposed to mode 1, the direct DB access attacks).
- `--victim host.docker.internal` — the target host. `host.docker.internal` is a special Docker DNS name resolving to the host machine running the container — used here because the vulnerable test app is running on the same machine, outside the container, on a published port.
- `--webPort 8080` — the TCP port the target web application listens on.
- `--uri "/userdata.php?usersearch=test"` — the path and query string of the vulnerable endpoint, including a baseline parameter value (`test`) that NoSQLMap will use as the seed value before mutating it with injection payloads.
- `--httpMethod GET` — specifies the HTTP method to use when sending requests (the tool also supports POST, with parameters supplied separately, e.g., via a saved Burp request).
- `--params 1` — tells NoSQLMap how many parameters in the URI/body should be treated as candidate injection points (here, just the one: `usersearch`).
- `--injectSize 4` — controls the size/complexity tier of the injection payload set NoSQLMap will cycle through; larger values test a broader, more exhaustive set of payload variations at the cost of more requests.
- `--injectFormat 2` — selects which payload *format* family to use (NoSQLMap maintains multiple payload templates — e.g., operator-based JSON object payloads vs. string-breaking JS payloads — `injectFormat` picks which family to run for this attack).
- `--doTimeAttack n` — disables (`n` = no) timing-based blind injection testing for this run. Setting this to `y` instead enables NoSQLMap's automated equivalent of the manual timing techniques from File 02 §6 — useful specifically when response content gives no boolean signal at all.

A second example from the same usage set, explicitly noted by the tool's own documentation as **JavaScript injection** (i.e., targeting the syntax-injection / `$where`-style category from File 01 §3.1, not operator injection):

```bash
docker-compose run --remove-orphans nosqlmap \
  --attack 2 \
  --victim host.docker.internal \
  --webPort 8080 \
  --uri "/orderdata.php?ordersearch=test" \
  --httpMethod GET \
  --params 1 \
  --injectSize 4 \
  --injectFormat 2 \
  --doTimeAttack n
```

Same flag meanings as above, applied to a different vulnerable endpoint — illustrating that real-world usage is just re-running the same flag template against every candidate parameter on every endpoint you've identified, exactly the way you'd loop sqlmap across multiple parameters.

---

## 5. What NoSQLMap Automates (Mapped Back to File 02's Manual Techniques)

| Manual technique (File 02) | NoSQLMap automation equivalent |
|---|---|
| Multi-context fuzz string + quote isolation (§1.2) | Automated error-based detection sweep across payload templates |
| `$ne`/`$gt`/`$in` auth bypass testing (§2) | Automated operator-injection payload set tried across all designated parameters |
| Boolean true/false response-diff extraction (§3.2) | Boolean-based blind detection logic comparing response content/length across payload variants |
| `$where` JS injection confirmation (§4.1) | JavaScript-injection payload family (selected via `--injectFormat`) |
| Timing-based busy-wait/`sleep()` extraction (§6) | `--doTimeAttack y` — automated timing-delta measurement across repeated requests |
| Manual unauthenticated-MongoDB discovery | Menu option 4 — automated subnet/IP-range scan for anonymous MongoDB/CouchDB access |
| Manual database enumeration and dumping once access is confirmed | DB Access Attacks mode (menu option 2) — can enumerate, clone, or exfiltrate an entire reachable database, and in older/unpatched MongoDB versions (2.2.3 and earlier) includes a path to a Metasploit module for remote code execution |

---

## 6. Honest Limitations Compared to sqlmap

This is the section that matters most for setting realistic expectations. NoSQLMap is a useful tool, but it is **not** at the same level of engineering maturity, payload sophistication, or active development as sqlmap, and you should plan your testing workflow accordingly.

1. **Maintenance and update cadence.** sqlmap has had continuous, heavily-resourced, near-daily development for over a decade, with constant additions for new DBMS versions, WAF bypass techniques, and tamper scripts. NoSQLMap's development has been comparatively sporadic — long gaps between releases are common, and the tool's last major wave of active commits significantly predates sqlmap's current pace. Don't assume NoSQLMap reflects the current state of NoSQL injection research the way sqlmap reflects current SQLi research; it often lags behind manual technique discovery (such as the `Object.keys()`-based blind field enumeration covered in File 02 §4, which is exactly the kind of advanced technique you should expect to need to run manually, because automation coverage for it is inconsistent).

2. **Database coverage is narrow.** sqlmap supports essentially every major SQL dialect (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and many more) with dialect-specific payload tuning for each. NoSQLMap's exploitation logic is focused almost entirely on **MongoDB**, with secondary support for **CouchDB**; broader NoSQL ecosystem support (Cassandra, Redis, etc., which the project's own documentation lists as aspirational "planned for future releases") has never materialized to a comparable depth. If you're testing a non-MongoDB NoSQL backend, NoSQLMap is largely not the right tool.

3. **No mature tamper-script / WAF-bypass ecosystem.** One of sqlmap's most valuable real-world features is its large library of `--tamper` scripts for obfuscating payloads past WAFs and input filters (case randomization, comment injection, encoding tricks, etc.), which is actively maintained and extended by the community. NoSQLMap has no comparable, actively-maintained tamper-script ecosystem. When you hit filtering or sanitization (File 03), you will very likely be hand-crafting the bypass yourself rather than reaching for a built-in flag — NoSQLMap's payload format selection (`--injectFormat`) gives you a handful of payload *families*, not a rich obfuscation pipeline.

4. **Detection heuristics are comparatively unsophisticated and prone to false positives/negatives.** sqlmap's boolean/blind detection logic has been refined over many years against an enormous range of real applications. Independent tool reviews of MongoDB-focused alternatives in this space (e.g., the `mongomap` tool, built explicitly because its author found existing detection tooling "skimpy and prone to false positives") echo a broader, recurring community observation: automated NoSQL injection detection in general is less mature than SQLi detection tooling, and manual verification of any automated finding is essential before you trust it in a report. Don't take a NoSQLMap "vulnerable" verdict as final without manually reproducing it using the techniques in File 02 — and conversely, don't take a "not vulnerable" result as conclusive, since the tool can miss operator-injection variants it wasn't specifically built to test (e.g., it has no concept of the operator-allowlist-gap or framework-specific bracket-notation parsing quirks covered in File 03).

5. **Smaller, less battle-tested codebase overall.** sqlmap is one of the most thoroughly used and hardened security tools in existence, run against an enormous diversity of real targets daily. NoSQLMap has a far smaller user base and correspondingly less real-world hardening — expect more edge cases, more manual troubleshooting of dependency/environment issues (see §2), and more situations where you need to read the tool's source to understand exactly what payload it's sending, rather than trusting its abstraction layer the way most testers trust sqlmap's.

6. **POST-request support has historically been more limited than GET.** Several of NoSQLMap's own usage examples and documentation snapshots note that POST request handling (versus GET) has lagged in completeness across versions, often requiring you to import a saved Burp Suite POST request rather than constructing POST parameters purely from CLI flags. Since most real-world operator-injection auth bypass targets (login endpoints) are POST-based JSON bodies, this is a meaningful practical friction point — the Burp-import workflow (menu option in §3) is the recommended path for these targets rather than fighting with flag-driven POST construction.

### Bottom line

Use NoSQLMap as a **fast first-pass scanner** — especially its anonymous-MongoDB-discovery mode (menu option 4), which has no real manual equivalent in terms of speed across a large IP range — and as a convenience wrapper for re-running known payload families across many parameters quickly. Do **not** treat it as a substitute for the manual, mechanism-level techniques in File 02 and File 03. Every serious finding should be manually reproduced and the *mechanism* explained in your report, the same discipline you already apply to sqlmap output.

---

## 7. Alternative / Complementary Tools Worth Knowing

Since NoSQLMap's limitations are real, it's worth knowing the rest of the (thin) NoSQL automation landscape:

- **`nosqli`** (Go, by Charlie Belmer) — a simpler, single-purpose CLI focused specifically on MongoDB injection *detection* (error-based, boolean-blind, and timing-based scans), not full exploitation/dumping. Lighter weight than NoSQLMap and useful as a quick triage tool; supports loading a raw request file (from Burp/ZAP) the same way NoSQLMap does.
- **`mongomap`** — a smaller, more recently written tool explicitly modeled on sqlmap's UX for MongoDB specifically, supporting both the bracket-notation (`username[$ne]=a`) and JSON-body operator-injection payload styles, with a `--dump` post-detection mode. Its own documentation candidly states it was built partly because existing tooling's difference-detection (false-positive handling) needed improvement — a useful confirmation of the broader maturity gap described in §6.

In practice, the right move on a real engagement is to run a quick automated pass with one or more of these tools for coverage and speed, then fall back to fully manual exploitation (File 02) for anything that needs precision, anything blocked by filtering (File 03), or anything the automated tools weren't built to detect at all (the `Object.keys()` blind field-enumeration technique in particular has no reliable automated equivalent in any of the tools above as of this writing).

Continue to `05_Cheatsheet.md` for a compressed, fast-reference version of this entire series.
