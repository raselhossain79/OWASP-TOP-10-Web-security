# 04 — Content Discovery: ffuf and gobuster

## Stage Overview

This file covers Stage 3 of the pipeline: for subdomains confirmed alive by httpx (file
02), going beyond "what subdomains exist" to "what does this specific application
actually expose" — technology stack, hidden directories and files, exposed API
endpoints, and parameters that accept input. This is general attack surface mapping
applied per-host rather than across the whole domain.

## Part 1 — Technology Stack Identification

Before brute-forcing content, identify what's actually running. This shapes every
subsequent decision — the wordlist you choose, the file extensions worth testing, and
which vulnerability classes are even plausible.

### Passive Identification (already partially covered by httpx)

httpx's `-tech-detect` flag (covered in file 02) fingerprints technology from response
headers, cookies, and page content automatically as part of the liveness pass. This is
the first signal and requires no extra requests.

### Manual / Targeted Identification

- **HTTP response headers** — `Server`, `X-Powered-By`, `X-AspNet-Version`, and similar
  headers often directly name the web server or framework in use.
- **Cookie names** — framework-default cookie names are strong signals: `PHPSESSID`
  (PHP), `JSESSIONID` (Java/Tomcat), `ASP.NET_SessionId` (ASP.NET), `laravel_session`
  (Laravel), `_django_session` or `csrftoken` (Django), `connect.sid` (Express/Node).
- **Error pages** — a default framework error page (a Django debug page, a Laravel
  "Whoops" page, an IIS default error) directly reveals the stack and sometimes the
  exact version, and can leak file paths or stack traces useful for later stages.
- **`robots.txt` and `sitemap.xml`** — frequently disclose paths the organization
  considers sensitive enough to ask crawlers not to index, which is itself a strong hint
  about where to look first (an entry like `Disallow: /admin-panel/` is a direct pointer).
- **JavaScript bundle inspection** — modern single-page applications ship their entire
  client-side routing and API endpoint structure in JavaScript bundles. Fetching and
  reading (or grepping) the main JS bundle for API paths, route definitions, and
  hardcoded URLs frequently reveals endpoints that no link on the rendered page points to.

---

## Part 2 — ffuf, Flag by Flag

ffuf ("Fuzz Faster U Fool") is a fast, flexible fuzzing tool used for directory/file
discovery, virtual host discovery, and parameter discovery — anywhere a wordlist needs
to be substituted into a request and responses compared.

### Directory and File Discovery

```
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -o ffuf_results.json
```

- **`-u https://target.com/FUZZ`** — Specifies the target URL with the literal string
  `FUZZ` marking the injection point where each wordlist entry will be substituted.
- **`-w wordlist.txt`** — Specifies the wordlist file to use, one candidate per line.
- **`-mc 200,301,302,403`** — Match-code filter: only displays results whose HTTP status
  code is in this list. 403 is included deliberately — a "Forbidden" response often
  means a real resource exists but access is restricted, which is itself valuable
  information (and sometimes bypassable).
- **`-o ffuf_results.json`** — Writes results to the specified output file (format
  inferred from extension, or set explicitly with `-of`).

### Additional flags used regularly

- **`-X POST`** — Sets the HTTP method for the fuzzed request, used when fuzzing
  POST-only endpoints rather than the default GET.
- **`-d "param=FUZZ"`** — Sets the request body, with `FUZZ` placed inside it instead of
  the URL — used for fuzzing POST body parameters or values.
- **`-H "Header: value"`** — Adds a custom header to every request, commonly used for
  authentication tokens, custom `Host` headers (for virtual host fuzzing, see below), or
  injecting `FUZZ` into a header value for header-based fuzzing.
- **`-fc 404`** — Filter-code: excludes responses with the specified status code(s),
  the inverse of `-mc`, useful when a wildcard or catch-all route returns one consistent
  noise status you want suppressed.
- **`-fs 0`** — Filter-size: excludes responses of a specific byte size, used when a
  "not found" page returns 200 OK but with a consistent, identifiable response size —
  a common pattern that defeats naive status-code-only filtering.
- **`-fw 10`** — Filter-words: excludes responses with a specific word count in the
  body, an alternative noise filter to `-fs` for catch-all pages with variable byte
  size but consistent word count.
- **`-fr "regex"`** — Filter-regex: excludes responses whose body matches the given
  regular expression, used for filtering out a catch-all error page that has a
  recognizable text pattern but inconsistent size or status.
- **`-recursion -recursion-depth 2`** — Enables recursive fuzzing: when a discovered
  result is itself a directory, ffuf automatically fuzzes inside it, up to the specified
  depth. Powerful but multiplies request volume quickly, so depth should be kept low.
- **`-t 100`** — Sets the number of concurrent threads, trading scan speed against
  network load and the risk of tripping rate-limiting or WAF blocking.
- **`-rate 50`** — Caps the request rate (requests per second) regardless of thread
  count, used for deliberately throttling scans against rate-limit-sensitive or
  WAF-protected targets to stay under detection thresholds.
- **`-e .php,.bak,.old,.zip`** — Appends each listed extension to every wordlist entry
  in turn, used for discovering backup files, source files, or archives left behind
  alongside legitimate application files (e.g., `config.php.bak` next to `config.php`).
- **`-ac`** — Auto-calibration: ffuf sends a few baseline requests for nonsense paths
  first and automatically derives filtering rules from the responses, useful as a
  faster alternative to manually tuning `-fs`/`-fw`/`-fc` against a target you haven't
  profiled yet.
- **`-mode clusterbomb`** (with multiple `FUZZ` keywords, e.g. `FUZZ1`/`FUZZ2`) — Sets
  the fuzzing mode when multiple wordlists and multiple injection points are used
  together; clusterbomb mode tries every combination of both wordlists rather than
  pairing them line-by-line (which `pitchfork` mode does instead).

### Virtual Host (vhost) Discovery

```
ffuf -u https://target.com/ -H "Host: FUZZ.target.com" -w subdomains.txt -fs 4242
```

- **`-H "Host: FUZZ.target.com"`** — Injects the fuzzed value into the `Host` header
  rather than the URL path, while the actual request still goes to the target's IP.
  This discovers virtual hosts configured on the same server that may not have a public
  DNS record at all but are still reachable if you know (or guess) the right `Host`
  header value.
- **`-fs 4242`** — Filters out the byte size of the default/catch-all virtual host
  response, so only `Host` values that produce a genuinely different response (a real,
  distinct vhost) are shown.

### Parameter Discovery

```
ffuf -u "https://target.com/api/endpoint?FUZZ=value" -w params.txt -fs 1234
```

- **`-u "https://target.com/api/endpoint?FUZZ=value"`** — Places `FUZZ` in the
  parameter name position rather than the path, testing whether each candidate
  parameter name from the wordlist is recognized and processed by the endpoint
  (typically detected by a response size, status, or content change versus an unknown
  parameter being silently ignored).
- **`-fs 1234`** — Filters out the baseline response size for an unrecognized
  parameter, surfacing only parameter names that cause a measurably different response —
  meaning the application is actually reading and using that parameter name.

### Real-World Example

```
ffuf -u https://target.com/FUZZ -w SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -e .php,.json,.bak -mc 200,301,302,403 -fs 0 -recursion -recursion-depth 2 \
  -t 50 -ac -o ffuf_target_results.json -of json
```

A realistic content discovery pass: a medium-sized curated wordlist, common backend
extensions appended, interesting status codes matched, empty/zero-size noise filtered,
recursive discovery to two levels deep, auto-calibration to handle any catch-all
response patterns automatically, and JSON output for later parsing.

---

## Part 3 — gobuster, Flag by Flag

gobuster is a simpler, more single-purpose alternative to ffuf — faster to reach for
when you just need straightforward directory, DNS, or vhost brute-forcing without ffuf's
more flexible filtering and multi-point fuzzing capabilities.

### Directory and File Discovery (`dir` mode)

```
gobuster dir -u https://target.com -w wordlist.txt -x php,bak,zip -o gobuster_results.txt
```

- **`dir`** — Selects gobuster's directory/file brute-forcing mode.
- **`-u https://target.com`** — Specifies the target base URL.
- **`-w wordlist.txt`** — Specifies the wordlist file to use.
- **`-x php,bak,zip`** — Appends each listed extension (comma-separated, no leading
  dot) to every wordlist entry, the gobuster equivalent of ffuf's `-e` flag.
- **`-o gobuster_results.txt`** — Writes results to the specified output file.

### Additional `dir` mode flags used regularly

- **`-s 200,301,302,403`** — Status codes to include (the inverse default behavior from
  ffuf's match/filter pattern — gobuster's `-s` is an explicit allow-list).
- **`-b 404`** — Status codes to exclude (blacklist); commonly left at the gobuster
  default which already excludes 404, but adjustable when a target returns a different
  "not found" status.
- **`-t 50`** — Sets the number of concurrent threads.
- **`-k`** — Skips TLS certificate verification, used when the target presents a
  self-signed or otherwise invalid certificate that would normally abort the connection.
- **`-r`** — Follows redirects rather than just recording the redirect response, useful
  when discovered paths commonly redirect somewhere informative.
- **`-c "session=value"`** — Sets a cookie header for every request, used when content
  discovery needs to happen in an authenticated session context.
- **`-H "Header: value"`** — Adds a custom header to every request, the same authentication
  or custom-header use case as ffuf's equivalent flag.
- **`--wildcard`** — Forces gobuster to continue even when it detects what looks like a
  wildcard response (a server that returns 200 for literally any path), which gobuster
  otherwise aborts on by default to avoid producing meaningless results.
- **`-l`** — Includes the response length in output for each result, a quick way to
  manually spot a catch-all wildcard pattern by its repeated identical size, similar in
  purpose to ffuf's `-fs` filtering but presented for manual review rather than
  automatically filtered.

### DNS Subdomain Brute-Forcing (`dns` mode)

```
gobuster dns -d target.com -w subdomains.txt -o gobuster_dns.txt
```

- **`dns`** — Selects gobuster's DNS subdomain brute-forcing mode, functionally
  overlapping with Amass's `-brute` mode from file 02, useful as a quick standalone
  check or cross-validation against Amass's brute-force results.
- **`-d target.com`** — Specifies the target root domain.
- **`-w subdomains.txt`** — Specifies the subdomain wordlist.

### Virtual Host Discovery (`vhost` mode)

```
gobuster vhost -u https://target.com -w subdomains.txt --append-domain
```

- **`vhost`** — Selects gobuster's virtual host discovery mode, functionally
  equivalent to the ffuf `Host` header fuzzing technique shown above but purpose-built
  for it.
- **`--append-domain`** — Automatically appends the target domain to each wordlist
  entry when constructing the `Host` header value being tested, so a plain wordlist of
  short names (`dev`, `staging`, `internal`) is automatically expanded to
  `dev.target.com`, `staging.target.com`, etc.

### Real-World Example

```
gobuster dir -u https://target.com -w SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,json,bak -s 200,301,302,403 -t 50 -r -o gobuster_target_results.txt
```

A standard directory discovery pass: curated medium wordlist, common extensions
appended, interesting status codes allow-listed, redirects followed, results saved to
file — the gobuster equivalent of the ffuf real-world example above, useful as a quick
cross-check tool when ffuf's more advanced filtering isn't needed.

---

## ffuf vs. gobuster — When to Use Which

- **gobuster** is faster to set up for a straightforward single-purpose scan (directory,
  DNS, or vhost) and has a simpler, more memorable flag set for quick use during a live
  engagement.
- **ffuf** is the better choice when filtering matters — auto-calibration, multi-point
  fuzzing (path + header + body simultaneously), and fine-grained response filtering
  (`-fs`/`-fw`/`-fc`/`-fr`) handle noisy targets (wildcard responses, inconsistent
  catch-all pages) far better than gobuster's simpler allow/block-list status filtering.
- In practice, most experienced hunters default to ffuf for anything beyond a trivial
  scan and reach for gobuster mainly for quick DNS brute-forcing or when ffuf's full
  flag set is unnecessary overhead for a simple check.

---

## Real-World Notes

- Wordlist choice matters more than tool choice. SecLists' `raft-*` and `directory-list-*`
  series under `Discovery/Web-Content/` are the de facto standard starting points;
  technology-specific wordlists (e.g., a WordPress-specific or Laravel-specific list)
  produce dramatically better signal-to-noise once the stack is identified via Part 1.
- Always profile the target's "not found" behavior before trusting raw status codes.
  Many modern applications return `200 OK` with a custom "page not found" body instead
  of a proper `404`, which silently defeats naive `-mc 200` matching unless paired with
  size/word/regex filtering (`-fs`/`-fw`/`-fr` in ffuf, or careful manual review with
  gobuster's `-l`).
- Rate limiting and WAF detection are a real operational concern on live bug bounty
  targets — an aggressive, high-thread content discovery scan is one of the most likely
  actions to get an attacking IP blocked mid-engagement. Starting conservative
  (`-rate`/`-t` set low) and only increasing once you've confirmed the target tolerates
  it is standard practice, not excessive caution.
- Content discovery results feed directly back into Stage 1 — discovered JavaScript
  bundles, API documentation paths, or configuration files frequently reveal additional
  subdomains or internal hostnames that didn't surface in the original passive/active
  recon pass, which is why this pipeline is iterative rather than strictly linear in
  live engagements (as noted in file 01).
