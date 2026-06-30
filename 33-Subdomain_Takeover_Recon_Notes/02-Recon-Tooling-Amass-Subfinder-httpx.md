# 02 — Recon Tooling: Amass, Subfinder, and httpx

## Stage Overview

This file covers the tooling for Stage 1 of the pipeline: building the largest possible,
most accurate list of subdomains for a target, then confirming which of those subdomains
are actually alive. Three tools, three roles:

- **Subfinder** — fast, passive-only subdomain discovery from dozens of OSINT sources.
  Your first pass, every time.
- **Amass** — deeper passive discovery plus active DNS brute-forcing, permutation, and
  relationship mapping (ASNs, related domains). Slower, more thorough, used as a
  second pass to catch what Subfinder misses.
- **httpx** — takes the raw subdomain list from both tools and tells you which hosts are
  actually alive, what they're running, and what their HTTP behavior looks like — turning
  a list of names into a list of real targets.

The standard workflow chains all three: Subfinder + Amass for discovery → merge and
deduplicate → httpx for liveness and fingerprinting.

## Part 1 — Passive Recon Theory

### Certificate Transparency (CT) Logs

Every publicly trusted TLS certificate issued since roughly 2018 is logged in public,
append-only Certificate Transparency logs (mandated by major browsers as a condition of
trusting the certificate authority that issued it). Because a certificate's Subject
Alternative Name (SAN) field lists every hostname it covers, searching CT logs for a
domain reveals every subdomain that has ever had a certificate issued for it — including
subdomains for internal tools, staging environments, and forgotten infrastructure that
were never meant to be publicly discoverable, but show up in CT logs the moment Let's
Encrypt or any other CA issues them a certificate.

This is why CT logs are the single highest-value passive recon source: the organization
itself generated this data by requesting certificates, and it cannot be retroactively
hidden once published to an append-only log. Both Subfinder and Amass query CT log
aggregators (such as crt.sh, which indexes Certificate Transparency log data) as part of
their default passive source list.

### DNS Aggregator APIs

Services like SecurityTrails, VirusTotal, Censys, and Shodan continuously crawl and index
DNS records, historical resolution data, and passive DNS data collected from sensors
across the internet. Querying these APIs (most require a free or paid API key) surfaces
subdomains that may not currently resolve but did at some point — which is exactly the
kind of stale, forgotten record that subdomain takeover targets.

### Active Brute-Forcing

Passive sources only reveal what has already been publicly indexed somewhere. Active
brute-forcing tests a wordlist of common subdomain names (`dev`, `staging`, `api`,
`admin`, `vpn`, `test`, and thousands more) against the target's DNS servers directly,
catching subdomains that have never appeared in a certificate or any public index. This
is slower, generates DNS query traffic the target's monitoring may see, and is the
reason brute-forcing is generally run as a second pass after passive sources have been
exhausted, using a focused or curated wordlist rather than a massive one to keep noise
and runtime manageable.

---

## Part 2 — Subfinder, Flag by Flag

Subfinder is purely passive by design — it has no brute-force mode, which makes it fast,
quiet, and the correct first tool to run against any new target.

```
subfinder -d example.com -all -recursive -o subfinder.txt
```

- **`-d example.com`** — Specifies the target root domain to enumerate. This is the only
  required flag.
- **`-all`** — Uses all configured sources, including slower ones that are excluded by
  default for speed. Worth using when thoroughness matters more than runtime (i.e., a
  one-time deep scan rather than a daily monitoring run).
- **`-recursive`** — Runs sources that are themselves capable of recursive subdomain
  discovery (finding subdomains of subdomains), which surfaces deeper infrastructure
  like `internal.dev.api.example.com`.
- **`-o subfinder.txt`** — Writes discovered subdomains, one per line, to the specified
  output file instead of only printing to stdout.

### Additional flags used regularly

- **`-dL domains.txt`** — Reads a list of target domains from a file instead of a single
  `-d` value, for enumerating multiple root domains (e.g., all domains in a bug bounty
  program's scope) in one run.
- **`-oJ subfinder.json`** — Outputs results in JSON format instead of plain text,
  useful when results need to be parsed programmatically rather than just read.
- **`-silent`** — Suppresses the banner and status output, printing only the discovered
  subdomain names. Essential when piping Subfinder's output directly into another tool.
- **`-s crtsh,virustotal`** — Restricts the scan to specific named sources instead of the
  full default list, useful for narrowing to sources you have API keys configured for.
- **`-rl 10`** — Sets the rate limit (requests per second) for the overall scan, used to
  avoid tripping rate limits on free-tier API sources.
- **`-rls source=2/m`** — Sets a per-source rate limit (e.g., 2 requests per minute for a
  specific named source), used when one particular source is rate-limiting aggressively
  while others can run faster.
- **`-t 50`** — Sets the number of concurrent threads used during enumeration, trading
  speed against the risk of overwhelming local resources or tripping target-side
  monitoring.
- **`-timeout 30`** — Sets the timeout in seconds for each individual source query,
  preventing one slow or unresponsive source from stalling the entire scan.
- **`-config config.yaml`** — Points Subfinder at a configuration file containing API
  keys for paid sources (SecurityTrails, Censys, Shodan, etc.), which substantially
  increases the number of subdomains discovered compared to unauthenticated source access.
- **`-resolvers resolvers.txt`** — Supplies a custom list of DNS resolvers to use for
  the resolution step, useful for avoiding rate limits on default public resolvers
  during large scans.

### Real-World Example

```
subfinder -dL scope.txt -all -recursive -silent -o subfinder_results.txt
```

A realistic first command run against an entire bug bounty program's in-scope domain
list (`scope.txt`), using all sources, recursive discovery, and silent output piped
straight to a results file — the standard opening move for a new target.

---

## Part 3 — Amass, Flag by Flag

Amass is heavier than Subfinder: it combines passive sources with active DNS
brute-forcing, permutation/alteration of discovered names, and relationship mapping via
ASN and WHOIS data. It is run as a thorough second pass, not a quick first look.

> **Version note:** Amass has changed command structure across major versions. The
> commands below follow the widely-used `amass enum` subcommand structure (OWASP Amass
> v3/v4). Always confirm with `amass -h` and `amass --version` against the installed
> binary before relying on flag behavior, since newer major versions have introduced
> additional subcommands (`amass subs`, `amass track`, `amass viz`) alongside `enum`.

### Passive Pass

```
amass enum -passive -d example.com -o amass_passive.txt
```

- **`enum`** — The subcommand that performs subdomain enumeration (as opposed to
  `intel`, which is used for organization-level reconnaissance like finding additional
  root domains via reverse WHOIS).
- **`-passive`** — Restricts the run to OSINT data sources only, with no direct DNS
  queries sent to the target's infrastructure. This is the quiet, non-intrusive mode —
  appropriate as a first Amass pass even before considering active techniques.
- **`-d example.com`** — Specifies the target root domain.
- **`-o amass_passive.txt`** — Writes discovered names to the specified output file.

### Active Pass with Brute-Forcing

```
amass enum -active -brute -d example.com -w subdomains-top1million.txt -o amass_active.txt
```

- **`-active`** — Enables active techniques: direct DNS resolution to validate findings,
  certificate name grabs against discovered hosts, and (if combined with other flags)
  zone transfer attempts. This sends traffic directly to the target's DNS
  infrastructure and reveals your IP address to them, unlike passive mode.
- **`-brute`** — Enables DNS brute-forcing using a wordlist, testing each word as a
  candidate subdomain label and checking whether it resolves.
- **`-w subdomains-top1million.txt`** — Specifies the wordlist used for brute-forcing.
  SecLists' `Discovery/DNS/subdomains-top1million-*.txt` files are the standard choice;
  smaller, curated lists are preferable when speed and stealth matter more than maximum
  coverage.
- **`-o amass_active.txt`** — Output file for this pass.

### Additional flags used regularly

- **`-df domains.txt`** — Reads multiple root domains from a file, equivalent in purpose
  to Subfinder's `-dL`.
- **`-rf resolvers.txt`** — Specifies a custom list of DNS resolvers, used to bypass
  rate-limiting on public resolvers and increase resolution throughput during large
  brute-force runs.
- **`-config config.yaml`** — Loads a configuration file containing API keys for premium
  passive sources (SecurityTrails, Censys, Shodan), substantially expanding passive
  coverage the same way it does for Subfinder.
- **`-dir ./project_output`** — Sets the directory where Amass stores its output files,
  logs, and its local graph database. Amass remembers prior enumeration results in this
  database and uses them to inform future runs against the same target.
- **`-oA results_prefix`** — Outputs results in all available formats (plain text, JSON,
  and graph) using the given filename prefix, useful when results will be both read
  directly and parsed or visualized later.
- **`-log amass.log`** — Writes verbose status, debug, and troubleshooting information
  to a log file during the run, useful for diagnosing why a particular source returned
  nothing or a brute-force pass behaved unexpectedly.
- **`-min-for-recursive 2`** — Requires a subdomain pattern to be observed at least
  twice before Amass attempts recursive brute-forcing on it, which reduces wasted
  effort recursing into one-off or noisy patterns.
- **`-timeout 60`** — Sets a timeout in minutes for the overall enumeration run,
  preventing an unbounded scan against a very large scope from running indefinitely.

### Real-World Example

```
amass enum -active -brute -d example.com \
  -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -rf resolvers.txt \
  -config config.yaml \
  -dir ./recon/example_com \
  -oA ./recon/example_com/amass
```

A realistic deep second pass: active mode with brute-forcing, a curated 5,000-word
list (not the full million — runtime and noise tradeoff), custom resolvers to avoid
rate-limiting, API keys loaded for premium passive sources, and output stored in a
per-target project directory for later reference.

### Merging Subfinder and Amass Output

```
cat subfinder.txt amass_passive.txt amass_active.txt | sort -u > all_subdomains.txt
```

- **`cat ... | sort -u`** — Concatenates all three result files, sorts the combined list
  alphabetically, and `-u` removes exact duplicate lines, producing one clean,
  deduplicated master list of every subdomain discovered across both tools and both
  Amass passes.

---

## Part 4 — httpx, Flag by Flag

A list of subdomain names is not yet a list of targets — many will not resolve, many
will resolve but have nothing listening, and many will be redirects or dead infrastructure.
httpx takes the raw name list and probes each one over HTTP/HTTPS to determine what's
actually alive and worth investigating.

```
httpx -l all_subdomains.txt -sc -title -tech-detect -o httpx_results.txt
```

- **`-l all_subdomains.txt`** — Specifies the input file containing the list of
  hostnames to probe, one per line (the merged output from Subfinder and Amass).
- **`-sc`** — Includes the HTTP status code of each response in the output, letting you
  immediately distinguish live (200/30x) hosts from errors (40x/50x) at a glance.
- **`-title`** — Extracts and includes the HTML `<title>` tag from each response,
  giving a quick human-readable hint about what's running on each host without opening
  a browser.
- **`-tech-detect`** — Runs Wappalyzer-style technology fingerprinting against each
  response (matching response headers, cookies, and page content against known
  signatures) and includes detected technologies (web server, CMS, JS framework,
  analytics, etc.) in the output.
- **`-o httpx_results.txt`** — Writes the full result set to the specified output file.

### Additional flags used regularly

- **`-sc -cl -title -server -tech-detect -ip -cname`** — A common combined flag set
  pulling status code, content length, page title, server header, detected technology,
  resolved IP, and CNAME record for each host into a single dense output line —
  effectively a one-pass reconnaissance summary per host.
- **`-cname`** — Includes the resolved CNAME record for each hostname in the output.
  This flag is specifically important for subdomain takeover hunting (covered in
  `03-Subdomain-Takeover-Exploitation.md`) because it is the fastest way to extract
  every CNAME target across thousands of hosts for fingerprint matching in one pass.
- **`-mc 200,301,302`** — Filters output to only hosts matching the specified status
  codes (match-code), useful for filtering down to "interesting" live hosts and
  excluding pure 404/error noise.
- **`-fc 404`** — The inverse of `-mc`: filters out (filter-code) hosts matching the
  specified status codes, useful for excluding a known-noisy error response pattern.
- **`-threads 100`** — Sets the number of concurrent probing threads, trading scan
  speed against network and target load.
- **`-timeout 10`** — Sets the per-request timeout in seconds, preventing slow or
  unresponsive hosts from stalling the overall scan.
- **`-follow-redirects`** — Follows HTTP redirects rather than just recording the
  initial response, useful for seeing where a host ultimately resolves to (relevant
  when chasing down a chain that ends at an unclaimed cloud resource).
- **`-json`** — Outputs results as JSON Lines instead of plain text, the correct format
  when results will be parsed programmatically for further automation (e.g., feeding
  into a takeover-checking script).
- **`-silent`** — Suppresses the banner and non-result output, printing clean result
  lines only — used when piping httpx output into another tool.
- **`-probe`** — Displays which protocol (http or https) successfully responded for
  each host, useful when a host responds differently or only on one of the two.

### Real-World Example

```
httpx -l all_subdomains.txt -sc -title -tech-detect -cname -ip \
  -mc 200,301,302,403 -threads 100 -timeout 10 -silent -json -o httpx_results.json
```

A realistic liveness and fingerprinting pass over the full merged subdomain list:
status code, title, technology detection, CNAME, and resolved IP for each host;
filtered to interesting status codes; JSON output for downstream automation
(specifically, feeding the CNAME field into the takeover-fingerprint matching process
covered in the next file).

---

## Real-World Notes

- A single domain in a bug bounty program can easily expand into thousands of
  subdomains once passive sources, brute-forcing, and permutation are all combined —
  the bottleneck shifts from "finding subdomains" to "triaging which of these thousands
  are actually worth investigating," which is exactly what httpx's fingerprinting flags
  are for.
- Running Subfinder first, then Amass as a slower second pass, is the standard ordering
  in professional bug bounty workflows: get fast, low-noise coverage immediately, then
  spend the extra time budget on Amass's deeper (and noisier) techniques.
- API keys matter more than people expect. An unauthenticated Subfinder or Amass run
  against a large target will typically surface a fraction of what the same run finds
  with SecurityTrails, Censys, and Shodan keys configured — free tiers on these
  services are usually sufficient to meaningfully improve coverage.
- Re-running this entire pipeline on a schedule (daily or weekly) against active bug
  bounty scope and diffing against the previous run's subdomain list is how serious
  hunters catch newly deployed, often misconfigured infrastructure within hours of it
  going live — which matters enormously for subdomain takeover specifically, since the
  unclaimed window is often short.
