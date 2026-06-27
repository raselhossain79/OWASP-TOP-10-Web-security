# 08 — Nikto: General Misconfiguration Scanning (Full Flag Breakdown)

## What Nikto is and why it belongs in this series

Nikto is an open-source web server scanner that checks a target against a large, continuously
updated database of known misconfiguration indicators: outdated server software, dangerous
default files, exposed sample/test scripts, missing security headers, directory listing,
and thousands of specific known-vulnerable file paths. It does not exploit anything — it is a
**reconnaissance and triage tool**, which is exactly why it's included here as the dedicated
"general misconfiguration scanning" tool for this series: it automates checks across nearly
every sub-category covered in files `02` through `06` in a single pass, and is the standard
first-pass tool industry pentesters run before manual verification.

## Installation

```bash
sudo apt install nikto -y
```

- `sudo apt install nikto` — installs Nikto from the Debian/Kali package repositories (it's
  pre-installed on Kali by default in most images, but this is the install command if it's
  missing).
- `-y` — automatically answers "yes" to the package manager's confirmation prompt.

## Basic scan command

```bash
nikto -h https://target.example.com
```

- `nikto` — invokes the tool.
- `-h https://target.example.com` — `-h` (host) specifies the target. Despite the flag name
  looking like "help," in Nikto's argument syntax `-h` / `-host` is the target specification
  flag; Nikto's actual help flag is `-Help`.

## Full flag-by-flag breakdown of a real engagement command

```bash
nikto -h https://target.example.com -p 443 -ssl -Tuning 123456789ab \
  -Plugins "@@ALL" -timeout 10 -maxtime 20m -Format htm -o nikto_report.html \
  -useragent "Mozilla/5.0 (compatible; AuthorizedPentest)"
```

- `-h https://target.example.com` — the target host/URL, as above.
- `-p 443` — explicitly specifies the **port** to scan. Useful when scanning a non-default port
  (e.g., an internal admin interface running on `8443` or `8080`) or when you want to be explicit
  rather than relying on Nikto's default port inference from the URL scheme.
- `-ssl` — forces Nikto to use SSL/TLS for the connection. This is mostly needed when scanning by
  IP+port rather than by a full `https://` URL, where Nikto might not otherwise infer that TLS is
  required.
- `-Tuning 123456789ab` — restricts which **categories of checks** Nikto runs, using Nikto's
  single-character tuning codes. Each character maps to a category:
  - `1` = Interesting File/Seen in logs
  - `2` = Misconfiguration/Default File
  - `3` = Information Disclosure
  - `4` = Injection (XSS/Script/HTML)
  - `5` = Remote File Retrieval (Inside Web Root)
  - `6` = Denial of Service
  - `7` = Remote File Retrieval (Server Wide)
  - `8` = Command Execution/Remote Shell
  - `9` = SQL Injection
  - `a` = Authentication Bypass
  - `b` = Software Identification
  - `c` = Remote Source Inclusion
  
  Supplying `123456789ab` runs all of these categories explicitly (you could instead supply just
  `23b` to focus purely on misconfiguration, info disclosure, and software ID checks if you want
  a faster, more targeted run for this series' specific scope).
- `-Plugins "@@ALL"` — tells Nikto to run every available scanning plugin (covering things like
  header analysis, cookie analysis, and outdated software detection modules) rather than a subset.
- `-timeout 10` — sets the per-request timeout to 10 seconds, preventing the scan from hanging
  indefinitely on a slow or unresponsive endpoint.
- `-maxtime 20m` — caps the **total scan duration** at 20 minutes; Nikto will stop issuing new
  checks once this time budget is exhausted, which is useful for keeping a scan within an
  agreed engagement testing window.
- `-Format htm` — sets the output report format to HTML (other options include `csv`, `txt`,
  `xml`, `nbe`, `sql`).
- `-o nikto_report.html` — the output file path to write the report to, matching the format
  specified by `-Format`.
- `-useragent "Mozilla/5.0 (compatible; AuthorizedPentest)"` — overrides the `User-Agent` header
  Nikto sends. This matters for two reasons: (1) some WAFs/IDS rules specifically flag Nikto's
  default user-agent string, so changing it can be necessary to get accurate results without
  being blocked mid-scan, and (2) on an authorized engagement it's good practice to embed a
  clearly identifiable string so the client's blue team/SOC can immediately recognize authorized
  testing traffic in their logs if they're monitoring during the engagement window.

## Other commonly used flags

```bash
nikto -h https://target.example.com -id admin:password123
```

- `-id admin:password123` — supplies HTTP Basic Authentication credentials in `username:password`
  format, for scanning behind a basic-auth-protected staging environment.

```bash
nikto -h https://target.example.com -C all
```

- `-C all` — forces Nikto to check **all CGI directories** it knows about (by default it only
  checks a subset for speed); useful on older infrastructure still running CGI-based applications.

```bash
nikto -h https://target.example.com -evasion 1
```

- `-evasion 1` — applies IDS-evasion technique #1 (one of several numbered techniques Nikto
  supports, such as URL encoding, random case, or directory self-reference insertion) to try to
  slip past simple pattern-matching network IDS rules. This should only be used when the
  engagement scope explicitly calls for evasion testing, since the goal of most pentests is to
  find findings, not to specifically test detection capability — using evasion by default can
  mask issues the client actually wants visibility into.

```bash
nikto -h https://target.example.com -nointeractive
```

- `-nointeractive` — disables Nikto's interactive keypress controls during the scan (normally you
  can press keys like `v` for verbose, `d` for debug, `e` for next host while a scan is running).
  This flag is used when running Nikto inside an automated pipeline/script where no human is
  present to send keystrokes.

## Reading Nikto's output

A typical finding line looks like:

```
+ /admin/: Directory indexing found.
+ Server: Apache/2.4.41 (Ubuntu)
+ The X-Content-Type-Options header is not set.
+ /backup.zip: This might be interesting...
```

- Each `+`-prefixed line is a single finding. Nikto deliberately reports broadly and with low
  precision — it is designed to surface candidates for **manual verification**, not to be treated
  as a final vulnerability report. Every line should be re-checked manually (using the techniques
  in files `02`–`06`) before it goes into a client deliverable, since Nikto has a meaningful
  false-positive rate, especially on the "interesting file" and "software identification"
  categories.

## Real-world notes

- Nikto's value in a professional engagement is speed of triage, not depth: running it early in
  an engagement against every in-scope host gives you a prioritized list of "worth investigating
  further" leads (default files, missing headers, outdated server banners) within minutes,
  which you then manually verify and weaponize using the techniques documented in the rest of
  this series.
- Because Nikto generates a high volume of requests in a short time, it is one of the noisiest
  tools commonly used in a pentest — always confirm scanning windows and rate limits with the
  client, and prefer running it against staging/lower environments first if available.
- Many WAFs and CDNs (Cloudflare, AWS WAF managed rules) specifically fingerprint and block Nikto's
  default request patterns; a scan returning suspiciously clean results against a
  well-known-imperfect target is itself a signal that traffic may be getting silently filtered,
  and is worth cross-checking against a manual `curl` request to the same paths.

## What's next

Continue to `09_Cheatsheet_and_Lab_Mapping.md` for the consolidated quick-reference and the full
PortSwigger Academy lab-order mapping for this series.
