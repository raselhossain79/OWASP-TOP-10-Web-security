# 09 — Cheatsheet and PortSwigger Lab Mapping

This is the condensed, fast-reference version of the series. Use files `01`–`08` to build
understanding; use this file during live engagements once the underlying concepts are
internalized.

## Quick-reference checklist by sub-category

### Default credentials & unnecessary features (file 02)
- [ ] Fingerprint stack: `whatweb -a 3 <url>`
- [ ] Check for known default creds on identified product: `searchsploit -w "<product>"`
- [ ] Test default creds with curated list (not a brute-force dictionary): `hydra -L users.txt -P passwords.txt <host> http-post-form "<form-spec>"`
- [ ] Enumerate HTTP methods: `curl -i -X OPTIONS <url>`
- [ ] Check Spring Boot Actuator: `/actuator/env`, `/actuator/heapdump`
- [ ] Check exposed `.git`: `curl -s -o /dev/null -w "%{http_code}\n" <url>/.git/HEAD`

### Verbose errors & debug exposure (file 03)
- [ ] Force type-confusion error: malformed parameter (e.g. `?productId=art`)
- [ ] Probe debug interfaces: `/__debug__/`, `/console`, `/cgi-bin/phpinfo.php`
- [ ] Send `TRACE` request, diff echoed headers against what you actually sent
- [ ] Compare response size/status for username enumeration via login form

### Security headers (file 04)
- [ ] `curl -sI <url>` then grep for: `content-security-policy`, `strict-transport-security`,
      `x-frame-options`/`frame-ancestors`, `x-content-type-options`, `referrer-policy`,
      `permissions-policy`
- [ ] Confirm CSP doesn't use `'unsafe-inline'` / `'unsafe-eval'` / wildcard sources
- [ ] Confirm HSTS `max-age` ≥ recommended minimum and `includeSubDomains` present

### CORS (file 05)
- [ ] Reflect arbitrary origin: `curl -H "Origin: https://evil.test" -i <url>`
- [ ] Test `null` origin trust: `curl -H "Origin: null" -i <url>`
- [ ] Test `http://` subdomain trust regardless of protocol
- [ ] Test internal-network-range trust (only with explicit engagement scope)
- [ ] Always check whether `Access-Control-Allow-Credentials: true` accompanies a permissive
      `Access-Control-Allow-Origin` — credentials flag is what makes reflection exploitable

### Directory listing (file 06)
- [ ] Check `robots.txt` / `sitemap.xml` for named sensitive paths
- [ ] Request directory path with trailing slash, grep for "Index of"
- [ ] Brute-force discovery: `gobuster dir -u <url> -w <wordlist> -x bak,old,zip,tar.gz`
- [ ] Mirror confirmed listing: `wget -r -np -nH --cut-dirs=1 <url>`
- [ ] Check `.git` exposure specifically: `wget -r <url>/.git/` then `git log --oneline` / `git diff`

### Cloud storage & infrastructure (file 07)
- [ ] Anonymous list test: `aws s3 ls s3://<bucket> --no-sign-request`
- [ ] Anonymous read test: `aws s3 cp s3://<bucket>/<object> . --no-sign-request`
- [ ] Bulk discovery: `s3scanner scan --buckets-file <candidates.txt>`
- [ ] GCS equivalent: `gsutil ls gs://<bucket>`
- [ ] Azure equivalent: unauthenticated container list URL via `curl`
- [ ] If SSRF present, check metadata endpoint exposure: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

### General scanning (file 08)
- [ ] `nikto -h <url> -Tuning 23b` for a fast misconfiguration/info-disclosure/software-ID pass
- [ ] `nikto -h <url> -Tuning 123456789ab -Plugins "@@ALL"` for a full pass
- [ ] Treat every Nikto finding as a lead requiring manual verification, not a final result

## PortSwigger Web Security Academy lab mapping — correct Academy progression order

PortSwigger does not group these under one "Security Misconfiguration" topic — they sit across
the **CORS** topic and the **Information disclosure** topic. Below is the full mapping in each
topic's actual Academy order, cross-referenced to the file in this series that covers it.

### CORS topic (Academy order 1 → 4)

| Order | Lab name | Covered in |
|---|---|---|
| 1 | CORS vulnerability with basic origin reflection | `05_CORS_Misconfiguration.md` — Pattern 1 |
| 2 | CORS vulnerability with trusted null origin | `05_CORS_Misconfiguration.md` — Pattern 2 |
| 3 | CORS vulnerability with trusted insecure protocols | `05_CORS_Misconfiguration.md` — Pattern 3 |
| 4 | CORS vulnerability with internal network pivot attack | `05_CORS_Misconfiguration.md` — Pattern 4 |

### Information disclosure topic (Academy order 1 → 5)

| Order | Lab name | Covered in |
|---|---|---|
| 1 | Information disclosure in error messages | `03_Verbose_Errors_and_Debug_Exposure.md` — Step 1 |
| 2 | Information disclosure on debug page | `03_Verbose_Errors_and_Debug_Exposure.md` — Step 2 |
| 3 | Source code disclosure via backup files | `06_Directory_Listing_Exposure.md` |
| 4 | Authentication bypass via information disclosure | `03_Verbose_Errors_and_Debug_Exposure.md` — Step 3 |
| 5 | Information disclosure in version control history | `06_Directory_Listing_Exposure.md` |

### Sub-categories with no dedicated PortSwigger lab

PortSwigger does not gamify these as standalone labs. They are covered in this series purely from
real-world pentest methodology and tooling, as noted in file `01`:

- Default credentials and unnecessary features/services → `02_Default_Credentials_and_Unnecessary_Features.md`
- Missing/misconfigured security headers as a standalone topic (header concepts appear woven into
  other Academy topics like clickjacking and XSS, but there's no dedicated "headers" lab series)
  → `04_Security_Headers_Misconfiguration.md`
- Cloud storage/infrastructure misconfiguration → `07_Cloud_Storage_and_Infrastructure_Misconfiguration.md`

## Suggested practice order

If you want to work through PortSwigger labs in parallel with this series, the most efficient
path is:

1. Read `01` for framing.
2. Read `03`, then solve Information Disclosure labs 1, 2, and 4 (error messages → debug page →
   auth bypass via TRACE) — these three build on each other directly.
3. Read `06`, then solve Information Disclosure labs 3 and 5 (backup files → git history) — these
   two are conceptually paired (exposed-path-leads-to-source-code).
4. Read `05`, then solve all four CORS labs in order — they are already structured as an
   escalating sequence by PortSwigger itself.
5. Read `02`, `04`, and `07` for the real-world-only sub-categories, applying the manual
   `curl`/CLI tooling against your own lab environments or authorized scope, since no Academy
   lab exists for direct practice.
6. Use `08` (Nikto) as your standard first-pass recon tool across any target environment you have
   authorization to scan, to build the habit of triage-then-manual-verify.

## Final notes

This series intentionally excludes XXE — see the dedicated XXE note series in this repository
for that sub-category, which PortSwigger and OWASP both treat as related to misconfiguration
(insecure XML parser settings) but substantial enough to warrant separate, deeper treatment.
