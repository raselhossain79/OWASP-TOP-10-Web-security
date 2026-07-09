# 02 — Default Credentials and Unnecessary Features/Services

## Part A: Default Credentials

### What it is

Default credentials are username/password pairs that ship with a product, device, or service
out of the box and are never changed during deployment. This includes:

- Admin panel logins for CMS platforms (WordPress, Joomla), routers, IP cameras
- Database default accounts (`root`/blank, `sa`/blank on MSSQL, `postgres`/`postgres`)
- Default accounts on management interfaces (Tomcat Manager, Jenkins, phpMyAdmin, Grafana)
- Hardcoded vendor credentials on IoT/embedded devices that are rarely, if ever, changed by
  end users

### Why it persists in production

- Deployment guides frequently say "log in with admin/admin and change this later" — and "later"
  never comes.
- Internal-only services (intended to be firewalled) get accidentally exposed to the internet
  during a misconfigured cloud migration, carrying their default credentials with them.
- Vendor-supplied appliances (firewalls, load balancers, NAS devices) are configured once at
  install time and never revisited.

### How to test for default credentials (manual, piece by piece)

Step 1 — Fingerprint the technology stack.

```bash
whatweb -a 3 https://target.example.com
```

- `whatweb` — a tool that fingerprints web technologies from HTTP responses (headers, HTML
  meta tags, JS libraries, cookies).
- `-a 3` — sets the **aggression level** to 3 ("aggressive"). WhatWeb has aggression levels 1–4;
  level 1 only inspects the homepage, level 3 follows redirects and probes a handful of common
  paths to confirm plugin/technology fingerprints with higher confidence. Level 4 is "heavy" and
  much noisier — level 3 is the standard balance for a pentest.
- `https://target.example.com` — the target URL to fingerprint.

This step matters because you cannot look up default credentials for "a website" — you need to
know *which* CMS, panel, or appliance you're dealing with before consulting its default
credential list.

Step 2 — Look up default credentials for the identified product.

```bash
searchsploit -w "Tomcat Manager"
```

- `searchsploit` — the command-line search tool for the Exploit-DB database (bundled with the
  Exploit-DB mirror, often pre-installed on Kali).
- `-w` — tells `searchsploit` to print the **web reference URL** (the Exploit-DB page link) for
  each match, instead of only the local mirrored file path. This is useful because some
  Exploit-DB entries for default-credential issues are advisories/write-ups rather than
  standalone exploit code, and the web page often documents the exact default login.
- `"Tomcat Manager"` — the search term; quoting it keeps it as a single search phrase.

This surfaces known default-credential advisories for the identified product (for Tomcat
Manager specifically: `tomcat`/`tomcat`, `admin`/`admin`, `admin`/`s3cret` are common defaults
depending on the distribution).

Step 3 — Attempt login with known defaults, rate-limited and logged.

```bash
hydra -L users.txt -P passwords.txt target.example.com http-post-form \
  "/manager/html:username=^USER^&password=^PASS^:F=Invalid"
```

- `hydra` — a parallelized login-cracking tool supporting many protocols.
- `-L users.txt` — load candidate usernames from the file `users.txt` (a small, curated list of
  vendor defaults like `admin`, `root`, `tomcat`, `manager` — NOT a brute-force wordlist; default
  credential testing should use a short, specific list, not an unbounded dictionary attack).
- `-P passwords.txt` — load candidate passwords from `passwords.txt`, again a short curated list
  of documented defaults for the identified product.
- `target.example.com` — the target host.
- `http-post-form` — tells Hydra the login is an HTTP POST form submission (as opposed to
  `http-get`, `ssh`, `ftp`, etc.).
- `"/manager/html:username=^USER^&password=^PASS^:F=Invalid"` — the form specification string,
  made of three colon-separated parts:
  - `/manager/html` — the path Hydra POSTs to.
  - `username=^USER^&password=^PASS^` — the POST body template; `^USER^` and `^PASS^` are
    placeholders Hydra substitutes from the wordlists on each attempt.
  - `F=Invalid` — a **failure condition string**. Hydra treats any response containing the text
    "Invalid" as a failed login. (You could instead use `S=` for a success-string match if the
    success response is more reliably unique.)

**Engagement note:** always check the client's rules of engagement before running any
credential-testing tool. Many environments lock accounts after a small number of failed
attempts, and `hydra` against a production login form can trigger denial-of-service-like account
lockouts if you're not careful with thread count (`-t`) and target scope.

### Real-world notes

- Default-credential findings on bug bounty programs are usually scoped *out* unless they expose
  genuinely sensitive functionality — but on internal pentests and red-team engagements, default
  credentials on management interfaces (Jenkins, Grafana, Kibana, Tomcat Manager) are one of the
  single most common ways testers achieve full compromise, because these panels often allow
  direct code execution (Jenkins script console, Tomcat WAR file deployment) once logged in.
- Shodan and Censys are frequently used during reconnaissance to find exposed management
  interfaces at scale before even attempting credential testing — searching `port:8080
  product:"Apache Tomcat"` is a common starting query.

---

## Part B: Unnecessary Features, Services, and Components Enabled

### What it is

This covers anything left active in a production deployment that increases attack surface
without adding required functionality:

- Debug/test endpoints (`/debug`, `/test`, `/_profiler`, Spring Boot Actuator endpoints like
  `/actuator/env`, `/actuator/heapdump`)
- Sample applications shipped with the application server (Tomcat's `/examples`,
  `/docs`, `/host-manager`)
- Unused HTTP methods enabled at the web server level (`PUT`, `DELETE`, `TRACE`)
- Unnecessary open network services (an exposed Redis/Memcached instance with no
  authentication, an exposed `.git` directory, an exposed CI/CD webhook listener)
- Verbose platform banners (server version banners revealing exact patch level)

### How to test, piece by piece

Step 1 — Enumerate exposed HTTP methods.

```bash
curl -i -X OPTIONS https://target.example.com/api/users
```

- `curl` — command-line HTTP client.
- `-i` — include the response headers in the output (not just the body), since the methods list
  comes back in a header.
- `-X OPTIONS` — override the request method to `OPTIONS`, which (per HTTP spec) asks the server
  to report which methods are supported on the given resource.
- `https://target.example.com/api/users` — the target endpoint.

The response `Allow:` header (e.g., `Allow: GET, POST, PUT, DELETE, TRACE`) tells you exactly
which methods the server has enabled for that path. `PUT`/`DELETE` enabled without proper
authorization checks is a classic unnecessary-feature finding; `TRACE` enabled re-opens the
information-disclosure risk covered in file `03`.

Step 2 — Check for exposed Spring Boot Actuator endpoints (common in Java microservices).

```bash
for ep in env health info beans configprops mappings heapdump; do
  echo "[*] /actuator/$ep"
  curl -s -o /dev/null -w "%{http_code}\n" https://target.example.com/actuator/$ep
done
```

- `for ep in ...; do ... done` — a Bash loop iterating over a list of common Actuator endpoint
  names.
- `curl -s` — silent mode, suppresses curl's own progress output.
- `-o /dev/null` — discard the response body (we only care about status code in this probing
  pass).
- `-w "%{http_code}\n"` — print only the HTTP status code returned, followed by a newline.
- `https://target.example.com/actuator/$ep` — the constructed URL for each endpoint name in the
  loop.

A `200` status on `/actuator/env` or `/actuator/heapdump` is a severe finding: `env` can leak
database credentials and API keys baked into environment variables, and `heapdump` lets you
download a full JVM heap dump — which can be mined offline for session tokens, passwords, and
internal object state using a heap analysis tool.

Step 3 — Check for exposed `.git` directories (a very common "leftover" exposure).

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://target.example.com/.git/HEAD
```

- Same flag breakdown as Step 2. A `200` here means the web server is directly serving the `.git`
  folder's internal files — this allows full repository reconstruction (see file `03`'s
  cross-reference to PortSwigger's "Information disclosure in version control history" lab,
  which models exactly this scenario).

### Real-world notes

- Spring Boot Actuator misconfiguration is one of the most frequently reported categories in
  bug bounty programs for Java-based fintech and SaaS backends specifically because `heapdump`
  and `env` so reliably yield credentials.
- Exposed `.git` directories are extremely common on smaller companies' marketing sites and
  internal tools that were deployed by simply copying a project folder onto a web server without
  excluding version-control metadata.
- Nikto (file `08`) automates discovery of many of these unnecessary-feature exposures in a
  single scan pass — this is one of the main reasons it's included as a dedicated tool file in
  this series.

## What's next

Continue to `03_Verbose_Errors_and_Debug_Exposure.md`.
