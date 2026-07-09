# 07 — Automation: crlfuzz

## What it is and where it fits

`crlfuzz` (by dwisiswant0, Go, MIT licensed) is a lightweight, fast CRLF
injection scanner. It does not belong in the same tier as `sqlmap` — it has
no DBMS fingerprinting, no exploitation engine, no data extraction. What it
does is exactly one thing: take a target URL (or list of URLs), generate a
set of candidate CRLF-injection points and payloads, fire them, and report
whether the injected sequence made it into the response in a way that
indicates the server reflected/processed it as a real line break. Think of
it as the `nikto` or `httpx`-tier of this topic — a fast triage tool you
run early to flag candidates, not a tool that replaces manual analysis.

## Installation

```bash
# Prebuilt binary
curl -sSfL https://git.io/crlfuzz | sh -s -- -b /usr/local/bin

# From source (Go 1.13+)
GO111MODULE=on go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# From GitHub
git clone https://github.com/dwisiswant0/crlfuzz
cd crlfuzz/cmd/crlfuzz
go build .
mv crlfuzz /usr/local/bin
```

## Core flags

| Flag | Purpose |
|---|---|
| `-u, --url <URL>` | Single target URL |
| `-l, --list <FILE>` | Fuzz every URL in a file, one per line |
| `-X, --method <METHOD>` | HTTP method to use (default `GET`) |
| `-d, --data <DATA>` | Request body, for `POST`/`PUT`/`PATCH`/`DELETE` |
| `-H, --header <HEADER>` | Custom header (repeatable — e.g. for auth cookies) |
| `-x, --proxy <URL>` | Route traffic through a proxy (point this at Burp) |
| `-c, --concurrent <n>` | Concurrency level (default `20`) |
| `-o, --output <FILE>` | Save vulnerable results to a file |
| `-s, --silent` | Only print confirmed-vulnerable targets |
| `-v, --verbose` | Print error detail on failed requests |
| `-V` | Print version |

## Basic usage

```bash
crlfuzz -u "https://target.example.com"
```

This sweeps the single target across crlfuzz's internal list of injectable
parameter/path patterns, trying CRLF payload variants in each.

## Practical, real-world workflows

### 1. Reconnaissance pipeline (the way it's actually used in the wild)

crlfuzz is most useful chained after subdomain enumeration and live-host
probing, since CRLF injection is most often found on long-tail endpoints
(redirect handlers, legacy admin panels) you only discover at scale:

```bash
subfinder -d target.com -silent | httpx -silent | crlfuzz -s -o crlf-hits.txt
```

Breaking this down: `subfinder` enumerates subdomains, `httpx` filters down
to hosts that actually respond over HTTP(S), and crlfuzz fuzzes each live
host, printing (with `-s`) only the ones it found vulnerable, written to
`crlf-hits.txt` for manual follow-up in Burp.

### 2. Authenticated scanning

Most interesting CRLF sinks (redirect-after-login, profile/preference
endpoints) sit behind authentication. Pass the session cookie as a header:

```bash
crlfuzz -u "https://target.example.com/redirect" -H "Cookie: session=YOUR_SESSION_TOKEN"
```

### 3. Routing through Burp for manual triage of hits

```bash
crlfuzz -u "https://target.example.com" -x http://127.0.0.1:8080
```

This is the recommended way to use crlfuzz against any target you're
actively pentesting: every request it fires lands in Burp's HTTP history,
so a "vulnerable" flag from crlfuzz can be immediately inspected, replayed,
and manually verified in Repeater rather than trusted at face value.

### 4. Scanning a list of endpoints harvested from crawling/Burp

```bash
crlfuzz -l urls.txt -c 40 -o results.txt
```

Useful after exporting a list of endpoints from a Burp crawl (Target →
Site map → "Copy URLs in this host") — feed that list straight in.

## Why this tool is "lighter than sqlmap-tier" and what that means in
practice

`sqlmap` understands SQL dialects, can enumerate a back-end DBMS, and can
escalate a finding all the way to data extraction or OS command execution
on its own. crlfuzz has none of that depth, because there isn't an
equivalent escalation path that's generic across targets — what a CRLF hit
*becomes* (cache poisoning, session fixation, log injection, response
splitting) is entirely sink-dependent and has to be manually assessed using
the techniques in files `02` through `05`. crlfuzz's job ends the moment it
confirms the injection point exists; everything after that is manual work,
which is exactly why this series is built the way it is.

## Real-world note and limitations

- crlfuzz detects the **presence** of an injectable CRLF point, generally
  by checking whether its injected marker shows up split into its own
  header/line in the response. It does **not** assess severity, does not
  attempt cache poisoning, and does not test HTTP/2-downgrade scenarios
  (file `03`, Tier B) — those require manual testing with Burp's Inspector,
  since they depend on binary HTTP/2 framing that a simple URL-based fuzzer
  doesn't model.
- False negatives are common against hardened modern frameworks (file
  `01`'s root-cause discussion) — a clean scan does not mean the
  application has no CRLF-adjacent risk, only that the specific payload set
  crlfuzz ships with didn't trigger a detectable reflection.
- Always treat a crlfuzz hit as a lead, not a finding — confirm manually in
  Burp (per workflow 3 above) before writing it up, and then assess which
  of the downstream chains in files `02`–`05` actually applies before
  assigning severity.
