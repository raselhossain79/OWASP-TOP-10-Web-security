# 02 — HTTP Response Splitting

## What it is

HTTP response splitting is the original, classic CRLF injection attack
(first documented by Amit Klein at Sanctum/Watchfire in 2004). The attacker
controls a value that ends up in a response header. By injecting `\r\n`
into that value, they terminate the header early and write additional
content into the response — additional headers, or, by injecting a second
`\r\n` (a blank line), an entirely new HTTP response body.

The name comes from the historical impact: on servers and proxies that
process a TCP connection as a stream of responses, a single attacker request
could cause the server to emit what looks like **two separate HTTP
responses**, "splitting" one response into two and confusing whatever
read the stream next (typically a caching proxy, browser, or downstream
client). On a single response, the simpler and far more common modern
outcome is just **header injection** — adding headers the application never
intended to send.

## Piece-by-piece: the baseline payload

Vulnerable sink (typical real pattern, a redirect):

```
response.setHeader("Location", "http://example.com" + userInput);
```

Request:

```
GET /redirect?url=/home%0d%0aSet-Cookie:%20admin=true HTTP/1.1
Host: example.com
```

Breaking this down byte by byte:

| Fragment | Meaning |
|---|---|
| `/home` | The legitimate, expected value — what the application "thinks" the entire parameter is |
| `%0d%0a` | URL-decoded by the server to `\r\n` — this is the injection. It terminates the `Location` header line *from the attacker's chosen point*, not the server's |
| `Set-Cookie:%20admin=true` | A second, fully attacker-controlled header line. `%20` decodes to a literal space, which is required after the colon for the header to parse as valid (`Header: value`, not `Header:value` — many parsers tolerate the latter, but writing it correctly avoids relying on parser leniency) |

The raw bytes the server ends up writing to the socket:

```
HTTP/1.1 302 Found
Location: http://example.com/home
Set-Cookie: admin=true
...
```

The browser/proxy now sees a legitimate-looking `Set-Cookie` header that the
application never intended to send. This is the entire mechanism: **the
attacker supplied the line terminator that should have only ever come from
the server's own response template.**

## Piece-by-piece: escalating to body injection (the "split")

To go from "inject one extra header" to "inject an entire second response,"
the attacker needs to also supply the **blank line** that normally separates
headers from the body — that's a *second* `\r\n` pair.

```
GET /redirect?url=/home%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2019%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: example.com
```

Breaking this apart:

| Fragment | Meaning |
|---|---|
| `/home` | Expected value, same as before |
| `%0d%0a` | Closes the legitimate `Location` header |
| `Content-Length:%200` | Attacker-forged header — tells whatever reads the *first* response that its body is zero bytes, so it immediately expects a fresh response next |
| `%0d%0a%0d%0a` | Two CRLF pairs back-to-back = end of headers + empty body for response #1. This is the critical "split" point |
| `HTTP/1.1%20200%20OK` | The attacker is now writing what looks like a brand-new status line — response #2 begins here |
| `Content-Type:%20text/html` / `Content-Length:%2019` | Forged headers for the fake second response, sized to match the injected body exactly |
| `%0d%0a%0d%0a` | End of headers for response #2 |
| `%3Cscript%3Ealert(1)%3C/script%3E` | The injected body — in this example a reflected XSS payload, but it could be any content |

If something downstream treats this TCP stream as containing two
back-to-back HTTP responses (historically: caching proxies and some older
browsers in pipelined-connection scenarios), it will serve the attacker's
forged second response — including its body — to whichever request happens
to be queued next on that connection. This is why response splitting was
historically a vector for **cache poisoning** before modern cache-poisoning
research (file `03`) generalized and modernized the technique using unkeyed
headers instead of raw CRLF.

## Why this is rarer today, and why it still matters

Most modern web frameworks now reject or strip `\r`/`\n` automatically when
you call a header-setting API (Java's `HttpServletResponse.setHeader()` has
done this since servlet spec hardening; ASP.NET Core does input validation
on header values; Express/Node's `http` module throws on invalid header
characters since Node 10). This is why textbook response splitting is
uncommon against current mainstream frameworks.

It still surfaces in:

- Custom/legacy code that builds raw header strings manually (hand-rolled
  socket servers, older PHP without `header()` hardening, legacy Java
  servlets, embedded device web UIs, IoT management consoles).
- Reverse proxies, API gateways, and WAFs themselves, when they construct
  headers internally from request data (these are high-value targets
  precisely because they sit in front of many applications at once).
- Languages/runtimes where the developer dropped to a lower-level HTTP
  library that doesn't validate (raw socket writes, custom HTTP/1.1
  serializers in performance-sensitive services).

## Real-world note

Response splitting findings in bug bounty programs today are almost always
on a *specific redirect or download endpoint* that builds a `Location` or
`Content-Disposition` header from a query parameter, on infrastructure that
predates or bypasses the framework's built-in CRLF filtering (custom Go/C
services, embedded admin panels, internal tooling exposed externally). When
you find one, always check whether it chains into cache poisoning (file
`03`) — a one-off response splitting bug against a single client is a low
severity finding; the same bug against a cached, shared response is
critical.

## PortSwigger lab note

PortSwigger does not run a dedicated lab for classic single-request response
splitting — most lab back-ends use frameworks that already filter raw CRLF
at the header API level, so the bug doesn't reproduce cleanly as a teaching
lab. Practice this technique conceptually and, where available, against
intentionally vulnerable local targets (e.g. an old PHP version without
header hardening, or a custom test harness) rather than expecting a Academy
lab match. The mechanism is identical to what you'll use in file `03`
against the two genuine PortSwigger CRLF labs — this file is the foundation
those labs build on.
