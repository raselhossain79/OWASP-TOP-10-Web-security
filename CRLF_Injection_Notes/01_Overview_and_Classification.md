# 01 — CRLF Injection: Overview and Classification

## What CRLF actually is

CRLF stands for Carriage Return, Line Feed — two ASCII control characters:

- `CR` = Carriage Return = byte `0x0D` = decimal `13` = URL-encoded `%0d`
- `LF` = Line Feed = byte `0x0A` = decimal `10` = URL-encoded `%0a`

Together, the two-byte sequence `\r\n` (`%0d%0a`) is the line terminator
defined by the HTTP/1.x specification (RFC 7230, formerly RFC 2616). Every
line in an HTTP/1.x message — the request line, every header, and the blank
line that separates headers from the body — must end in `\r\n`. The message
is terminated by two consecutive CRLF pairs (`\r\n\r\n`), which marks "end of
headers, body starts here."

This is the entire reason CRLF injection exists as a vulnerability class:
**HTTP/1.x has no length-prefixed framing for headers.** A header isn't "the
next N bytes" — it's "everything up to the next `\r\n`." If an application
takes attacker-controlled input and writes it into a header value (or a log
line, or any other CRLF-delimited text format) without filtering `\r` and
`\n`, the attacker can inject their own line terminator and the receiving
parser will believe a new line — a new header, a new log entry, a new HTTP
response — has started, even though from the application's point of view it
was all one string.

This is structurally the same root cause as SQL injection: the parser cannot
distinguish "data" from "syntax" because the application failed to separate
the two before handing the string to the next layer. In SQL injection the
delimiter is a quote character breaking out of a string literal. In CRLF
injection the delimiter is `\r\n` breaking out of a header value.

## Why HTTP/2 changes the picture (and why it doesn't eliminate the bug)

HTTP/2 is a binary protocol. Headers are sent as discrete, length-prefixed
fields (HPACK-encoded), not as `\r\n`-delimited text. This means a raw `\r\n`
sequence inside an HTTP/2 header value has **no special meaning to an HTTP/2
endpoint** — it's just two bytes inside a string.

The vulnerability resurfaces the moment that HTTP/2 request gets
**downgraded** to HTTP/1.1 by a front-end server or CDN before being
forwarded to a back-end that only speaks HTTP/1. The downgrade process
rewrites the binary HTTP/2 headers back into HTTP/1.x text syntax. At that
point, the `\r\n` the attacker smuggled inside an HTTP/2 header value
suddenly *does* become a real line terminator on the HTTP/1.1 side — letting
the attacker inject arbitrary headers or even a second, fully smuggled
request into the back-end's stream. This is exactly the mechanism behind the
two PortSwigger Advanced Request Smuggling labs covered in file `03`.

Industry note: this is precisely the class of bug James Kettle (PortSwigger
Director of Research) demonstrated at Black Hat USA 2021 ("HTTP/2: The
Sequel is Always Worse") and extended further in the 2025 "HTTP/1.1 must
die" research. Real CDNs and reverse proxies (not lab targets) have been
found vulnerable to HTTP/2-to-HTTP/1 downgrade CRLF injection in the wild.

## Classification of CRLF injection impact

CRLF injection isn't one attack — it's an injection *primitive* that enables
several distinct downstream attacks depending on **where** the unsanitized
input ends up:

| Sink | Resulting attack | Covered in |
|---|---|---|
| A response header value, reflected to the client | HTTP response splitting → reflected XSS, header smuggling | `02` |
| An unkeyed request header used to build a response, then cached | Web cache poisoning | `03` |
| A `Set-Cookie` header constructed from attacker input | Session fixation | `04` |
| A log line (access log, application log, audit log) | Log injection / log forging | `05` |
| A header value forwarded through an HTTP/2 → HTTP/1 downgrade | Request smuggling / response queue poisoning | `03` |

## Root causes seen in real codebases

These are the actual coding patterns that produce CRLF injection in
production, not lab-only contrivances:

1. **Manual header construction with string concatenation.** Older Java
   (`HttpServletResponse.setHeader()` pre-hardening), classic ASP, PHP's
   `header()` function before PHP 5.1.2, and hand-rolled Python socket code
   are the classic offenders. PHP's `header()` function was patched in
   5.1.2 specifically to reject embedded `\r` and `\n` — this single CVE is
   why CRLF injection is rarer in modern PHP apps but still common in
   legacy code and custom frameworks.
2. **Redirect endpoints that build a `Location` header from a
   user-supplied parameter** (`?returnUrl=`, `?next=`) without encoding it.
   This is the single most common real-world CRLF injection entry point
   found in bug bounty reports.
3. **Reverse proxies and load balancers that decode percent-encoded
   characters in a header value before forwarding it upstream**, turning a
   filtered `%0d%0a` into a raw `\r\n` exactly where the back-end parser is
   least expecting it. This is a parser-discrepancy bug, the same family as
   request smuggling.
4. **Logging frameworks that write attacker-controlled fields (User-Agent,
   X-Forwarded-For, username, search query) directly into a log line**
   without escaping newlines.

## What "broken parser" actually means, concretely

Take a hypothetical vulnerable redirect:

```
GET /redirect?url=/home HTTP/1.1
Host: example.com
```

Server-side pseudocode:

```
response.setHeader("Location", request.getParameter("url"));
```

If the application does nothing to `url` except drop it into the header
value, the raw bytes written to the socket look like:

```
HTTP/1.1 302 Found
Location: /home
Set-Cookie: session=abc123
...
```

The `Location:` line ends at the first `\r\n` the server's own templating
adds. The attacker doesn't control that boundary — yet. The vulnerability is
that if the attacker's `url` value itself *contains* a `\r\n`, they inject a
boundary **before** the server's intended one arrives, and everything after
their injected `\r\n` is no longer inside the `Location` value — it's a new
line in the response. That single capability is response splitting, and
it's the mechanism every later file in this series builds on.

## Real-world severity framing

CRLF injection is rated under **CWE-93 (Improper Neutralization of CRLF
Sequences)**. On its own it's often scored as medium severity (information
disclosure, minor header manipulation). Its real-world severity comes
entirely from **what it's chained into**:

- Chained into cache poisoning → mass XSS against every visitor, high/critical.
- Chained into session fixation → full account takeover, critical.
- Chained into request smuggling on shared infrastructure → cross-user data
  exposure, critical, frequently a 4-figure-to-5-figure bug bounty payout.
- Used for log injection alone → usually low/medium (log integrity,
  potential second-order injection into a SIEM or log viewer).

This is why every later file in this series treats the raw CRLF as a
building block, not the end goal — exactly how it's treated in real
penetration test reports and bug bounty write-ups.
