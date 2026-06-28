# HTTP Request Smuggling — Detection Techniques

This file assumes you've read `01-concept-and-root-cause.md` and understand why
CL.TE/TE.CL/TE.TE desyncs happen. Detection is about turning that theoretical
disagreement into something you can actually *observe* from outside the
infrastructure, without already knowing which variant (if any) is present.

## 1. Why timing is the primary detection signal

You, as an external attacker/tester, cannot see what the back-end server is doing
internally. You can't inspect its parser state. What you *can* observe is **how long
the front-end takes to send back a response**. The timing-based detection technique
exploits this: craft a request that is deliberately incomplete from the back-end's
point of view (but looks complete to the front-end), send it, and measure whether the
response is delayed.

If the back-end is left waiting for bytes that will never arrive (because the
front-end already considered the request finished and won't send any more), the
back-end will eventually time out — typically after several seconds. That delay,
compared against a normal baseline response time, is your detection signal. This is
also the exact technique Burp Scanner automates under the hood when it flags
"HTTP request smuggling" findings.

## 2. Detecting CL.TE using timing

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

Breakdown:
- `Content-Length: 4` — the front-end, if it honors `Content-Length`, reads exactly 4
  bytes of body: `1\r\nA\r\n`. It forwards only those 4 bytes to the back-end and
  considers the request done. The trailing `X` is **never sent** — the front-end
  truncates it off because, as far as the front-end is concerned, that byte belongs
  to a separate, subsequent request (or nothing at all, depending on what else is
  queued).
- The back-end, if it honors `Transfer-Encoding: chunked` instead, parses the 4 bytes
  it did receive as: `1` (chunk size = 1 byte), then `A` (the 1-byte chunk payload).
  Per the chunked spec, after consuming a declared chunk it expects **another chunk
  header line** to follow — either more data or the zero-length terminator. But
  nothing more arrived, because the front-end never forwarded `X` or anything past it.
- Result: the back-end's chunked parser sits there waiting for the next chunk header
  that will never come (within this request), until its read timeout fires —
  typically observable as a multi-second delay in the HTTP response compared to a
  normal, fast baseline request to the same endpoint.

If you see that delay, you have strong evidence of a **CL.TE** vulnerability: the
front-end trusted `Content-Length` (truncating the request short), and the back-end
trusted `Transfer-Encoding` (and is now stuck mid-chunk).

🔗 **PortSwigger Lab:** *HTTP request smuggling, confirming a CL.TE vulnerability via
differential responses* (uses this kind of probe as its starting point, then escalates
to differential-response confirmation — see Section 4 below).

## 3. Detecting TE.CL using timing

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

Breakdown:
- The front-end, if it honors `Transfer-Encoding: chunked`, parses the body as
  chunked: it reads `0` as a zero-length chunk, which terminates the body
  immediately per spec. The front-end therefore forwards only up through that
  terminator and stops — the trailing `X` on its own line is **not forwarded**,
  because the front-end correctly considers the chunked body finished before that
  point.
- The back-end, if it honors `Content-Length: 6` instead, expects exactly 6 bytes of
  body. It received `0\r\n\r\n` (5 bytes: `0`, CRLF, CRLF) from the front-end — short
  of the promised 6. The back-end's parser is now waiting for 1 more byte that will
  never arrive on this request, because the front-end already truncated everything
  after the chunk terminator.
- Result: the back-end stalls waiting for the missing byte, producing the same kind
  of observable timing delay as the CL.TE test — but this time it indicates the
  **opposite** disagreement: front-end trusts TE, back-end trusts CL.

### Operational caution — order matters
PortSwigger's own guidance, and standard practice in real engagements, is: **always
run the CL.TE timing probe first.** If a site turns out to be CL.TE-vulnerable and you
send the TE.CL-style probe to it, you risk the trailing data (`X` in the example
above) being smuggled into and corrupting another real user's in-flight request on
that same back-end connection — a live, disruptive side effect on production traffic,
not just a passive detection test. Only proceed to the TE.CL timing test if the CL.TE
test came back clean, to minimize the blast radius of your probing on a live target.
This ordering discipline is exactly the kind of detail that separates a careful,
professional engagement from a reckless one and is worth calling out explicitly in
any pentest methodology document or bug bounty report.

🔗 **PortSwigger Lab:** *HTTP request smuggling, confirming a TE.CL vulnerability via
differential responses*

## 4. Why timing alone isn't proof — confirming with differential responses

A timing delay is *evidence*, not *proof*. Network jitter, a genuinely slow backend
endpoint, WAF rate-limiting, or unrelated server load could all produce a similar
delay and create a false positive. To get a confirmable, repeatable signal, you escalate
to a **differential response** test: deliberately smuggle a fragment that corrupts
the *next* request sent down the same connection, and observe that the *next*
request's response changes in a predictable, attacker-caused way.

The methodology has two parts sent back-to-back on the same connection:
1. An **"attack" request** — the smuggling payload, designed to leave a fragment
   that will be glued onto whatever request comes immediately after it.
2. A **"normal" request** — a request you'd expect to get an ordinary, known
   response (e.g. HTTP 200 with search results).

If the normal request instead comes back with a response that matches what the
*smuggled fragment* would cause (e.g. an unexpected 404), you've proven the
back-end genuinely concatenated your fragment onto the next request — i.e. the
desync is real and exploitable, not a timing artifact.

### Confirming CL.TE via differential response

Normal baseline request:
```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```
This normally returns HTTP 200 with search results — establish this baseline first.

Attack request:
```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

Breakdown:
- `Content-Length: 49` is what the front-end honors. It counts exactly 49 bytes of
  body — covering the entire chunked-looking section *and* the smuggled
  `GET /404 HTTP/1.1\r\nFoo: x` lines — and forwards that whole block as one request's
  body to the back-end.
- The back-end honors `Transfer-Encoding: chunked` instead. `e` is hex for 14: it
  reads the next 14 bytes (`q=smuggling&x=`) as the first chunk's payload. Then `0`
  terminates the chunked body. Everything after that — `GET /404 HTTP/1.1\r\nFoo: x`
  — is left over, unconsumed, sitting in the back-end's buffer as the start of the
  *next* request it will read off this connection.
- Immediately send the "normal" baseline request again, on the same connection. The
  back-end now concatenates your leftover fragment with the start of that next
  request, producing effectively:
  ```
  GET /404 HTTP/1.1
  Foo: xPOST /search HTTP/1.1
  Host: vulnerable-website.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 11

  q=smuggling
  ```
- The back-end's request-line parser reads `GET /404 HTTP/1.1` as the actual request
  line — a request to a path that doesn't exist — and the rest is parsed as headers
  (with `Foo: xPOST /search HTTP/1.1` becoming one garbled header line, harmlessly
  ignored as malformed). The response comes back as **HTTP 404**, not the expected
  200 with search results.
- That 404 — appearing on a request that should have returned 200 — is your
  confirmed, repeatable, attacker-caused interference. This is materially stronger
  evidence than a timing delay alone.

### Confirming TE.CL via differential response

```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0

```

Breakdown:
- The front-end honors `Transfer-Encoding: chunked`. `7c` is hex for 124: it reads the
  next 124 bytes as one chunk's payload — which is the entire smuggled
  `GET /404...x=` block — then reads `0` as the terminator. It forwards the whole
  thing as a single, complete request.
- The back-end honors `Content-Length: 4` instead, reading only 4 bytes of body:
  `7c\r\n` (the literal characters `7`, `c`, and the CRLF — 4 bytes total). It treats
  the request as complete right there. Everything from `GET /404 HTTP/1.1` onward is
  unconsumed and becomes the start of the next request the back-end parses.
- As with the CL.TE case, immediately sending the baseline "normal" request causes
  the back-end to glue it onto this leftover `GET /404...` fragment, and the
  resulting response is HTTP 404 instead of the expected 200 — confirming a TE.CL
  desync.
- Same Burp Repeater caveat applies: uncheck "Update Content-Length" before sending,
  and make sure you include the trailing `\r\n\r\n` after the final `0` chunk
  terminator — Burp's editor will not add this for you automatically when you're
  hand-crafting a chunked body.

### Operational requirements for a valid differential-response test
These are easy to get wrong and will produce false negatives if ignored:
- The attack request and the normal request **must use separate network
  connections** opened back-to-back — not literally the same socket reused inline —
  but must land on the **same back-end server**. Sending both over genuinely the same
  single uninterrupted connection doesn't prove anything about smuggling across
  connection reuse; it just proves sequential processing.
- Keep the URL and parameters of the attack and normal requests as similar as
  possible. Many real architectures route different URLs/parameters to different
  back-end pool members; if your two requests land on different physical back-ends,
  the test will fail even though the vulnerability is real.
- You are racing other live traffic. If the application has real users on the same
  back-end connection pool, your "normal" request might collide with theirs instead
  of with your own attack fragment — meaning a failed first attempt doesn't
  necessarily mean "not vulnerable," and a single success could mean you just
  smuggled into a stranger's session (treat that as a serious finding requiring
  immediate caution and disclosure, not something to keep probing recklessly).

## 5. Practical workflow summary

1. Establish a fast, reliable baseline response time and response body for a target
   endpoint.
2. Send the CL.TE timing probe first. If you see a multi-second delay relative to
   baseline, you likely have CL.TE.
3. Only if CL.TE was clean, send the TE.CL timing probe.
4. For any timing hit, escalate to the matching differential-response confirmation
   request to turn "suspicious delay" into "proven, repeatable interference."
5. If neither CL.TE nor TE.CL timing probes show anything, move to TE.TE header
   obfuscation testing (see `01-concept-and-root-cause.md` Section 6) — this is where
   the **HTTP Request Smuggler** Burp extension earns its keep, since it automates
   sending the entire library of known obfuscation variants rather than requiring you
   to hand-test each one (covered in `04-burp-http-request-smuggler-extension.md`).

🔗 **PortSwigger Labs covered in this file (in Academy progression order):**
- *HTTP request smuggling, confirming a CL.TE vulnerability via differential
  responses*
- *HTTP request smuggling, confirming a TE.CL vulnerability via differential
  responses*
