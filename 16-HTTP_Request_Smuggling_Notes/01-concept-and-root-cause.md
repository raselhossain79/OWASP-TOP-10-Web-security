# HTTP Request Smuggling — Core Concept and Root Cause

> OWASP mapping: A05:2021 (Security Misconfiguration) in practice, though request
> smuggling is really an HTTP/1.1 protocol-parsing flaw that surfaces wherever a
> front-end proxy/load balancer and a back-end application server disagree about
> request boundaries. Some classifications also tie it to A04:2021 (Insecure Design),
> since the vulnerability is fundamentally an architectural consequence of chaining
> HTTP servers together. Most bug bounty programs simply tag it as **Request
> Smuggling / Desync** as its own category.

## 1. Why this category exists: the architecture that creates the problem

Almost every production web application today sits behind at least one intermediary:

```
Client  ──▶  Front-end (load balancer / reverse proxy / CDN)  ──▶  Back-end (app server)
```

Examples of front-ends: AWS ALB/ELB, NGINX, HAProxy, Varnish, Cloudflare, Akamai,
Apache acting as a reverse proxy, F5 BIG-IP. Examples of back-ends: the actual
application server — Tomcat, Node/Express, Gunicorn, IIS, another NGINX, etc.

For performance reasons, the front-end does **not** open a new TCP connection to the
back-end for every single client request. That would mean a fresh TCP handshake (and
often a fresh TLS handshake) per request, which is expensive. Instead, the front-end
reuses a small pool of persistent, keep-alive connections to the back-end, and
**multiplexes many different users' requests over the same back-end connection, one
after another**:

```
Connection to back-end:
[ Request A from User 1 ][ Request B from User 2 ][ Request C from User 1 ]...
```

This is efficient, but it creates a critical requirement: **the back-end server must
be able to tell, byte for byte, exactly where Request A ends and Request B begins.**
If it gets that boundary wrong, it will read part of Request A's intended body as the
beginning of Request B — or it will read part of Request B's headers as if they were
still part of Request A's body.

That single sentence — *two servers disagreeing on where a request ends* — is the
entire root cause of HTTP request smuggling. Every CL.TE/TE.CL/TE.TE technique in this
series is just a different way of engineering that disagreement on purpose.

## 2. The two competing ways HTTP/1.1 specifies request length

HTTP/1.1 gives servers two completely different mechanisms for declaring "this is
where my message body ends," and both are legal to use:

### Mechanism 1 — `Content-Length`

A simple byte count of the body.

```
POST /search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

Line-by-line:
- `POST /search HTTP/1.1` — request line: method, path, protocol version.
- `Host: example.com` — mandatory in HTTP/1.1, tells the server (and any virtual-host
  router) which site this request is for.
- `Content-Type: application/x-www-form-urlencoded` — tells the receiver how to parse
  the body (form-encoded key=value pairs).
- `Content-Length: 11` — declares that exactly 11 bytes follow the blank line that
  separates headers from body. The server reads exactly 11 bytes (`q=smuggling` is
  11 characters) and then considers the request complete.
- Blank line — the HTTP/1.1 header/body delimiter (`\r\n\r\n` on the wire).
- `q=smuggling` — the body, exactly 11 bytes as promised.

### Mechanism 2 — `Transfer-Encoding: chunked`

Used when the sender doesn't know the total body length in advance (e.g. streamed
data). Instead of one length, the body is split into chunks, each prefixed by its own
length in hex, and terminated by a zero-length chunk.

```
POST /search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0

```

Line-by-line:
- `Transfer-Encoding: chunked` — tells the receiver: ignore any length header, parse
  the body as a sequence of chunks instead.
- `b` — this is hex for 11. It says "the next chunk of data is 11 bytes long." (Burp
  Suite auto-decodes this for display, which is why many testers have never seen raw
  chunked bodies — they only ever see Burp's already-unpacked view.)
- `q=smuggling` — the 11-byte chunk payload itself.
- `0` — a chunk declared to be **zero bytes long**. By spec, a zero-length chunk is
  the terminator: "there is no more body, the request ends here."
- The trailing blank line after `0` is required — it's the chunk-section terminator
  (`\r\n\r\n` after the final `0\r\n`).

## 3. The ambiguity: what happens when a request has BOTH headers

The HTTP/1.1 specification (RFC 7230, later RFC 9112) anticipated that some sender
might mistakenly — or maliciously — include both headers in the same request. Its
rule for resolving this is explicit:

> If a message is received with both a `Transfer-Encoding` and a `Content-Length`
> header field, the `Transfer-Encoding` overrides the `Content-Length`.

That single rule is fine **if there is only one server reading the request**. The
problem is that in a front-end/back-end chain, there are **two** independent HTTP
parsers reading the same byte stream, written by two different engineering teams, in
two different languages, often years apart, against slightly different interpretations
or older drafts of the spec. The specification's tie-breaking rule only works if both
parsers actually implement it. In the real world:

- Some servers don't support `Transfer-Encoding` in requests at all (it's rare for a
  client to send chunked requests — browsers basically never do, so some server
  codebases never bothered to implement request-side chunked parsing).
- Some servers do support it, but only recognize the header in its exact, precise
  form, and can be tricked into ignoring it if it's spelled or formatted slightly
  differently (more on this in the TE.TE section below).
- Some servers prioritize `Content-Length` over `Transfer-Encoding` even though the
  spec says not to, because they were written before the spec rule was finalized, or
  they prioritize whichever header appears first/last instead of always preferring TE.

When the front-end and the back-end land on **different answers** to "which header
governs the length of this request," you get a desynchronized view of where the
request ends — and that desync is what an attacker weaponizes.

## 4. CL.TE — front-end trusts Content-Length, back-end trusts Transfer-Encoding

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Breakdown:
- `Content-Length: 13` — the front-end honors this header. It counts 13 bytes after
  the blank line: that's `0\r\n\r\nSMUGGLED` (the chunk terminator line plus the word
  `SMUGGLED`). The front-end considers the **entire** request — including the literal
  text `SMUGGLED` — to be the body of this one request, and forwards the whole thing
  unchanged to the back-end as a single unit.
- `Transfer-Encoding: chunked` — the back-end honors *this* header instead and parses
  the body as chunked data.
- `0` — the back-end reads this as a chunk declared to be **zero bytes**. Per the
  chunked-encoding spec, a zero-length chunk means "body ends here." The back-end
  therefore considers the request **finished** at this point.
- `SMUGGLED` — these bytes were never consumed by the back-end's chunked parser,
  because as far as that parser is concerned, the request already ended. The back-end
  leaves `SMUGGLED` sitting in its read buffer, treating it as the **first bytes of
  the next request** that arrives on this reused connection.

This is the mechanism. Whatever real, complete-looking HTTP request text an attacker
puts in place of `SMUGGLED` will get glued onto the front of the next unlucky request
the back-end happens to process on that same TCP connection — which might belong to a
completely different user.

### Real-world framing
CL.TE is the classic, original desync technique documented in PortSwigger's 2019
Black Hat/DEF CON research ("HTTP Desync Attacks: Request Smuggling Reborn"), which
re-popularized this entire vulnerability class after it had first been described back
in 2005. CL.TE shows up constantly in bug bounty reports against architectures using
older or minimally-configured load balancers (legacy HAProxy/NGINX configs, some
CDN edge nodes) sitting in front of app servers that fully support chunked request
bodies (most modern Java/Node/Python web frameworks do).

🔗 **PortSwigger Lab:** *HTTP request smuggling, basic CL.TE vulnerability*

## 5. TE.CL — front-end trusts Transfer-Encoding, back-end trusts Content-Length

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

Breakdown:
- The front-end honors `Transfer-Encoding: chunked`, so it parses this as chunked
  data:
  - `8` — declares the next chunk is 8 bytes. `SMUGGLED` is exactly 8 characters, so
    the front-end reads `SMUGGLED` as that chunk's payload.
  - `0` — a zero-length chunk: terminator. The front-end considers the request
    complete after this point, and forwards the **whole thing** (all of it, since it
    correctly parsed the chunk structure) to the back-end as one request.
- The back-end honors `Content-Length: 3` instead. It reads exactly 3 bytes of body
  after the blank line. Those 3 bytes are `8\r\n` (the chunk-size line for the first
  chunk) — note: the literal character `8` plus the line ending equals 3 bytes. As
  far as the back-end's parser is concerned, the request body is just `8`, and the
  request is now complete.
- Everything after that — `SMUGGLED\r\n0\r\n\r\n` — was never consumed by the
  back-end. It sits in the buffer, waiting to be interpreted as the start of the
  **next** request on the connection. Since `SMUGGLED` itself isn't valid as the
  start of an HTTP request line, a real attack replaces it with an actual request
  (e.g. `GET /admin HTTP/1.1\r\nHost: x\r\n\r\n`) so that the back-end parses it as a
  legitimate next request.

Practical note: when sending this in Burp Repeater, you must uncheck "Update
Content-Length" in the Repeater menu, or Burp will silently recalculate and overwrite
the deliberately-wrong `Content-Length: 3` you need for the attack to work. This trips
up almost everyone the first time they try TE.CL by hand.

### Real-world framing
TE.CL is generally considered the more dangerous variant in mixed infrastructure
because more front-ends (proxies, CDNs, older load balancers) skip chunked-encoding
support on the inbound side entirely, while more back-ends (raw Node `http` servers,
older Apache configs) *do* parse `Transfer-Encoding`, which is exactly the opposite
combination from CL.TE. Because the disagreement is in the other direction, your
probe and confirmation requests have to be built the other way around too — testers
who only ever practice CL.TE often completely miss TE.CL vulnerabilities live.

🔗 **PortSwigger Lab:** *HTTP request smuggling, basic TE.CL vulnerability*

## 6. TE.TE — both servers support chunked encoding, but one can be tricked into ignoring it

This is the subtlest variant. Both the front-end and the back-end *correctly*
implement `Transfer-Encoding: chunked` parsing. The attack instead targets **how
strictly each server validates the literal text of the header name/value**. If you
can obfuscate the header just enough that one server still recognizes it as valid
`Transfer-Encoding: chunked`, while the other server's stricter (or looser) parser
fails to recognize it and falls back to `Content-Length` — you've recreated a CL.TE
or TE.CL situation, just by header trickery instead of by server capability.

Documented obfuscation variants (each is a tiny, deliberate departure from the exact
RFC-compliant header form):

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked        (space before the colon)

Transfer-Encoding: chunked
Transfer-Encoding: x               (duplicate header, second one invalid)

Transfer-Encoding:[tab]chunked     (tab instead of space)

 Transfer-Encoding: chunked        (leading space before the header name)

X: X[\n]Transfer-Encoding: chunked (newline injected into a preceding header value)

Transfer-Encoding
: chunked                          (line break inside the header name)
```

Why these work at all: HTTP/1.1 parsers in the wild are implementations, not the spec
itself, and real parsers tolerate small deviations differently. A front-end built on a
permissive parser might accept `Transfer-Encoding : chunked` (extra space) as valid
chunked encoding, while the back-end's stricter parser sees that extra space, decides
the header name doesn't exactly match `Transfer-Encoding`, and ignores it — falling
back to `Content-Length` instead. You now have a CL.TE-shaped desync, produced purely
by which server is more "forgiving" of malformed input. Swap which server is the
strict one, and you get a TE.CL-shaped desync instead.

Concrete worked example (duplicate Transfer-Encoding header, second value garbage):

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: cow

5c
GET /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

- Two `Transfer-Encoding` headers are present. One server in the chain (commonly the
  front-end) takes the *last* declared value (`cow`) as authoritative, decides that's
  not a recognized encoding, and falls back to `Content-Length: 4` — reading only
  `5c\r\n` (4 bytes) as the body and forwarding the rest untouched.
- The other server (commonly the back-end) takes the *first* declared value
  (`chunked`) as authoritative and parses everything as chunked: `5c` (92 in hex) bytes
  of chunk data containing the smuggled `GET /admin...` request, followed by the
  zero-length terminator chunk.
- Net effect: identical mechanism to CL.TE, just achieved by exploiting which
  duplicate header each parser trusts rather than by one server lacking TE support
  altogether.

### Real-world framing
TE.TE is the variant most likely to survive against infrastructure that has already
been "hardened" against the basic CL.TE/TE.CL pair — for instance, environments where
an engineering team patched their load balancer to always support
`Transfer-Encoding`, assuming that was sufficient. It wasn't: supporting the header is
not the same as parsing it identically to every other server in the chain. This is
also the variant most directly targeted by Burp's automated request-smuggling scan
checks and by the **HTTP Request Smuggler** Burp extension (covered in its own file in
this series), because manually enumerating every obfuscation permutation by hand does
not scale.

🔗 **PortSwigger Lab:** *HTTP request smuggling, obfuscating the TE header*

## 7. Why this is HTTP/1.1-specific (and what changes with HTTP/2)

HTTP/2 replaced the text-based header/length model entirely with a binary framing
layer that has a single, unambiguous length field per frame — there is no
`Content-Length` vs `Transfer-Encoding` choice to be confused about. A website that
genuinely speaks HTTP/2 **end-to-end**, front-end to back-end, is inherently immune to
the classic CL.TE/TE.CL/TE.TE techniques in this file.

In practice, though, very few back-end application stacks speak HTTP/2 natively. The
overwhelmingly common real architecture is: client speaks HTTP/2 to an edge/CDN/load
balancer, and that front-end then **downgrades** the request to HTTP/1.1 before
forwarding it to the back-end. That downgrade step reintroduces exactly the same
length-declaration ambiguity discussed above, plus an entirely new set of
HTTP/2-specific smuggling vectors (H2.CL, H2.TE, pseudo-header injection, and more).
Those downgrading-specific techniques are out of scope for this file and are flagged
honestly as an advanced/expert-tier topic in the final cheatsheet file of this series,
since they involve a distinct lab set and a different attacker workflow.

## 8. The one-sentence mental model to keep

> **Every smuggling technique is just answering one question differently between two
> servers: "where does this request's body end?" — and then placing a second,
> attacker-controlled request right where that disagreement leaves a gap.**

Everything in the rest of this series — detection, exploitation outcomes, and
tooling — is built directly on this single idea.
