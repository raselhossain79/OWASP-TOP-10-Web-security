# 06 — Filter and WAF Bypass for CRLF Injection

## Why signature-based detection targets `%0d%0a` specifically

Most WAF rulesets and naive in-app filters detect CRLF injection by
pattern-matching on the literal encoded sequence `%0d%0a` (and its
case variants `%0D%0A`, `%0d%0A`, etc.) in request parameters, plus
sometimes the raw, unencoded `\r` and `\n` bytes. This is a signature
match, not a parser-level understanding of HTTP framing — which means it
inherits the same weakness every regex-based filter does: it can only catch
the encodings it was told to look for. Every technique in this file
exploits a gap between "what the filter's regex recognizes" and "what the
upstream parser (browser, proxy, back-end server) will still decode and
act on."

Always confirm the actual upstream component you're trying to reach
(application-level decoder vs. WAF vs. CDN edge) — different layers decode
percent-encoding, case, and Unicode differently, and the bypass that works
against one will not necessarily work against another in the same request
path.

## Technique 1 — case manipulation

Some older or poorly configured filters match `%0d%0a` as a literal,
case-sensitive string and miss case variants, because percent-encoded hex
digits are case-insensitive in the HTTP specification — `%0D` and `%0d` are
defined as byte-for-byte identical, decoding to the exact same `0x0D` byte.

```
%0D%0A
%0d%0A
%0D%0a
```

Breaking this down: there is nothing clever happening at the protocol
level here — the bypass is purely that the **filter's regex** was written
to match one case pattern (commonly lowercase, since that's what most
payload examples online use) and never accounted for the fact that hex
encoding is case-insensitive by specification. The decoder downstream
doesn't care about case at all; it decodes `%0D` and `%0d` to the identical
byte. This is the single easiest bypass to test for, and the first thing to
try against any filter that appears to block the lowercase form.

## Technique 2 — double encoding

```
%250d%250a
```

Breaking this down:

| Fragment | Decodes to (1st pass) | Decodes to (2nd pass) |
|---|---|---|
| `%25` | `%` | (already final) |
| `%250d` | `%0d` | `\r` |
| `%250a` | `%0a` | `\n` |

`%25` is the URL-encoding of the `%` character itself. If a filter
URL-decodes the input **once** to check for `%0d%0a` and finds only `%0d%0a`
written as `%250d%250a` (which decodes on the *first* pass to the literal
*text* `%0d%0a`, not yet to the actual CR/LF bytes), the filter sees no raw
CR/LF and passes it through. The bypass only works if something
**downstream of the filter decodes the value a second time** — which
happens more often than expected when a request passes through multiple
layers (CDN edge decodes once, origin application framework decodes again
when reading the parameter). Always verify there actually is a second
decode step in the target's request pipeline; double encoding does nothing
against a single-decode pipeline.

## Technique 3 — Unicode / overlong UTF-8 encoding

```
%E5%98%8A%E5%98%8D
```

Breaking this down: these are not standard CRLF encodings — they are bytes
that some specific, non-standard decoders have been found to normalize down
to `\r` and `\n` due to malformed/overlong UTF-8 decoding bugs (lenient
decoders that don't reject invalid byte sequences and instead "helpfully"
collapse them to the nearest valid character). This is a decoder-specific
quirk, not a general technique — it only works against the exact decoder
implementation it was discovered against (this is the same family of
overlong-UTF-8 tricks used historically against path traversal and XSS
filters). Test it opportunistically against older or custom decoders; do
not expect it to work against modern, spec-compliant HTTP/Unicode parsing.

## Technique 4 — alternate line-ending bytes

The HTTP/1.x spec mandates `\r\n`, but many real-world parsers are lenient
and accept either byte alone as a line terminator, for compatibility with
older systems (classic Mac OS used bare `\r`, Unix uses bare `\n`):

```
%0a          (bare LF only)
%0d          (bare CR only)
```

Breaking this down: a filter built specifically to detect the *pair*
`%0d%0a` together will often miss a single `%0a` or `%0d` submitted alone,
because the filter's signature is the two-byte sequence, not either byte
individually. Whether this actually achieves header injection depends
entirely on how lenient the **target's own parser** is — test both bytes
independently against the actual sink, since a permissive HTTP/1.x parser
on the back-end will frequently still treat a lone `\n` as a line
terminator even though the spec says it shouldn't.

## Technique 5 — null-byte and whitespace injection inside the sequence

```
%0d%00%0a
%0d%09%0a    (tab byte between CR and LF)
```

Breaking this down: this targets filters that match `%0d%0a` as an
*adjacent, unbroken* string. Inserting a byte the filter doesn't expect
between the `%0d` and `%0a` breaks the literal-string match while the
target's own decoder may strip or ignore the inserted byte (especially the
null byte, `%00`, which many older C-based parsers historically
mishandled) and still arrive at a working `\r\n` once the inserted byte is
discarded. This is highly parser-specific — confirm behavior empirically
against the actual target rather than assuming it works.

## Technique 6 — HTTP/2 header-value injection (bypasses CRLF filters
entirely)

This is the most reliable bypass against any filter that's looking for
`%0d%0a`-style percent-encoded text in the request line or query string:
**don't send the CRLF as encoded text at all.** As covered in file `03`,
HTTP/2 carries headers as discrete binary fields, so a literal `\r\n` byte
sequence inside an HTTP/2 header value is not URL-encoded text the WAF can
pattern-match against — it's two raw bytes inside a field the WAF's
text-based regex engine was never built to inspect the same way. A WAF
tuned to catch `%0d%0a` in query strings and form bodies frequently has no
equivalent inspection logic for raw bytes inside HTTP/2 header field
values, especially if the WAF itself operates on HTTP/1.x semantics
internally. This is precisely why the request-smuggling-via-CRLF labs in
file `03` use Burp's Inspector (Shift+Return inside a header value) rather
than a URL-encoded payload — there's no encoding to bypass; the bytes are
just there.

## Practical bypass methodology

When a WAF or filter blocks an obvious `%0d%0a` payload:

1. Confirm it's actually the CRLF sequence being blocked, not something
   else in the payload (isolate variables — submit `%0d%0a` alone with no
   other payload content first).
2. Try case variants (Technique 1) — cheapest test, highest hit rate
   against naive filters.
3. Identify how many decode passes happen between the filter and the
   sink (test with a single `%25`-prefixed value and observe whether it
   round-trips through one or two decodes) before trying double encoding
   (Technique 2).
4. Test bare `%0a` and `%0d` independently (Technique 4) — many WAFs only
   signature-match the pair.
5. If the front end is HTTP/2-capable, test the header-value-injection
   route (Technique 6) directly via Burp's Inspector rather than the
   browser/URL bar — this sidesteps URL-encoding-based filters entirely.

## Real-world note

In real WAF evaluations (Cloudflare, AWS WAF, Akamai, ModSecurity-based
deployments), the case and double-encoding bypasses above are exactly the
class of technique vendors patch reactively after disclosure — meaning
what bypasses a given WAF version today may be patched within months.
Always re-test bypass techniques against the current version of the
target's WAF rather than relying on a technique that worked in an older
write-up; this is a fast-moving cat-and-mouse area, not a stable list of
guaranteed bypasses.
