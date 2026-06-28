# HTTP Request Smuggling — Cheatsheet & PortSwigger Lab Mapping

Quick-reference companion to the rest of this series. Use this file to jump straight
to a payload skeleton or to check which Academy lab matches which technique —
detailed mechanism explanations live in the other files, referenced inline below.

## 1. Quick payload skeletons

### CL.TE timing probe
```
POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
See `02-detection-techniques.md` §2.

### TE.CL timing probe (only after CL.TE probe is clean)
```
POST / HTTP/1.1
Host: TARGET
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
See `02-detection-techniques.md` §3.

### CL.TE exploitation skeleton
```
POST / HTTP/1.1
Host: TARGET
Content-Length: <bytes through end of "0\r\n\r\n" + SMUGGLED-REQUEST>
Transfer-Encoding: chunked

0

SMUGGLED-REQUEST-HERE
```
See `01-concept-and-root-cause.md` §4.

### TE.CL exploitation skeleton
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

<hex-length-of-SMUGGLED-REQUEST>
SMUGGLED-REQUEST-HERE
0

```
Remember: uncheck "Update Content-Length" in Burp Repeater. Include trailing
`\r\n\r\n` after the final `0`. See `01-concept-and-root-cause.md` §5.

### TE.TE obfuscation header variants to fuzz
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked / Transfer-Encoding: x   (duplicate)
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding\n: chunked
```
See `01-concept-and-root-cause.md` §6. In practice, fuzz this list with the **HTTP
Request Smuggler** extension's probe rather than by hand — see
`04-burp-http-request-smuggler-extension.md`.

## 2. Decision tree

```
1. Send CL.TE timing probe.
   ├─ Delay observed? → confirm with CL.TE differential-response test
   │                      → if confirmed, you have CL.TE → move to exploitation
   └─ No delay → go to step 2

2. Send TE.CL timing probe.
   ├─ Delay observed? → confirm with TE.CL differential-response test
   │                      → if confirmed, you have TE.CL → move to exploitation
   └─ No delay → go to step 3

3. Fuzz Transfer-Encoding obfuscation variants (manually or via extension).
   ├─ One variant desyncs the two servers → you have TE.TE
   │   → determine which side ignored the header → treat the rest of the attack
   │     as CL.TE-shaped or TE.CL-shaped accordingly
   └─ No variant works → consider HTTP/2 downgrade-specific vectors (H2.CL, H2.TE)
       or browser-powered/client-side desync vectors — both out of this series'
       core scope, see §5 below
```

## 3. Exploitation outcome quick index

| Goal | Technique | Detail file |
|---|---|---|
| Bypass an access-control gate | Smuggle a request to the restricted path | `03-exploitation-outcomes.md` §2 |
| Discover front-end-injected headers | Open-ended reflected `email=` parameter | `03-exploitation-outcomes.md` §3 |
| Forge a trusted internal header | Smuggled request with forged header | `03-exploitation-outcomes.md` §3 |
| Steal another user's session/cookie | Open-ended storage-feature request | `03-exploitation-outcomes.md` §4 |
| Deliver XSS without victim interaction | Payload in a smuggled header | `03-exploitation-outcomes.md` §5 |
| Turn an on-site redirect into open redirect | Forged `Host` on smuggled request | `03-exploitation-outcomes.md` §6 |
| Poison the cache for all users | Malicious redirect glued to a static URL | `03-exploitation-outcomes.md` §7 |
| Leak a victim's private content via cache | Private-content request glued to a static URL | `03-exploitation-outcomes.md` §8 |

## 4. PortSwigger Web Security Academy — Lab Mapping (Academy progression order)

This is the dedicated, well-developed lab set for this category, listed in the order
they appear on the Academy. PortSwigger explicitly recommends running the CL.TE test
before the TE.CL test in real testing to minimize disruption to other users — that
same caution applies to working through these labs in order, since later labs build
directly on the mechanics taught in earlier ones.

| # | Lab title | Technique covered | Series file |
|---|---|---|---|
| 1 | HTTP request smuggling, basic CL.TE vulnerability | CL.TE, basic exploitation | `01-concept-and-root-cause.md` §4 |
| 2 | HTTP request smuggling, basic TE.CL vulnerability | TE.CL, basic exploitation | `01-concept-and-root-cause.md` §5 |
| 3 | HTTP request smuggling, obfuscating the TE header | TE.TE via duplicate/obfuscated header | `01-concept-and-root-cause.md` §6 |
| 4 | HTTP request smuggling, confirming a CL.TE vulnerability via differential responses | Detection/confirmation | `02-detection-techniques.md` §4 |
| 5 | HTTP request smuggling, confirming a TE.CL vulnerability via differential responses | Detection/confirmation | `02-detection-techniques.md` §4 |
| 6 | Exploiting HTTP request smuggling to bypass front-end security controls, simple | Access-control bypass | `03-exploitation-outcomes.md` §2 |
| 7 | Exploiting HTTP request smuggling to bypass front-end security controls, advanced | Access-control bypass (harder variant) | `03-exploitation-outcomes.md` §2 |
| 8 | Exploiting HTTP request smuggling to reveal front-end request rewriting | Header-rewrite discovery | `03-exploitation-outcomes.md` §3 |
| 9 | Exploiting HTTP request smuggling to capture other users' requests | Session/credential theft | `03-exploitation-outcomes.md` §4 |
| 10 | Exploiting HTTP request smuggling to deliver reflected XSS | Zero-interaction XSS | `03-exploitation-outcomes.md` §5 |
| 11 | Exploiting HTTP request smuggling to perform web cache poisoning | Persistent mass-impact redirect | `03-exploitation-outcomes.md` §7 |
| 12 | Exploiting HTTP request smuggling to perform web cache deception | Private-data leak via cache | `03-exploitation-outcomes.md` §8 |

## 5. Honest disclosure — advanced/expert-tier labs beyond this series' scope

The Academy's request smuggling topic goes considerably further than the 12 core
labs mapped above — PortSwigger has stated the topic now includes over 20 free,
hands-on labs in total. This series deliberately focuses on the classic HTTP/1.1
CL.TE/TE.CL/TE.TE foundation, since that's the prerequisite for everything else in
the category and is what was scoped for this note set. The additional, more advanced
material that exists on the Academy but is **not** covered file-by-file in this
series includes:

- **HTTP/2-specific downgrade smuggling** — H2.CL and H2.TE vulnerabilities, plus
  HTTP/2-exclusive injection vectors (CRLF injection, pseudo-header injection,
  ambiguous Host/path injection). Conceptually these are the same root cause
  (length-declaration disagreement) reintroduced specifically by the HTTP/2-to-1.1
  downgrade step described in `01-concept-and-root-cause.md` §7.
- **Response queue poisoning** — a more advanced consequence of request smuggling
  where the *response* queue, not just the request queue, gets desynchronized,
  enabling theft of other users' entire responses rather than just request
  fragments.
- **HTTP request tunnelling** — a related but distinct technique (no full
  desynchronization required) for hiding a request inside another one.
- **Browser-powered / client-side desync attacks** — CL.0 vulnerabilities and
  client-side desync techniques that work using fully browser-compatible requests
  (a perfectly normal `Content-Length` header), meaning a victim's own browser can
  be induced to desync its own connection — this removes the need for raw malformed
  requests entirely and is one of PortSwigger's most significant recent research
  directions in this space (`Browser-Powered Desync Attacks`, presented at Black Hat
  USA and DEF CON).
- **Pause-based desync attacks** — exploiting processing delays/timing rather than
  pure header-parsing disagreements to force a desync.

If you intend to build the equivalent multi-file depth for these as a follow-on
series, the natural split would be: one file for HTTP/2 downgrade vectors (H2.CL/
H2.TE/pseudo-header injection), one for response queue poisoning, one for request
tunnelling, and one for the full browser-powered/client-side desync family
(CL.0 + client-side desync + pause-based desync) — each of those is a substantial
topic on its own and deserves the same line-by-line treatment as this core series,
rather than being compressed into a short addendum here.

## 6. Defense / prevention checklist (for completeness in writeups)

When writing a finding report, the standard, defensible remediation guidance is:

- Use HTTP/2 end-to-end and disable HTTP downgrading wherever possible — HTTP/2's
  single, robust length mechanism is inherently immune to this entire class.
- If downgrading can't be avoided, validate the rewritten HTTP/1.1 request strictly
  against the spec before forwarding (reject newlines in headers, colons in header
  names, spaces in the method, etc.).
- Make the front-end normalize ambiguous requests, and make the back-end reject any
  request that's still ambiguous after that — closing the TCP connection rather than
  guessing.
- Never assume a request "won't have a body" — this assumption is the root cause of
  both CL.0 and client-side desync vulnerabilities.
- Disable backend connection reuse if request volume allows it, understanding this
  still does not protect against request tunnelling attacks specifically.

## 7. Real-world severity framing for reports/bounty submissions

Request smuggling consistently ranks among the highest-paying bug classes in modern
bug bounty programs, specifically because the *blast radius* is structural rather
than per-victim: a successful smuggling chain into cache poisoning or queue poisoning
can compromise every subsequent visitor to a cached resource, or an arbitrary
unrelated authenticated user's session, not just the tester's own account. James
Kettle's most recent research (`HTTP/1.1 Must Die: The Desync Endgame`, presented at
Black Hat USA and DEF CON 2025) makes the case that this is not a legacy or
fully-patched category — it remains rampant and underestimated across tens of millions of supposedly well-secured websites worldwide, precisely because consistently determining HTTP/1.1 request boundaries across chains of interconnected systems is fundamentally difficult, not just a matter of a few known bad payloads to block. That framing — that this is a structural, ongoing protocol-level risk rather than a fixed-and-done vulnerability class — is worth keeping front and center in any report, since it's exactly the argument that justifies high severity and high payout.
