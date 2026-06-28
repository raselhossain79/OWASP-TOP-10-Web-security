# URL Structure & Encoding

> Nearly every WAF bypass and filter evasion technique across this entire repo is some 
> variation of "encode the payload differently so the filter doesn't recognize it but 
> the server still decodes it correctly." This file is the foundation for all of that.

---

## 1. Anatomy of a URL

```
https://user:pass@example.com:8443/path/to/page?id=1&name=test#section
  │       │            │        │       │            │            │
scheme  userinfo      host     port    path        query        fragment
```
- **scheme** — `http`/`https`
- **userinfo** — rarely used now, embeds credentials directly (legacy, and itself a 
  source of bypass tricks — `https://trusted.com@evil.com` visually looks like 
  trusted.com but actually goes to evil.com)
- **host** — the domain or IP
- **port** — defaults to 80 (HTTP) or 443 (HTTPS) if omitted
- **path** — the resource location
- **query** — `key=value` pairs after `?`, separated by `&`
- **fragment** — after `#`, **never sent to the server at all** — purely client-side 
  (this is exactly why DOM-based XSS via `location.hash` is a distinct category — the 
  server never sees this part, so server-side filtering can't catch it)

## 2. URL Encoding (Percent-Encoding)

Characters that aren't allowed raw in a URL get represented as `%` followed by their 
hex byte value:
```
space  → %20  (or + in query strings specifically)
'      → %27
"      → %22
<      → %3C
>      → %3E
/      → %2F
\n (newline) → %0A
\r (carriage return) → %0D
```
**Why this matters for nearly every bypass technique in this repo:** a single-encoded 
payload often gets caught by a WAF/filter, but if the application decodes input twice 
(once at the WAF/proxy layer, once at the application layer) — a **double-encoded** 
payload can sail through:
```
'           → single-encode → %27        → double-encode → %2527
```
This exact mechanic is the basis of the double-encoding WAF bypass mentioned in the 
SQLi notes and reused across several other note series.

## 3. Other Encodings You'll See Reused Constantly

| Encoding | Example | Where it shows up |
|---|---|---|
| **Base64** | `YWRtaW4=` (= "admin") | JWT structure, `php://filter` LFI-to-RCE chains, sometimes hidden in cookies/params |
| **Hex** | `0x61646d696e` (= "admin" in MySQL) | SQLi payload obfuscation, avoiding quote characters |
| **Unicode escapes** | `\u003c` (= `<`) | XSS filter bypass, JS string context payloads |
| **HTML entity encoding** | `&lt;` (= `<`), `&#x3c;` | XSS context-specific bypass when output is HTML-encoded inconsistently |
| **CRLF sequence** | `%0d%0a` | CRLF Injection — this literally IS the payload, not just an obfuscation trick |

## 4. Why Encoding Inconsistency Is the Root of So Many Bugs

The recurring pattern across this entire repo:
```
Layer 1 (WAF/proxy) decodes the input ONE way
Layer 2 (application/database) decodes the SAME input a DIFFERENT way or AGAIN
                    │
                    ▼
   The two layers disagree about what the actual payload is
                    │
                    ▼
        This disagreement IS the vulnerability
```
This single pattern explains: WAF bypass via double-encoding, HTTP Request Smuggling 
(disagreement about where a request ends), HPP (disagreement about which duplicate 
parameter value is "the real one"), and several charset/encoding-based XSS filter 
bypasses.

## 5. Real-World Notes
- Burp's **Decoder** tool (covered in file 07) is built specifically around this — 
  you'll use it constantly to encode/decode/hash values while building payloads.
- When a payload "should work" based on the theory but doesn't, encoding mismatch is one 
  of the first things to check — is your payload getting encoded by your tool before 
  it's sent, and is that double-encoding it on top of the target's own decoding?
- Always test how an application handles **already-encoded characters in input** — 
  sending a literal `%27` vs an actual `'` character sometimes produces different 
  behavior and reveals where encoding/decoding happens in the request pipeline.

Continue to → `06_Web_Architecture_Basics.md`
