# HTTP & HTTPS Fundamentals

---

## 1. What HTTP Actually Is

HTTP (HyperText Transfer Protocol) is a **plain-text, request-response protocol**. A 
client (browser, curl, Burp) sends a request; a server sends back a response. That's the 
entire model — everything else in web security is built on manipulating pieces of this 
exchange.

## 2. Anatomy of an HTTP Request

```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Cookie: session=abc123

username=admin&password=test
```

Breaking this down line by line:
- **`POST /login HTTP/1.1`** — the request line: HTTP method (`POST`), the path being 
  requested (`/login`), and the HTTP version (`1.1`)
- **`Host: example.com`** — tells the server which website you want (critical when one 
  server hosts multiple sites — see Host header injection in the advanced notes)
- **`Content-Type: application/x-www-form-urlencoded`** — tells the server how to parse 
  the body that follows (form data here; could be `application/json`, 
  `multipart/form-data` for file uploads, etc.)
- **`Content-Length: 29`** — exact byte length of the body; the server uses this to know 
  where the request ends (this exact field is the basis of HTTP Request Smuggling — see 
  that note series later)
- **`Cookie: session=abc123`** — sends back any cookies the server previously set
- Blank line — separates headers from the body
- **`username=admin&password=test`** — the body/payload itself

## 3. Anatomy of an HTTP Response

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Set-Cookie: session=xyz789; HttpOnly; Secure
Content-Length: 1024

<html>...</html>
```
- **`HTTP/1.1 200 OK`** — status line: protocol version, status code, status text
- **`Set-Cookie`** — the server instructing the browser to store a cookie (see file 03 
  for the security-relevant attributes here)
- The blank line and body work the same way as in the request

## 4. HTTP Methods You'll Actually Encounter

| Method | Purpose | Pentest relevance |
|---|---|---|
| `GET` | Retrieve data, no body | Most injection points start here (URL parameters) |
| `POST` | Submit data, has a body | Form submissions, login, most state-changing actions |
| `PUT` | Replace a resource entirely | Sometimes left enabled accidentally — can allow file upload/overwrite |
| `DELETE` | Remove a resource | Relevant to Broken Access Control testing (can you delete someone else's resource?) |
| `PATCH` | Partially update a resource | Same access-control relevance as PUT/DELETE |
| `OPTIONS` | Ask what methods/headers are allowed | Used during CORS preflight checks — directly relevant to the CORS notes |
| `HEAD` | Like GET but no body returned | Useful for checking if a resource exists without downloading it |

**Real-world note:** always test if "blocked" methods are actually disabled at the 
application layer or just hidden from the UI — `PUT`/`DELETE` left enabled on an API 
that the frontend never uses is a common real-world finding.

## 5. HTTP Status Codes Worth Knowing by Heart

| Range | Meaning | Pentest relevance |
|---|---|---|
| 2xx | Success | `200 OK` is normal; differences in body length on otherwise-identical 200 responses are a classic boolean-blind signal |
| 3xx | Redirection | `301`/`302`/`307` — the `Location` header here is exactly what Open Redirect abuses |
| 4xx | Client error | `401` Unauthorized vs `403` Forbidden distinction matters for access control testing — `401` means "you're not authenticated," `403` means "you're authenticated but not allowed" |
| 5xx | Server error | Error-based SQLi and most "something broke server-side" signals show up here |

## 6. HTTPS — What TLS Actually Does (Just Enough to Matter)

HTTPS = HTTP **wrapped in TLS encryption**. The handshake, simplified:
1. Client connects, says "here are the TLS versions/ciphers I support" (`ClientHello`)
2. Server responds with its certificate and chosen cipher (`ServerHello` + Certificate)
3. Client verifies the certificate against trusted Certificate Authorities (CAs)
4. Both sides derive a shared symmetric encryption key for the actual session

**Why you need to know this much:**
- Certificate validation failures (self-signed certs, expired certs, wrong hostname) are 
  a common finding category on their own
- Mixed content issues (an HTTPS page loading an HTTP resource) break the security 
  guarantee and are flagged in real assessments
- TLS misconfiguration (weak ciphers, outdated protocol versions like TLS 1.0/1.1) is 
  tested with `testssl.sh` (covered in depth in the Cryptographic Failures notes)
- HTTPS encrypts the channel — it does **not** validate or sanitize anything inside the 
  request/response. SQLi, XSS, every vulnerability in this repo works exactly the same 
  over HTTPS as over HTTP; encryption protects data in transit, not application logic

## 7. Real-World Notes
- Browser dev tools (Network tab) show you the same request/response structure covered 
  here — get comfortable reading raw requests there before you even open Burp.
- Every payload you'll ever inject (SQLi, XSS, command injection, etc.) gets delivered 
  through one of these exact structures — a URL parameter, a header value, a body field, 
  or a cookie value. There is no other delivery mechanism in standard web exploitation.
- When a request "looks normal" but something is broken in your testing, the first 
  troubleshooting step is always: re-read the raw request/response in Burp/Repeater and 
  check Content-Length matches the actual body, headers are correctly formatted, and the 
  method/path match what you intended.

Continue to → `02_HTTP_Headers_Complete_Reference.md`
