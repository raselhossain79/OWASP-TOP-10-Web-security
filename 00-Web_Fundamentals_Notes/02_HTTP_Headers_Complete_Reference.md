# HTTP Headers — Complete Reference for Pentesting

> This file exists because headers appear, get manipulated, or get checked in almost 
> every single vulnerability category in this repo. Treat this as the reference you 
> come back to whenever a later note mentions a header you don't immediately recognize.

---

## 1. Request Headers (sent by the client)

| Header | What it does | Where it shows up later in this repo |
|---|---|---|
| `Host` | Tells the server which site you want | Host Header Injection, Password Reset Poisoning notes |
| `User-Agent` | Identifies the browser/client | Sometimes a blind injection point (apps that log it unsafely); fingerprinting/recon |
| `Referer` | The page you came from | Open Redirect / CSRF-protection-bypass relevance (some apps check Referer instead of a real token) |
| `Cookie` | Sends stored cookies back to the server | Session management, almost every auth-related vuln |
| `Authorization` | Carries credentials — `Basic`, `Bearer <token>` | JWT attacks, API auth testing |
| `Content-Type` | Tells the server how to parse the body | Mass Assignment, file upload (`multipart/form-data`), API testing (`application/json`) |
| `Content-Length` | Byte length of the body | HTTP Request Smuggling (CL.TE/TE.CL confusion) |
| `Transfer-Encoding` | Alternative to Content-Length, body sent in chunks | HTTP Request Smuggling — this header is the other half of the smuggling root cause |
| `X-Forwarded-For` | Claims the "real" client IP behind a proxy | IP spoofing for rate-limit/auth bypass — covered in Auth Failures rate-limit bypass file |
| `X-Forwarded-Host` | Claims the "real" Host behind a proxy | Host Header Injection, Web Cache Poisoning (unkeyed header) |
| `Origin` | The origin a cross-origin request came from | CORS, CSRF protection checks |
| `If-Modified-Since` / `If-None-Match` | Caching/conditional request headers | Web Cache Poisoning recon |

## 2. Response Headers (sent by the server)

| Header | What it does | Where it shows up later in this repo |
|---|---|---|
| `Set-Cookie` | Server tells the browser to store a cookie | Cookie security attributes — see file 03 |
| `Content-Security-Policy` (CSP) | Restricts what scripts/resources a page can load | CSP bypass file in the XSS notes |
| `X-Frame-Options` | Controls whether the page can be embedded in an iframe | Clickjacking notes |
| `Access-Control-Allow-Origin` | Tells the browser which origins can read the response | CORS Misconfiguration notes — this is THE header that gets misconfigured |
| `Access-Control-Allow-Credentials` | Whether cookies/auth are included in cross-origin requests | Combined with a bad `Allow-Origin`, this is the core CORS vulnerability |
| `Strict-Transport-Security` (HSTS) | Forces the browser to only use HTTPS for this domain | TLS/transport security checks |
| `X-Content-Type-Options: nosniff` | Stops the browser from guessing content type | Reduces some XSS/file-upload abuse vectors when missing |
| `Cache-Control` / `ETag` | Caching directives | Web Cache Poisoning — understanding cache behavior |
| `Location` | Where to redirect to (used with 3xx codes) | Open Redirect — this header is literally the vulnerability |
| `Server` / `X-Powered-By` | Reveals server software/version | Recon, Vulnerable Components fingerprinting |

## 3. Security Headers — Quick "What Happens If Missing" Table

| Header | If missing... |
|---|---|
| `Content-Security-Policy` | Browser has no extra restriction on inline scripts — XSS impact is higher |
| `X-Frame-Options` (or CSP `frame-ancestors`) | Page can be framed by anyone — clickjacking is possible |
| `Strict-Transport-Security` | First connection to the site can be intercepted before HTTPS is enforced |
| `Secure` cookie attribute | Cookie can be sent over plain HTTP, exposing it to network interception |
| `HttpOnly` cookie attribute | Cookie is readable by JavaScript — directly increases XSS impact (session theft via `document.cookie`) |

This table alone explains why "missing security headers" is such a common Security 
Misconfiguration finding — each missing header doesn't cause a vulnerability by itself, 
but it removes a layer of defense against vulnerabilities found elsewhere.

## 4. Headers That Commonly Get Trusted (and Shouldn't)

This is the pattern behind several vulnerability classes in this repo: an application 
trusts a header value that the **client fully controls**, and uses it for something 
security-relevant.

```
X-Forwarded-For: 127.0.0.1        → used for IP-based access control or rate limiting
X-Forwarded-Host: evil.com         → used to build password reset links, redirects
X-Original-URL / X-Rewrite-URL     → used by some frameworks for internal routing, 
                                      sometimes bypasses path-based access rules
```
**The underlying lesson:** any header without a server-side cryptographic guarantee 
(unlike, say, a properly validated session cookie) is just a string the client typed in 
— treat every header as untrusted input, the same way you'd treat a form field.

## 5. Real-World Notes
- Burp's Proxy → HTTP history is where you'll actually see every header discussed here 
  in real traffic — read this file once, then go watch real requests in Burp to make it 
  concrete.
- A huge number of real-world findings are just "the app trusts a header it shouldn't" — 
  Host header trust, X-Forwarded-* trust, and Origin-reflection in CORS are the three 
  most common versions of this single root pattern.
- When you start a new target, get in the habit of opening Burp's Repeater and just 
  removing/modifying headers one at a time on a normal authenticated request — you'll 
  be surprised how often removing a header that "shouldn't matter" changes behavior.

Continue to → `03_Cookies_and_Sessions.md`
