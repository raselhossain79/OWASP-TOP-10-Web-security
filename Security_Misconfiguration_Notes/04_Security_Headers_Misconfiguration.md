# 04 — Missing or Misconfigured Security Headers

## What it is

HTTP security headers are response headers that instruct the browser to enforce extra protections
on behalf of the user — restricting what a page is allowed to load, embed, or be embedded into,
and how it handles transport security. Missing or weak configuration of these headers does not
create a vulnerability by itself in most cases, but it **removes a defensive layer** that limits
the impact of other bugs (especially XSS and clickjacking). This is why header misconfiguration
is graded as a security misconfiguration issue rather than a standalone vulnerability class.

## The core headers, one by one

### 1. Content-Security-Policy (CSP)

**What it does:** Tells the browser which sources are allowed to load scripts, styles, images,
fonts, frames, etc. on the page. A correctly scoped CSP can prevent injected `<script>` tags from
executing even if an XSS bug exists elsewhere in the application.

**Common misconfigurations:**
- Missing entirely.
- `script-src 'unsafe-inline'` — allows any inline `<script>` block to execute, defeating most of
  CSP's anti-XSS value.
- `script-src *` or overly broad wildcard domains (e.g., `*.amazonaws.com` for a CDN, which any
  customer of that cloud provider could host content under).
- Using `'unsafe-eval'`, which permits `eval()` and similar dynamic code execution.

**How to inspect it:**

```bash
curl -sI https://target.example.com | grep -i content-security-policy
```

- `curl -sI` — `-s` silences progress output, `-I` sends a `HEAD` request and prints only the
  response headers (no body needed, since we only care about header presence/content).
- `grep -i content-security-policy` — case-insensitively filter the output to the
  `Content-Security-Policy` line, since header names are case-insensitive per the HTTP spec but
  `grep` is not by default.

### 2. Strict-Transport-Security (HSTS)

**What it does:** Instructs the browser to only ever connect to this domain over HTTPS for a
specified duration, even if the user types `http://` or clicks an `http://` link. Without it, a
user's very first connection (or any connection after the HSTS cache expires) is vulnerable to an
SSL-stripping man-in-the-middle attack.

**Common misconfigurations:**
- Missing entirely.
- `max-age` set too low (e.g., a few minutes instead of the recommended minimum of 6 months —
  `31536000` seconds is the common "1 year" value used in production).
- Missing `includeSubDomains`, leaving subdomains unprotected.

**How to inspect it:**

```bash
curl -sI https://target.example.com | grep -i strict-transport-security
```

(Flag breakdown identical to the CSP check above.)

### 3. X-Frame-Options / frame-ancestors

**What it does:** Controls whether the page can be loaded inside an `<iframe>` on another site.
This is the primary defense against clickjacking. (Note: `frame-ancestors` inside CSP is the
modern replacement/supplement for `X-Frame-Options` and takes precedence in browsers that support
it.)

**Common misconfigurations:**
- Missing entirely (page can be framed by any origin).
- `X-Frame-Options: ALLOW-FROM` used (deprecated and unsupported in most modern browsers, which
  means it provides **no actual protection** despite looking configured).

**How to inspect it:**

```bash
curl -sI https://target.example.com | grep -iE "x-frame-options|frame-ancestors"
```

- `grep -iE` — `-E` enables extended regex so the `|` alternation operator works, letting this
  single command check for either header name.

### 4. X-Content-Type-Options

**What it does:** When set to `nosniff`, this stops the browser from trying to "guess" (MIME-sniff)
a different content type than the one declared in `Content-Type`. Without it, a browser might
render an uploaded file (e.g., one declared as `text/plain`) as HTML/JavaScript if its content
looks like markup — opening a path to stored XSS via file upload functionality.

**How to inspect it:**

```bash
curl -sI https://target.example.com/uploads/some-file | grep -i x-content-type-options
```

### 5. Referrer-Policy

**What it does:** Controls how much of the current page's URL is sent in the `Referer` header
when the user navigates to (or loads a resource from) another origin. A missing or overly
permissive policy (`unsafe-url`) can leak sensitive data embedded in URLs — session tokens,
password-reset tokens, internal search queries — to third-party domains.

**How to inspect it:**

```bash
curl -sI https://target.example.com | grep -i referrer-policy
```

### 6. Permissions-Policy (formerly Feature-Policy)

**What it does:** Restricts which browser features/APIs (camera, microphone, geolocation, USB,
etc.) the page and any embedded iframes are allowed to use. Missing this doesn't directly create
a vulnerability, but it widens the blast radius if an attacker manages to inject content (e.g.,
via XSS or a malicious ad) that tries to invoke a sensitive browser API.

**How to inspect it:**

```bash
curl -sI https://target.example.com | grep -i permissions-policy
```

## A single combined audit command

```bash
curl -sI https://target.example.com | grep -iE \
  "content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy"
```

- This is simply the same `curl -sI` header dump piped into one `grep -iE` call with all six
  header names joined by `|` (OR), so a single request prints every header of interest at once
  (or nothing, for headers that are absent — absence is itself the finding).

## Automated tooling

```bash
docker run --rm -it ssllabs/ssllabs-scan --host=target.example.com
```

This is sometimes used for the HSTS/TLS layer, but for full security-header grading the de facto
industry tool is the **Mozilla Observatory** CLI (`mdn-http-observatory`) or its web UI, and
**securityheaders.com**, which both grade a target's full header configuration against current
best practice in a single pass. These are referenced here as recon-acceleration tools — the
underlying `curl` checks above are what you should understand and be able to perform manually
under exam/engagement conditions where outbound tooling may be restricted.

## Real-world notes

- Header misconfiguration is rarely a standalone payout in bug bounty programs unless paired with
  a PoC showing concrete impact (e.g., demonstrating that a missing `X-Frame-Options` actually
  enables a working clickjacking attack against a sensitive action like a funds transfer button).
- CSP misconfiguration review is now a standard line item in PCI-DSS and SOC 2 vendor security
  questionnaires — many enterprise clients will fail a vendor security review purely on missing
  CSP/HSTS, independent of any proof-of-concept exploit.
- A surprisingly common real-world pattern: a CDN or WAF strips/overrides security headers set by
  the origin server, so the same site can show different header behavior depending on which layer
  (origin vs. edge) responds — always test both where possible (e.g., by hitting the origin IP
  directly with the `Host` header set, if in scope).

## What's next

Continue to `05_CORS_Misconfiguration.md`.
