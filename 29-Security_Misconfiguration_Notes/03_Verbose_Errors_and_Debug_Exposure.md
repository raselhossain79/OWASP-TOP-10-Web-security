# 03 — Verbose Error Messages, Stack Traces, and Debug Exposure

## What it is

This sub-category covers any response that reveals more about the application's internals than
a normal user needs to see:

- Full stack traces returned to the client on unhandled exceptions
- Framework/server "debug mode" pages (Django `DEBUG=True`, Flask debug mode with the Werkzeug
  interactive debugger, Rails `config.consider_all_requests_local`, PHP `display_errors=On`)
- Database error messages echoed verbatim (revealing DBMS type, table/column names, query
  structure)
- Verbose `Server:`/`X-Powered-By:` banners revealing exact software versions

This is one of the categories PortSwigger Web Security Academy models directly under its
**Information disclosure** topic, so this file includes the relevant lab mapping inline as well
as in the consolidated table in file `09`.

## How it arises

- Frameworks default to verbose debug output during development for good reason (it speeds up
  debugging), and the flag controlling this is simply never flipped to its production value
  before deployment.
- Custom error handlers are written for "happy path" errors (404, 403) but not for unexpected
  exceptions, which fall through to the framework's default — often verbose — handler.
- Load balancers/reverse proxies are configured to pass backend error pages straight through
  instead of replacing them with a generic error page.

## How to test, piece by piece

### Step 1 — Force an unexpected error with a malformed parameter

```bash
curl -s "https://target.example.com/product?productId=art" | head -n 40
```

- `curl -s` — silent mode (suppress progress meter).
- `"https://target.example.com/product?productId=art"` — the request URL. The `productId`
  parameter normally expects a number; supplying a non-numeric string (`art`) is a classic way
  to trigger a type-conversion exception in a weakly-typed handler.
- `| head -n 40` — pipe the output to `head`, printing only the first 40 lines, since stack
  traces are often hundreds of lines long and the framework/version info is usually near the top.

If the backend does not validate/sanitize the parameter type before using it, this can throw an
unhandled exception, and if debug mode is on, the resulting page will frequently disclose the
exact framework, version, and even a fragment of source code or file path.

### Step 2 — Probe for framework-specific debug interfaces

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://target.example.com/__debug__/
```

- Same flag breakdown as in file `02`, Step 2. This specific path is the default mount point for
  the Django Debug Toolbar; equivalent checks exist for other frameworks (e.g.
  `/console` for the Werkzeug/Flask interactive debugger when triggered, or `/phpinfo.php` /
  `/cgi-bin/phpinfo.php` for exposed PHP info pages).

### Step 3 — Send a TRACE request to check for insecure HTTP method configuration

```bash
curl -s -X TRACE -i https://target.example.com/admin
```

- `-X TRACE` — override the request method to `TRACE`, an HTTP diagnostic method that, if
  enabled on the server, causes it to echo the exact request it received back in the response
  body.
- `-i` — include response headers in the output.

If `TRACE` is enabled, compare the request as you sent it against what's echoed back. Any header
that appears in the echoed request but that you did **not** send yourself (e.g., an
`X-Custom-IP-Authorization` header automatically injected by a front-end proxy) is a leaked
internal implementation detail — exactly the technique used in PortSwigger's "Authentication
bypass via information disclosure" lab (mapped below).

### Step 4 — Compare error responses for subtle behavioral differences

```bash
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" "https://target.example.com/login" \
  --data "username=admin&password=wrong1"
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" "https://target.example.com/login" \
  --data "username=nonexistentuser123&password=wrong1"
```

- `-w "%{http_code} %{size_download}\n"` — print the HTTP status code and the response body size
  in bytes, instead of the body itself.
- `--data "username=...&password=..."` — send the given string as the URL-encoded POST body.

Running the same request twice with a *valid username + wrong password* versus an
*invalid username + wrong password* and comparing status code and response size is the standard
technique for detecting username enumeration via differential error responses — a behavioral
information-disclosure pattern, not a verbose-text one.

## PortSwigger Web Security Academy lab mapping for this file

These labs sit under PortSwigger's **Information disclosure** topic, in the order they appear
in the Academy:

1. **Information disclosure in error messages** — directly matches Step 1 above: an invalid
   `productId` value triggers a stack trace that reveals the underlying framework version.
2. **Information disclosure on debug page** — matches Step 2: locating and exploiting a debug
   interface (in this lab's case, a `phpinfo()` page reachable from an HTML comment) to extract a
   secret key.
3. **Authentication bypass via information disclosure** — matches Step 3: using `TRACE` to
   discover an internal header name, then supplying that header yourself to bypass an IP-based
   access restriction on an admin panel.

(Two further labs in this PortSwigger topic — backup file source disclosure and version control
history disclosure — are mapped in file `06_Directory_Listing_Exposure.md` and file `09`, since
they're more directly about exposed file/directory structure than verbose runtime errors.)

## Real-world notes

- Verbose stack traces are one of the highest-value low-effort findings in a pentest: a single
  exposed framework version string (e.g., `Apache Struts 2.3.x`) can immediately be cross-checked
  against the NVD/CVE database for a known remote code execution vulnerability, turning an
  "informational" finding into a full compromise path within minutes.
- Many real breaches (including parts of the Equifax incident) trace back to verbose error
  disclosure helping attackers fingerprint exact vulnerable software versions during
  reconnaissance, before the actual exploitation step.
- Production incident response teams generally treat any reappearance of a stack trace in a
  customer-facing response as a P2/P3 bug regardless of "severity," precisely because it signals
  that the application's exception-handling middleware has a gap somewhere.

## What's next

Continue to `04_Security_Headers_Misconfiguration.md`.
