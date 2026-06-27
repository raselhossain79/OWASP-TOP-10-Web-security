# Client-Side Integrity: Subresource Integrity and CDN Trust

## 1. The trust relationship being exploited

When a web page loads a script (or stylesheet) from a third-party domain — a CDN, an
analytics provider, a widget vendor — the browser, by default, executes whatever
content that domain returns **at the moment of the request**, with no verification
that the content matches what the page author originally intended to load.

That means the *security* of every page that does this is only as strong as:

1. The third-party domain never being compromised, **and**
2. The third-party domain never changing ownership/control in a way the site owner
   doesn't notice, **and**
3. No on-path attacker (compromised Wi-Fi, malicious DNS, BGP hijack) being able to
   intercept the request and substitute a different response.

This is precisely the structure that failed in the **polyfill.io incident (2024)**:
the domain itself changed ownership, the new owner modified the served JavaScript to
inject malicious redirects and payloads, and every site that had simply written
`<script src="https://cdn.polyfill.io/v3/polyfill.min.js">` without any additional
verification served that malicious code to its own visitors automatically, with zero
changes required on the site owner's end. Estimates at the time put the affected
site count above 100,000.

## 2. Subresource Integrity (SRI) — the actual defense

### 2.1 How it works mechanically

```html
<script
  src="https://cdn.example.com/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous">
</script>
```

Breakdown:
- `src="..."` — the URL the browser fetches the script from, exactly as normal.
- `integrity="sha384-..."` — a base64-encoded cryptographic hash of the **exact
  expected content** of that file, computed using SHA-384 (SHA-256 and SHA-512 are
  also valid prefixes). The browser computes this same hash over the bytes it
  actually receives from the network, **before executing the script**, and compares
  the two values.
- If the computed hash does **not** match the `integrity` attribute, the browser
  **refuses to execute the script at all** — it is blocked exactly like a CORS
  failure, and the failure is visible in the browser console as a integrity
  mismatch error. This is the exact mechanism that would have neutralized the
  polyfill.io compromise on any site that had it configured: the malicious,
  ownership-changed content would not match the hash computed against the original,
  legitimate file, and the browser would simply have refused to run it.
- `crossorigin="anonymous"` — **required** alongside `integrity` for any
  cross-origin resource. Without it, the browser cannot read the response bytes
  needed to compute the integrity hash at all (a CORS restriction on response body
  access), and SRI silently fails to provide any protection — this is a very common,
  easy-to-miss real-world misconfiguration: teams add the `integrity` attribute
  without `crossorigin`, get no actual protection, and don't find out until an
  incident or an audit.

### 2.2 Generating the correct integrity hash

```bash
curl -s https://cdn.example.com/library.js | openssl dgst -sha384 -binary | openssl base64 -A
```

Breakdown:
- `curl -s https://cdn.example.com/library.js` — fetches the exact file content,
  silently (`-s` suppresses curl's progress meter so it doesn't pollute the piped
  output).
- `openssl dgst -sha384 -binary` — computes the SHA-384 message digest over the
  piped input. `-binary` outputs raw binary digest bytes rather than a hex string,
  because the next step needs raw bytes, not hex, to produce a correct SRI value.
- `openssl base64 -A` — base64-encodes the raw digest bytes. `-A` forces single-line
  output (no line wrapping), which matters because the `integrity` attribute expects
  one continuous base64 string.
- The final output, prefixed manually with `sha384-`, is exactly what belongs in the
  `integrity` attribute. This is the standard manual method; in practice most teams
  generate this automatically as part of their build pipeline (e.g. via
  webpack-subresource-integrity or equivalent bundler plugins) so the hash is
  recomputed and embedded automatically every time the vendored file changes —
  which also has the useful side effect of **breaking the build loudly** if a
  vendored dependency's content changes unexpectedly between builds, surfacing
  exactly the kind of unannounced upstream change that caused the polyfill.io
  incident, before it ever reaches production.

### 2.3 Detecting missing SRI across a site — testing methodology

```bash
curl -s https://target.example/ | grep -oP '<script[^>]+src="https?://[^"]+\.js"[^>]*>' 
```

Breakdown:
- Fetches the page's raw HTML and extracts every `<script>` tag that loads from an
  **absolute, external URL** (i.e., third-party-hosted, not the site's own
  first-party static assets) using a Perl-compatible regex via `-oP` to print only
  the matched tags.
- The manual review step: for each matched tag, check whether it includes an
  `integrity` attribute. Any third-party-hosted script **without** one is a finding
  — the severity of which scales directly with how privileged the page context is
  (a marketing landing page loading an unverified analytics script is lower risk than
  an authenticated banking dashboard loading an unverified third-party widget
  script, since the latter executes in a context with access to session
  cookies/tokens and sensitive DOM content).

```bash
curl -sI https://cdn.example.com/library.js | grep -i "content-security-policy\|cache-control"
```

Breakdown:
- Checking response headers from the third-party host itself is a secondary signal:
  aggressive caching (`Cache-Control`) on the vendor's side reduces (but does not
  eliminate) the window in which a compromised CDN could serve different content to
  different visitors, while the *absence* of any cache headers at all means every
  single page load is a fresh opportunity for content substitution if the upstream
  is compromised at that moment.

### 2.4 Content-Security-Policy as a complementary (not equivalent) control

```http
Content-Security-Policy: require-sri-for script style; script-src 'self' https://cdn.example.com
```

Breakdown:
- `require-sri-for script style` — an experimental CSP directive (limited browser
  support — verify current support before relying on it as a sole control) that
  instructs the browser to **refuse to load any script or stylesheet that lacks an
  `integrity` attribute at all**, regardless of what site author forgot to add one.
  This is valuable specifically as an organizational guardrail against the human
  error case (a developer adds a new third-party script tag and simply forgets SRI)
  rather than relying on code review catching every instance.
- `script-src 'self' https://cdn.example.com` — a standard CSP allow-list, restricting
  which origins scripts may be loaded from at all. This is a **distinct** control
  from SRI: CSP's `script-src` answers "is this domain allowed to serve scripts to
  this page at all," while SRI answers "does the content this allowed domain
  actually returned match what we expect." A compromised-but-still-allow-listed CDN
  (exactly the polyfill.io scenario — the domain itself didn't change, so CSP
  `script-src` would not have blocked anything) is only caught by SRI, not by CSP
  alone. Real-world hardening uses both together, not one in place of the other.

## 3. Third-party JavaScript supply chain — beyond CDN libraries

The polyfill.io case is the cleanest example, but the same trust failure applies to
any third-party-controlled script embedded on a page: chat widgets, A/B testing
tools, customer support plugins, advertising/analytics tags. This is the mechanism
behind real-world **Magecart-style attacks**, where attackers compromise a
third-party script provider (rather than the target site directly) specifically to
inject payment-card-skimming JavaScript into every site that embeds that vendor's
script — a notable real-world instance being the 2018 British Airways breach, where
a modified third-party script (attributed to a compromised Magecart-style supply
chain component) exfiltrated payment card data entered on the airline's own payment
page, without the airline's own backend or database ever being directly breached.

### 3.1 Why SRI alone doesn't fully solve this category

A legitimate, frequently-updated third-party script (a live chat widget that
deploys new code multiple times a day, for instance) is **operationally
incompatible** with a static `integrity` hash — the hash would need updating on every
vendor deployment, which most sites cannot realistically track in real time. This is
the honest limitation worth stating in any report or note on this topic: SRI is the
correct control for **versioned, infrequently-changing** third-party resources (CDN
libraries, pinned widget versions), but for **continuously-deployed third-party
scripts**, the realistic mitigations shift toward:

- Sandboxing third-party scripts in an `<iframe>` with a restrictive `sandbox`
  attribute and no access to the parent page's DOM/cookies where the vendor's
  functionality allows it.
- Strict CSP `script-src` allow-listing combined with vendor contractual/security
  assessment requirements (SOC 2, vendor security questionnaires) — i.e., shifting
  from a purely technical control to a vendor-risk-management control, which is the
  honest, real-world answer industry teams give when asked "how do you protect
  against your live-chat vendor getting compromised."

## 4. Real-world note: SRI's biggest practical obstacle isn't technical

In nearly every site audit involving SRI, the gap is not a misunderstanding of the
mechanism — it's that nobody owns the process of **regenerating the hash every time
the vendored file is intentionally updated**, so teams either skip SRI entirely to
avoid maintenance overhead, or (worse) leave a stale `integrity` hash in place that
silently breaks the legitimate functionality the moment the vendor pushes a routine
update, leading developers to remove the attribute under deadline pressure rather
than debug it. The sustainable fix industry teams converge on is automating hash
generation as part of the build pipeline (section 2.2) rather than treating it as a
manual, one-time task — worth stating explicitly in any remediation recommendation,
since "just add integrity attributes" without addressing the maintenance workflow is
a fix that tends not to survive contact with a real engineering team's release cadence.
