# 03 — Bypass Scenarios for Partial Frame Protections

A clickjacking finding is rarely "header present vs. header absent." In real
engagements you'll most often encounter *partial* or *misconfigured* protections —
this file covers how to recognize and bypass them.

## 3.1 — Client-Side Frame Busting Scripts

Before server-side headers were standard, applications tried to defend themselves with
JavaScript "frame busting" / "frame breaking" scripts. These typically attempt to:

- Check whether the current window is the top-level window (`window.top !==
  window.self`), and if not, force navigation to break out of the frame.
- Make all frames forcibly visible.
- Intercept clicks on content believed to be inside an invisible frame.
- Alert the user to a potential clickjacking attempt.

### Why these are fundamentally unreliable

Frame busters are JavaScript-based, which means their effectiveness depends entirely on
the script actually executing inside the framed context — something the attacker
controls indirectly via the iframe tag itself.

### The Bypass: `sandbox` attribute

```html
<iframe id="victim_website"
        src="https://victim-website.com"
        sandbox="allow-forms">
</iframe>
```

**Breakdown:**

- The HTML5 `sandbox` attribute, when present (even with no value), imposes a set of
  restrictions on the framed content by default — including disabling script execution
  entirely unless explicitly re-permitted.
- `allow-forms` re-enables form submission inside the sandboxed iframe (needed if the
  sensitive action you're targeting is a form submit) **without** re-enabling
  `allow-scripts`.
- Without `allow-scripts`, the frame buster script inside the target page simply never
  runs — it can't execute because script execution itself is blocked by the sandbox.
  The frame buster doesn't fail or get bypassed in a clever way; it's prevented from
  ever starting.
- If the target action does require JavaScript to function client-side, you can instead
  use `sandbox="allow-scripts"` — but **deliberately omit** `allow-top-navigation`. This
  permits scripts to run (so the page functions normally) while specifically blocking
  the one capability the frame buster needs to defend itself: navigating the top-level
  window out of the frame. The frame buster's detection logic may still run, but its
  *escape* action is structurally blocked by the browser, regardless of what the script
  tries to do.
- This is the PortSwigger Academy lab pattern for the "frame buster script" lab — it
  demonstrates that client-side JS defenses are not a substitute for server-side
  headers, because the attacker, not the defender, controls which sandbox flags are
  granted to the framed content.

### Real-world note

If you find a frame buster script and no `X-Frame-Options` / CSP `frame-ancestors`
header, report it as **effectively no clickjacking protection at all** — don't let a
client claim partial credit for a frame buster in a remediation review. This is one of
the most common "the dev team thinks they're protected but aren't" situations in
clickjacking findings.

## 3.2 — Missing or Misconfigured `X-Frame-Options`

`X-Frame-Options` (XFO) directives:

```
X-Frame-Options: deny
X-Frame-Options: sameorigin
X-Frame-Options: allow-from https://trusted-site.com
```

### Common real-world misconfigurations

- **Header entirely absent** — the most common finding; trivially clickjackable unless
  CSP `frame-ancestors` is independently present and correctly configured.
- **Set inconsistently across endpoints** — e.g. present on the login page but missing
  on the account settings or OAuth consent page. Always test the *specific sensitive
  page*, not just the homepage — many automated scanners only check the root URL and
  miss this.
- **`allow-from` reliance** — this directive is not supported in current versions of
  Chrome or Safari at all (only ever had partial Firefox/IE support). A site relying
  solely on `allow-from` to restrict framing to a "trusted" partner site is, in
  practice, unprotected in most modern browsers — this is a frequent and
  underappreciated misconfiguration worth flagging explicitly in a report, since the
  developer may believe `allow-from` works because it's a documented directive.
- **Set via `<meta>` tag instead of HTTP header** — `X-Frame-Options` has no effect when
  delivered as an HTML `<meta http-equiv>` tag; it is only honored as a genuine HTTP
  response header. This is a real and recurring mistake worth specifically checking for
  in source review.

## 3.3 — Missing or Misconfigured CSP `frame-ancestors`

```
Content-Security-Policy: frame-ancestors 'self';
Content-Security-Policy: frame-ancestors trusted-site.com;
Content-Security-Policy: frame-ancestors 'none';
```

This is the modern, recommended replacement for XFO. `frame-ancestors 'none'` is
equivalent to XFO `deny`; `frame-ancestors 'self'` is roughly equivalent to XFO
`sameorigin`. CSP takes precedence over XFO when both are present and a browser
supports both, but only if `frame-ancestors` is actually specified — a CSP header that
governs other directives (script-src, etc.) but omits `frame-ancestors` entirely
provides **zero** clickjacking protection, even though the application clearly has *a*
CSP. This is a very common false sense of security in real audits: testers should
always check specifically for the `frame-ancestors` directive within the CSP, not just
the presence of a CSP header.

### Common real-world misconfigurations

- **CSP present, `frame-ancestors` directive absent** — covered above; extremely
  common, since teams often configure CSP for XSS mitigation (`script-src`,
  `object-src`, etc.) without realizing `frame-ancestors` is a separate, opt-in
  directive that must be added explicitly.
- **Overly broad allowlist** — e.g. `frame-ancestors *.example.com` where a subdomain
  takeover or an unrelated, attacker-controllable subdomain exists under that wildcard.
  If you can find or stand up content under any matching subdomain, the protection is
  bypassed entirely.
- **Conflicting XFO and CSP values** — e.g. `X-Frame-Options: sameorigin` alongside a
  CSP with no `frame-ancestors`, served to a browser that prioritizes CSP. Always test
  empirically in the actual target browser rather than assuming header precedence
  theoretically protects the page.

## 3.4 — SameSite Cookies as a Partial (and Often Overstated) Protection

Modern browsers default cookies to `SameSite=Lax`, which prevents cookies from being
sent on most cross-site framed requests — meaning even if a page *can* be framed, the
framed content may load unauthenticated, neutralizing many classic clickjacking
attempts in practice. This has meaningfully reduced classic clickjacking's real-world
impact since browser vendors shipped `SameSite=Lax` as default.

**However, this should not be treated as a substitute for explicit framing headers in a
report**, for several reasons:

- It depends entirely on browser defaults and cookie configuration the application
  doesn't fully control (e.g. cookies explicitly set to `SameSite=None` for legitimate
  cross-site integration purposes remain fully exploitable).
- It does not protect against the prefilled-form-input variant in cases where the
  sensitive action doesn't strictly require authentication (e.g. public-facing forms).
- Most importantly: **it does nothing against double-clickjacking**, covered next.

## 3.5 — Why Double-Clickjacking Defeats All of the Above

This is the critical real-world gap to understand and to communicate clearly in any
report or write-up: every defense covered in this file — frame busters, XFO,
`frame-ancestors`, and SameSite cookies — operates on the assumption that the attack
**requires framing the target page**.

Double-clickjacking (File 02, section 2.4) never frames the target at all. The victim's
final click is a direct, top-level, first-party interaction with the real page in the
real, fully-authenticated browser window — no iframe, no cross-site cookie restriction
to defeat, nothing for `frame-ancestors` to refuse to permit. A page can correctly
implement every defense in this file and still be exploitable via double-clickjacking.

### What actually mitigates double-clickjacking

As of this writing there is no equivalent standardized HTTP header defense. The
practical client-side mitigation proposed by the technique's discoverer is to disable
sensitive action buttons by default and only re-enable them after a deliberate user
gesture distinct from a rapid double-click pattern (e.g. requiring a short delay, or
requiring the button to first receive a genuine `focus` event from keyboard
navigation rather than enabling on page load). This is an application-level UX/JS
mitigation, not a server header — which is itself worth stating plainly in a
report, since it changes who on the client side needs to action the finding (frontend
engineering, not just infrastructure/headers config).

### Reporting implication

When you find an application with fully correct XFO/CSP configuration, it is still
reasonable and accurate to note that classic clickjacking is mitigated, while flagging
that no current header-based standard protects against double-clickjacking on
sensitive, single-action confirmation flows (OAuth consent, payment authorization,
2FA disable) — this is a forward-looking, defense-in-depth recommendation rather than a
confirmed vulnerability unless you've built and demonstrated a working PoC against the
specific target.

Next: `04-cheatsheet-and-lab-mapping.md` consolidates everything into quick-reference
payloads and the full PortSwigger Academy lab progression.
