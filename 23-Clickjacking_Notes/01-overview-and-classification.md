# 01 — Overview & Classification

## What Clickjacking Actually Is

Clickjacking (also called UI redressing) is a client-side attack where a victim is
tricked into clicking on something other than what they perceive themselves to be
clicking on. The victim believes they are interacting with a decoy page they
intentionally visited — a "claim your prize" button, a CAPTCHA, a video play button —
when in reality their click (or, in newer variants, a sequence of clicks) lands on a
hidden, legitimate page that performs a sensitive action.

The defining characteristic is **visual deception of an authenticated action**, not
network-level request forgery. This is what separates it from CSRF.

## Clickjacking vs. CSRF — Why They're Different Bug Classes

This distinction matters in real engagements because it determines what defenses are
relevant and what a report should say.

- **CSRF** forges an entire request without requiring the victim to do anything beyond
  load a malicious page (e.g. an auto-submitting form or an image tag triggering a GET).
  CSRF tokens defeat this because the attacker cannot read or predict the token value.
- **Clickjacking** does not forge a request at all. The victim's own browser sends a
  completely legitimate, same-origin request, with the real CSRF token attached,
  because the victim is genuinely interacting with the real page — they just don't know
  it. The request is loaded in a hidden iframe and the victim's authenticated session
  cookie is used exactly as the application expects.

This is why a CSRF token does **nothing** to stop clickjacking. A target page can be
fully CSRF-protected and still be completely clickjackable. This is a very common
finding-justification point in real pentest reports: testers frequently need to explain
to developers why "we already have CSRF tokens" is not a valid objection to a
clickjacking finding.

## Real-World Industry Framing

Clickjacking has a long history of real impact, not just lab exercises:

- Used historically to inflate Facebook "Likes" and social shares (the original
  "Likejacking" attacks, ~2010).
- Used against banking and webmail interfaces to trick users into authorizing
  transactions or changing account recovery settings.
- A standard finding category in nearly every external web application penetration
  test — testers check for missing/misconfigured framing headers as a baseline item,
  even on pages with no obviously "sensitive" action, because chaining with DOM XSS or
  OAuth consent screens can escalate severity significantly.
- OAuth and SSO consent screens are a particularly high-value clickjacking target:
  tricking a user into clicking "Authorize" on a consent screen they didn't realize was
  loaded is a realistic account-takeover vector on real platforms.
- Browser extensions (crypto wallets, password managers) have become a 2024–2025 target
  for clickjacking-adjacent techniques, expanding the attack surface beyond traditional
  web pages.

When writing a finding for a client, severity should be argued based on the **specific
sensitive action exposed**, not on "clickjacking exists" in the abstract. A clickjackable
logout button is informational; a clickjackable "disable 2FA" or "authorize third-party
app" button is high/critical.

## Classification of Clickjacking Variants

### 1. Classic / Basic Clickjacking (Single-Click Overlay)

An invisible or near-invisible iframe loading the target site is positioned exactly over
a decoy element on the attacker's page. The victim clicks the decoy and unknowingly
clicks the real, sensitive control underneath (e.g. "Delete account", "Update email").

This is the foundational technique. Everything else in this series is a variation on it.

### 2. Clickjacking with Prefilled Form Input

A variant of the classic technique where the target page accepts form values via GET
parameters (e.g. `?email=attacker@evil.com`). The attacker pre-populates the hidden
iframe's form with their own values via the URL, then tricks the victim into clicking
the submit button. This turns a simple "click this button" attack into a full
account-takeover primitive (e.g. changing the victim's registered email to one the
attacker controls, then using password reset).

### 3. Frame-Busting Bypass

Some applications attempt client-side, JavaScript-based protection ("frame busters")
that try to detect framing and break out of it. These can usually be neutralized using
the HTML5 `sandbox` attribute on the iframe, which strips the framed page's ability to
navigate the top-level window — covered in depth in File 03.

### 4. Clickjacking Chained with DOM-Based XSS

Clickjacking is also used as a delivery mechanism for other vulnerabilities, not just as
a standalone attack. If a page has a DOM XSS sink that's only reachable via a user
click (e.g. a button that triggers `eval()` on a URL parameter), an attacker can frame
that exact URL and trick the user into triggering the click — turning a "requires user
interaction" XSS into something exploitable via decoy page.

### 5. Multistep Clickjacking

Some attacks require more than one click to complete a sensitive flow (e.g. add item to
basket, then confirm checkout). Multistep clickjacking layers multiple decoy elements
over multiple points in a hidden iframe to walk the victim through an entire multi-click
flow without their awareness. This requires much more precise positioning and is more
fragile in practice, but is realistic against multi-step confirmation flows designed
specifically to resist single-click clickjacking.

### 6. Double-Clickjacking (2024–present)

Disclosed by security researcher Paulos Yibelo in December 2024, this is a structurally
different technique — it does **not** rely on framing the target page in an iframe at
all, which means it is **not stopped by X-Frame-Options or CSP `frame-ancestors`**, and
is also not stopped by SameSite cookie protections, because the victim is interacting
directly with the real, top-level target page rather than a framed copy of it.

The mechanism exploits the timing and event order of a double-click:

1. The victim is lured to an attacker page with an enticing button (e.g. "claim
   reward").
2. Clicking it opens a new browser window/tab — this new window is positioned to
   overlay the original, or simply takes focus, and displays something like a fake
   CAPTCHA prompting a second click.
3. The new window listens for the `mousedown` event of the second click. The instant
   `mousedown` fires, JavaScript immediately closes the overlay window (or uses
   `window.opener.location` to navigate the parent to the real target's sensitive
   action page, e.g. an OAuth consent screen).
4. The subsequent `click`/`mouseup` portion of that same double-click now lands on the
   real, now-visible target page — directly, with no iframe involved — landing on a
   sensitive button (e.g. "Authorize") that the user never consciously intended to
   click.

Because the final click is a genuine top-level interaction with the genuine origin, none
of the iframe-based defenses apply. This is covered in mechanism-level detail with a PoC
breakdown in File 02 and discussed as a defense gap in File 03.

> **Real-world note:** As of this writing, double-clickjacking does not have a dedicated
> PortSwigger Academy lab. It is included here because it represents the current state
> of the art in this vulnerability class and is directly relevant to real bug bounty and
> pentest work — omitting it would leave this series outdated relative to the live
> threat landscape.

## Summary Table

| Variant | Relies on iframe? | Defeated by XFO / frame-ancestors? | Defeated by CSRF token? |
|---|---|---|---|
| Classic overlay | Yes | Yes | No |
| Prefilled form input | Yes | Yes | No |
| Frame-buster bypass | Yes (via sandbox) | Partially — depends on header presence | No |
| DOM XSS chained | Yes | Yes | No |
| Multistep | Yes | Yes | No |
| Double-clickjacking | No | **No** | No |

The next file (`02-poc-building-techniques.md`) walks through building a working PoC for
each of these, breaking every CSS/HTML property down piece by piece.
