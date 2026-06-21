# 03 — Stored (Persistent) XSS

## Definition Recap

Stored XSS = the payload is submitted once and **persisted server-side** (database, file, cache, log, message queue, search index — anywhere data is saved and later re-rendered), then served back to **any user** who subsequently views the page/feature containing that data. No per-victim link crafting is required — the application itself becomes the ongoing delivery mechanism.

## Why It's Rated More Severe Than Reflected (Usually)

- **No social engineering needed per victim.** Once stored, every viewer is hit automatically.
- **Can reach privileged users as part of their normal job.** A support agent reviewing tickets, a moderator reviewing reported content, or an admin viewing a user list are all routine workflows that become attack surface — this is the foundation for Blind XSS (file 05), since the tester usually can't see what privileged internal users see.
- **Wider blast radius.** One injection can compromise every subsequent viewer until the data is cleaned/removed, not just one tricked victim.

## Step-by-Step Methodology

1. Identify every **input** that gets **persisted and later displayed to anyone** (including yourself on a different page load, or another test account) — comments, display names, bios, support tickets, file names, uploaded file metadata (EXIF/XMP), product reviews, chat messages, forum posts, "company name" fields in B2B apps, log viewers that render request data.
2. Submit a unique marker, then **reload the page from a fresh request** (not just the immediate response) to confirm persistence — this is the key test that separates Stored from Reflected; if the marker only appears in the immediate response and disappears on reload, it's Reflected, not Stored.
3. Determine **who views the data** — only you? other regular users? admins/support only (→ likely Blind XSS territory, file 05)? Use a second test account when the app allows it to confirm cross-user visibility.
4. Probe context and encoding exactly as in Reflected XSS methodology (file 02) — context determination doesn't change based on delivery mechanism, only the testing workflow around persistence does.
5. Craft and store the context-correct payload; verify execution by viewing the page as the **second** account/session, proving genuine cross-user impact (not just "it ran for me, the one who submitted it" — which is closer to self-XSS until cross-user impact is shown).

## Worked Example — HTML Body Context (Comment Field, No Encoding)

A blog lets users post comments which are rendered as:
```html
<div class="comment">USER_INPUT</div>
```
Submit as the comment body:
```
<script>alert(document.domain)</script>
```
Mechanism is identical to the Reflected HTML-body case (file 02) — the only difference is **when** it executes: not in the immediate response to the attacker, but every time *any* user (including the attacker testing as a second account) loads the blog post page afterward. This timing difference is exactly why you must reload as a separate session to validate real Stored XSS rather than relying on the submission response.

## Worked Example — HTML Attribute Context (Profile "Website" Field)

A common, very real pattern: a profile lets you set a personal website URL, rendered as:
```html
<a href="USER_INPUT">Visit my website</a>
```
If the field accepts arbitrary strings (no `http(s)://` validation) and the output isn't attribute-encoded:
```
javascript:alert(document.domain)
```
Breakdown: identical mechanism to the URL-context scheme injection in file 02 — `javascript:` is evaluated as a JS expression when the link is clicked. The **stored** aspect is what changes the exploitation story: every visitor to that profile page who clicks "Visit my website" executes the payload in their own session, not yours. This exact lab pattern (profile "website" field → `href` injection) is one of PortSwigger's earliest Stored XSS labs because it's extremely common in real applications — any user-editable URL/link field in a profile, comment signature, or forum post is worth testing this way.

## Worked Example — Filtered/Encoded Variant (Forces Event-Handler Attribute Injection)

If `<` and `>` are stripped/encoded but a quote character and `=` survive inside an existing attribute (e.g. an `onclick` value built server-side from user input, or a `style` attribute), look for any attribute you can break into and inject an event handler as a **new attribute on the existing tag**, exactly as covered in file 01/02's attribute-breakout mechanics — e.g.:
```
" onmouseover="alert(document.domain)
```
This works whenever quotes survive but angle brackets don't, because you're modifying the *existing* tag rather than creating a new one.

## PortSwigger Lab Mapping (Stored XSS — Difficulty Progression)

| Order | Lab | What it teaches |
|---|---|---|
| 1 | Stored XSS into HTML context with nothing encoded | Baseline comment-field injection, same mechanics as Reflected HTML-body but via persistence |
| 2 | Stored XSS into anchor `href` attribute with double quotes HTML-encoded | Profile "website" field → forces `javascript:` scheme injection since quotes are encoded (can't attribute-breakout, must stay inside the existing `href` value) |
| 3 | Stored XSS into HTML context with most tags and attributes blocked | Allowlist bypass — same lesson as Reflected lab 2, but via a stored comment, reinforcing that filter bypass technique is independent of delivery mechanism |
| 4 | Stored XSS into HTML context with all tags blocked except custom ones | Custom-tag + event-handler execution, stored variant |
| 5 | Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped | Heavily filtered attribute context — forces creative encoding/escaping bypass within an existing JS-attribute context |
| 6 | Stored XSS into anchor `href` attribute with double quotes HTML-encoded and single quotes and backslash escaped | Combines URL-context scheme injection with escaped-quote handling — no `"`, no `'`, no `\` available, must construct a payload using only what survives |

> As with file 02's table: verify exact current lab titles/order at `portswigger.net/web-security/cross-site-scripting/stored`, since PortSwigger periodically refreshes lab sets.

## Real-World Engagement Notes

- **File upload metadata is a frequently-missed Stored XSS vector.** EXIF `Comment`/`Artist` fields, SVG file content (SVG is XML and can contain `<script>` directly), and even filenames displayed in an admin's "uploaded files" list are realistic findings — test file uploads specifically for this, not just form fields.
- **Multi-tenant B2B SaaS apps** (e.g., a "Company Name" or "Department" field set by one customer org but displayed to *that org's own* support agent in your shared admin tooling) are a common real-world Stored XSS pattern in enterprise software — pay attention to any field visible across tenant boundaries to internal staff.
- **Markdown/rich-text renderers are a major Stored XSS source.** If comments/posts support Markdown or a WYSIWYG editor, test the underlying HTML sanitizer directly — many custom or outdated sanitizer configs allow `<img onerror=...>`, raw `<svg>`, or `data:` URIs through. This overlaps heavily with mXSS testing (file 04) since sanitizers are exactly where mutation-based bypass shows up.
- **Second-order Stored XSS** — where the stored payload triggers in a feature *different* from where it was submitted (e.g., submitted via a support ticket subject line, but triggers when an admin's dashboard later renders "recent ticket subjects" in a different module) — is easy to miss because the trigger point is non-obvious. Always check *every* place a stored field is later displayed, not just the obvious one.

## Common Mistakes

- Confirming the payload appears in the **immediate** response after submission and stopping there — that alone doesn't prove persistence; always reload from a clean/new request.
- Testing only with your own account and declaring it exploitable without checking whether *other users* (or any user at all) actually view that data — true Stored XSS requires demonstrable cross-user reach.
- Missing that some "stored" fields are actually re-encoded correctly on **display** even though they're stored raw in the database — always test the rendered output, not the database content.
- Forgetting rate-limiting/moderation queues exist on some platforms (a comment might need approval before being publicly visible) — confirm the trigger point you're testing against is actually reachable by other users in the real application flow.

## Report-Writing Notes

- Explicitly state **where the payload is submitted** and **where/to whom it executes** if they differ (second-order XSS) — this distinction materially affects remediation guidance (the dev team needs to fix output encoding at the *render* point, which might be a different code path than the *input* point).
- Note any **moderation/approval gating** that exists between submission and public visibility, and state whether you bypassed it or tested through the legitimate flow — this affects real-world exploitability and severity.
- If the visible audience is "any authenticated user" vs. "admins/support staff only," call that out clearly, since it changes both severity and remediation urgency.

---
**Next:** `04_DOM_Based_XSS.md`
