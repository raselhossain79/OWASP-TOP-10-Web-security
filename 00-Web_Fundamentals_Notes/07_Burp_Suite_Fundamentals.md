# Burp Suite Fundamentals

> Every single note series in this repo assumes you can use Burp's core tools. This file 
> covers the ones you'll touch constantly — not a full feature tour, just what you need 
> before starting the vulnerability-specific notes.

---

## 1. Proxy — The Foundation Everything Else Sits On

Burp Proxy sits **between your browser and the target**, intercepting every request/
response so you can see and modify them.

**Setup (what you need to actually do, broken down):**
1. Burp listens on `127.0.0.1:8080` by default — this is a local address only your own 
   machine can reach
2. Configure your browser (or use FoxyProxy extension) to send its traffic through that 
   address instead of directly to the internet
3. Install Burp's CA certificate in your browser — without this, HTTPS sites will show 
   certificate errors, because Burp is technically performing a controlled 
   man-in-the-middle to decrypt and show you the traffic

**Proxy → HTTP History tab** — every request/response you generate while browsing shows 
up here in order. This is your primary "what actually happened" log, more reliable than 
trying to remember what you clicked.

**Intercept toggle** — when ON, Burp pauses every request before it's sent, letting you 
edit it live before forwarding. Useful for one-off tests; for repeated testing, 
Repeater (below) is faster.

## 2. Repeater — Send the Same Request Repeatedly, Modified Each Time

Right-click any request in Proxy history → "Send to Repeater." This:
- Keeps the exact request structure (headers, cookies, body)
- Lets you edit any part of it (a parameter, a header value, the method)
- Resend with one click, see the response immediately

**This is your primary manual-testing tool** for almost everything in this repo — 
confirming SQLi, testing IDOR by changing an ID parameter, modifying CORS Origin 
headers, testing CSRF token removal — all of it happens in Repeater first, before any 
automation.

## 3. Intruder — Automated Payload Insertion

Intruder takes one request, marks one or more positions as "payload slots," and 
re-sends the request once per payload in a list you provide.

**Attack types, broken down:**
- **Sniper** — one payload set, cycles through positions one at a time (good for 
  testing each parameter individually for the same vulnerability)
- **Battering ram** — same payload inserted into ALL positions simultaneously (good 
  when the same value needs to go in two places at once, like username appearing in 
  both a cookie and a body field)
- **Pitchfork** — multiple payload sets, one per position, all advancing together 
  (good for testing username+password pairs together)
- **Cluster bomb** — multiple payload sets, every combination tested (good for 
  brute-forcing two independent unknowns, like a 2-character boolean-blind SQLi 
  extraction where you're testing both position AND character value)

**Why this matters for specific notes later:** boolean-blind SQLi extraction, 
brute-forcing with Hydra-equivalent logic inside Burp, and basic fuzzing all use 
Intruder's core mechanic — you mark a position, you supply a payload list, Burp 
automates the repetition that would take forever by hand in Repeater.

## 4. Decoder — Encoding/Decoding Swiss Army Knife

Paste any value in, choose an encoding (URL, Base64, Hex, HTML entities, etc.), and 
Decoder converts it. This directly supports everything covered in file `05` 
(URL Structure & Encoding) — instead of manually calculating percent-encoding or 
Base64, Decoder does it instantly while you're building a payload.

## 5. Target / Site Map — Passive Recording of Everything You've Touched

As you browse a target through Proxy, Burp builds a tree of every URL/endpoint it's 
seen. Useful for attack surface mapping (covered in depth in the Subdomain Takeover & 
Recon notes) — a quick way to see the full structure of what you've discovered so far 
on a target.

## 6. Real-World Notes
- Community Edition (free) covers Proxy, Repeater, Intruder (rate-limited), Decoder, 
  and Target — everything needed for the vast majority of this repo's content. 
  Professional adds Scanner (automated vuln scanning) and unlocks full-speed Intruder 
  plus extensions like Turbo Intruder (used in the Race Conditions notes) and Param 
  Miner (used in the Web Cache Poisoning notes).
- Get comfortable with keyboard shortcuts early — `Ctrl+R` to send to Repeater, 
  `Ctrl+Shift+B` for URL-encode in Decoder-style fields — manual speed matters a lot 
  once you're doing real engagements under time pressure.
- A habit worth building now: every time you find something interesting in Proxy 
  history, send it to Repeater immediately rather than trying to replicate the request 
  by re-clicking in the browser — re-clicking often changes cookies/tokens and you lose 
  the exact state that triggered the interesting behavior.

Continue to → `08_Networking_Basics_for_Web_Pentest.md`
