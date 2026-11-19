# Origin IP Discovery

## 1. Purpose
Find the real server IP behind a CDN/WAF. If successful, later testing can hit the
origin directly — though whether you're *allowed* to do that is a separate question
(see Section 11).

## 2. When to Use
After confirming a target sits behind a CDN/WAF (`cdn-waf-identification.md`), and
before deciding whether filter-bypass work (`07-WAF-and-Filter-Analysis/`) is
necessary at all.

## 3. Prerequisites
Confirmed scope including whether direct-origin testing is permitted.

## 4. Methodology & Commands

### a) Historical DNS Records (passive)
```bash
curl -s "https://api.securitytrails.com/v1/history/dns/a?apikey=YOUR_KEY" \
  -H "hostname: target.com"
```
Also check `crt.sh` and DNSdumpster manually. These sources reflect **what DNS used
to point to**, not necessarily what's live now — treat any hit as a candidate to
verify, not a confirmed origin.

### b) Un-proxied Subdomains (passive/light-active)
```bash
cat subs.txt | httpx -silent -ip -o subs_with_ip.txt
```
Compare each resolved IP against the CDN's published ranges using proper CIDR
matching, not substring comparison (a substring match like grepping `"203.0.113"`
against an IP range is unreliable and can produce both false matches and misses):

```bash
python3 -c "
import ipaddress, urllib.request
ranges = urllib.request.urlopen('https://www.cloudflare.com/ips-v4').read().decode().splitlines()
candidate = ipaddress.ip_address('TARGET_IP_HERE')
in_cf = any(candidate in ipaddress.ip_network(r) for r in ranges if r)
print('In Cloudflare range:', in_cf)
"
```
This checks true CIDR containment (is the IP actually inside the published network
block) rather than comparing text. An IP that is **not** in any published CDN range
is a real candidate; one that **is** in range is not useful here (it's still behind
the CDN).

> Cloudflare's published ranges change periodically — always fetch them live, don't
> hardcode a saved copy.

### c) TLS Certificate Matching (passive)
```bash
openssl s_client -connect target.com:443 -servername target.com </dev/null 2>/dev/null \
  | openssl x509 -noout -serial -fingerprint -sha256
```
- `-servername target.com`: required for SNI-based virtual hosting. **Important
  limitation**: on a CDN edge, SNI tells the edge server which backend/cert to
  present — it does **not** mean you're talking to the origin. You will usually get
  the CDN edge's certificate for that hostname, not the origin's, when connecting to
  the public hostname. This command is useful for capturing the *target's*
  certificate fingerprint to search for elsewhere (see below), not for reaching the
  origin itself.
```bash
shodan search "ssl.cert.serial:<SERIAL_FROM_ABOVE>"
```
**Limitation to state plainly**: a serial/fingerprint match on Shodan is *supporting
evidence*, not proof. The same certificate can legitimately appear on multiple hosts
(wildcard certs across many subdomains, shared hosting, or even other CDN edge nodes
that happen to serve the same cert for routing reasons). Always confirm with the
content-verification step (Section 4e) before treating a match as the origin.

### d) Favicon Hash Matching (passive)
```bash
curl -s https://target.com/favicon.ico -o favicon.ico
python3 -c "
import mmh3, base64
data = open('favicon.ico','rb').read()
b64 = base64.encodebytes(data)
print(mmh3.hash(b64))
"
```
```bash
shodan search "http.favicon.hash:<HASH_FROM_ABOVE>"
```
Same caveat as certificate matching: a shared favicon (e.g. a common CMS default
icon) can produce unrelated matches — cross-check against other signals.

### e) Email Header Analysis (passive) — corrected
If the target sends transactional email, the originating mail server's IP can
appear in the `Received:` headers. **Correction from earlier guidance**: `Received:`
headers are prepended by each mail server as a message transits — the **most
recently added header is at the top** (your own mail provider's hop), and the
**header closest to the original sending server is near the bottom** of the stack,
just above the message body/other original headers. Read from the bottom of the
`Received:` block upward to trace back toward the origin, not top-down.

### f) Verifying a Candidate (active — only once, to confirm)
```bash
curl -s -k -H "Host: target.com" "https://<CANDIDATE_IP>/" | head -50
diff <(curl -s https://target.com/) <(curl -s -k -H "Host: target.com" https://<CANDIDATE_IP>/)
```
A matching response body is good confirmation the candidate IP serves the target's
content. This still does **not** prove it's the only origin, or that it's the
production origin rather than a staging mirror — note it as "confirmed to serve
matching content," which is what you actually know.

## 7. Expected Output
Zero, one, or several candidate IPs, each with its supporting evidence type
(DNS history / subdomain / cert / favicon / email) and a content-verification result.

## 8. Interpretation
- **Candidate origin**: one piece of supporting evidence, unverified.
- **Confirmed origin infrastructure**: content-verified via Section 4f, with at
  least one independent supporting signal (e.g. both cert match and matching
  response body). Still describe it as "the infrastructure serving this content
  from this IP," not "the single origin server," unless you have direct
  confirmation otherwise (e.g. from the client/program).

## 9. False Positives
- CDN edge nodes occasionally share certificates/favicons with origin-adjacent
  infrastructure for routing reasons — a single matching signal is not reliable
  alone.
- Historical DNS can point to infrastructure that has since been decommissioned or
  reassigned to an unrelated party (IP addresses get reused) — the content
  verification step (4f) is what rules this out.

## 10. Next Action
If a confirmed origin is found **and the program authorizes direct-origin testing**,
later vulnerability testing can target it directly, bypassing the CDN/WAF layer. If
not found, or not authorized, proceed to `07-WAF-and-Filter-Analysis/`.

## 11. Safety Considerations — Authorization, Not Just Technique
**Finding an origin IP does not automatically authorize sending test traffic to it.**
This is a genuinely separate question from the technical one:
- Many bug bounty programs explicitly prohibit bypassing their CDN/WAF, because the
  WAF/rate-limiting/DDoS protection is itself an in-scope control they want tested
  *as deployed*, not routed around.
- Direct-origin traffic can impact shared infrastructure (other tenants on the same
  host) not covered by your authorization.
- If scope is silent on this specific point, ask the program via their disclosed
  contact channel before using a discovered origin IP for anything beyond the
  passive confirmation steps above.

## 12. Documentation
Record: the IP, which evidence type(s) led to it, the content-verification result,
and — separately — whether you had explicit authorization to test it directly before
doing so.
