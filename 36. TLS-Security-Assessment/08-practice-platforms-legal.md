# 08 — Practice Platforms (Legal & Authorized)

TLS misconfiguration is under-represented in standard web-app lab platforms
(PortSwigger, HackTheBox web modules, etc.) because most of those labs run
behind a shared, correctly-configured TLS termination layer that you're not
meant to touch — the vulnerable logic sits at the application layer, not the
transport layer. This section separates targets into two categories so the
authorization boundary stays unambiguous.

## 8.1 Category A — Reference-Only (Scan/Observe, Never "Exploit")

These are public services intentionally built to *demonstrate* specific TLS
states. Scanning them with `testssl.sh`/`openssl s_client` etc. is exactly
what they're for — but there's nothing to "exploit" here, and you should not
attempt to interact with them beyond passive assessment (no active MITM
attempts, no traffic injection, no load-testing).

- **badssl.com** — the standard reference: dozens of subdomains, each
  deliberately configured with one specific weakness (`expired.badssl.com`,
  `self-signed.badssl.com`, `wrong.host.badssl.com`, `rc4.badssl.com`,
  `dh480.badssl.com`, `tls-v1-0.badssl.com`, etc.). This is the best single
  place to practice *recognizing* each finding type from files 01–04,
  because each subdomain isolates exactly one variable.
- **howsmyssl.com** — reports back what protocol/cipher *your own client*
  negotiated; useful for understanding the client side of the handshake and
  for testing your own tooling's client-mode behavior.
- **Qualys SSL Labs' own test suite** (ssllabs.com) — running it against
  badssl.com subdomains is fully permitted (badssl.com exists specifically
  to be scanned) and gives you the "graded report" format to get used to.

Nothing on these public reference services should be treated as a stand-in
for a real target — they exist purely so the specific *signatures* of each
weakness (what does an expired-cert scan actually look like in testssl.sh
output?) become familiar before you look at a real assessment.

## 8.2 Category B — Your Own Lab (Full Practice Cycle, Including Fixing)

To actually practice the full test → identify → remediate → re-test cycle
described throughout this library, you need a server where you control the
TLS configuration yourself. Recommended setup:

1. **Local VM or cloud VPS you own** (e.g., a small DigitalOcean/Linode/AWS
   instance, or a local VirtualBox/VMware VM) running nginx or Apache.
2. **Deliberately misconfigure it** to reproduce each finding one at a time:
   - Set `ssl_protocols SSLv3 TLSv1;` to reproduce 01.1/5.2/5.3 findings.
   - Set a weak cipher string (`ssl_ciphers 'RC4:DES:EXPORT';`) to reproduce
     02.2/02.3/5.6 findings.
   - Generate a self-signed cert with a 1024-bit RSA key and MD5 signature
     (`openssl req -x509 -newkey rsa:1024 -md5 ...`) to reproduce 03.5/03.6/03.7.
   - Omit `Strict-Transport-Security` header entirely, then add it, to
     compare 04.2 before/after.
3. **Scan your own misconfigured lab** with every tool in file 07, confirm
   the finding appears exactly as documented, **then fix it** using the
   remediation steps and re-scan to confirm the fix worked.
4. **Never expose this lab to the public internet** while intentionally
   vulnerable (bind it to a private IP, VPN-only, or a security group
   restricted to your own IP) — a deliberately weak TLS server is itself a
   liability if internet-reachable.

This is the only way to close the full loop your library format requires
(test → weakness → fix), since Category A targets are read-only by design.

## 8.3 What NOT to Do

- Do not run `testssl.sh -U` (active vulnerability probes like Heartbleed)
  against any third-party production site without written authorization —
  several of these checks send malformed/edge-case handshake data, and
  while generally low-risk, they are still active probing against a system
  you don't own.
- Do not attempt any actual downgrade/MITM demonstration (POODLE, FREAK,
  DROWN exploitation, not just detection) against anything other than your
  own lab — detection scans are passive observation of what the server
  offers; exploitation requires network positioning that is not appropriate
  outside an authorized engagement or your own lab.
- If a freelance/client engagement is the real target: get the TLS
  assessment scope written into the same authorization/rules-of-engagement
  document that covers the rest of the pentest — don't assume "web app
  pentest" authorization automatically covers active TLS vulnerability
  probing unless it's explicitly listed.
