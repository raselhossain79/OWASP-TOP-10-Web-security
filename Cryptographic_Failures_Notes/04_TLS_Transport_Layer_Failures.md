# 04 — Missing/Weak TLS Configuration

## 1. What This Category Covers

This file covers cryptographic failures that occur **in transit** rather than at rest —
problems with how a server negotiates and maintains an encrypted connection with clients,
as opposed to how it hashes passwords or signs tokens. TLS misconfiguration is one of the
most common A02:2021 findings in real assessments because it requires zero
application-level access to detect — it's visible from the network layer alone, before
you've even logged in.

## 2. Missing TLS Entirely

### What it is

The application is served over plain HTTP, or offers HTTP without a forced redirect to
HTTPS, meaning all traffic — including credentials and session tokens — travels in
plaintext and can be read or modified by anyone positioned on the network path
(public Wi-Fi, compromised router, malicious ISP, nation-state intercept).

### Real-world note

This is now rare for primary public-facing domains (browser warnings and SEO penalties
have largely forced adoption of HTTPS), but is still routinely found on **internal
admin panels, staging environments, IoT device management interfaces, and legacy
intranet applications** that were never intended to be internet-facing but ended up
reachable anyway. It is consistently one of the easiest, highest-confidence findings in
an internal network pentest.

## 3. Weak Cipher Suites and Protocol Versions

### What it is

Even when TLS is present, the server may still support:
- **SSLv2/SSLv3** — fully broken, vulnerable to POODLE (SSLv3) among others
- **TLS 1.0/1.1** — deprecated by all major browsers and PCI-DSS as of 2018-2020; weak
  against BEAST and other attacks
- **RC4 stream cipher** — statistically biased keystream, practically broken
- **Export-grade ciphers (40/56-bit)** — deliberately weakened for historical US export
  law compliance, now trivially brute-forceable
- **Anonymous/NULL ciphers** — encryption with no authentication, or no encryption at all
  while still being labeled a "cipher suite"

### Why this is a cryptographic failure category, not "just a config issue"

A server can use a mathematically strong algorithm (AES-256) and still be vulnerable if
the **handshake negotiation** allows fallback to a weaker option. The actual algorithm
strength used in any given connection is decided by negotiation — if a weak option is
*offered at all*, an active attacker performing a downgrade attack can often force its
use, regardless of how strong the server's preferred option is. The failure is in the
configuration allowing the weak option to exist, not in any single connection.

## 4. Certificate Misconfiguration

- **Expired certificates** — browsers reject the connection or warn, but some internal
  apps and APIs silently disable cert validation in client code to "fix" the warning,
  which removes the protection entirely rather than fixing the certificate
- **Self-signed certificates** in production — no trusted CA has verified the identity
  behind the certificate, making man-in-the-middle interception trivial for anyone
  willing to present their own self-signed cert, since nothing about the trust chain is
  actually being checked by a misconfigured client
- **Weak signature algorithms** on the certificate itself (e.g., SHA1-signed certs,
  now rejected by modern browsers but still found on internal systems)
- **Missing certificate revocation checking (OCSP/CRL)** — a compromised private key's
  certificate can continue to be trusted by clients that never check revocation status

## 5. Protocol Downgrade Attacks

### What it is

An active network attacker interferes with the TLS handshake to force the connection
down to a weaker protocol version or cipher suite than either side would normally choose,
then exploits the resulting weak connection. **POODLE** (Padding Oracle On Downgraded
Legacy Encryption) is the canonical named example — it combines a downgrade to SSLv3 with
a padding oracle attack (see file 02, section 4) against SSLv3's CBC-mode implementation
to decrypt session cookies.

This is a direct, real-world example of how the categories in this series connect: a
downgrade attack (transport-layer) creates the conditions for a padding oracle attack
(cipher-mode-layer) to succeed.

## 6. Mixed Content

A page served over HTTPS that loads scripts, stylesheets, or other active resources over
plain HTTP. Browsers increasingly block this outright for active content, but when
allowed, it reintroduces a plaintext, modifiable channel into an otherwise secure page —
an attacker who can intercept the HTTP resource can inject arbitrary JavaScript into the
"secure" page that loaded it.

---

## 7. testssl.sh — Full Usage Breakdown

`testssl.sh` is the industry-standard open-source command-line tool for auditing a
server's TLS/SSL configuration end-to-end in a single scan, covering protocol support,
cipher suites, certificate validity, and known named vulnerabilities (Heartbleed,
POODLE, BEAST, etc.) without needing separate tools for each check.

### 7.1 Full default scan

```bash
./testssl.sh https://target.com
```

Run with just the target URL, testssl.sh performs its complete default battery: protocol
support, cipher ordering/preference, certificate chain validation, and all of its
built-in named-vulnerability checks. This is the right starting point on any engagement
where TLS is in scope — there is rarely a reason to skip straight to narrower flags
unless you already know exactly what you're confirming.

### 7.2 Targeting specific checks

```bash
./testssl.sh --protocols --ciphers --vulnerable target.com:443
```

| Flag | Meaning |
|---|---|
| `--protocols` | Restricts the scan to **protocol version support** only (SSLv2 through TLS 1.3) — useful when you already know the cipher config is fine and only need to confirm whether legacy protocols are disabled |
| `--ciphers` | Restricts the scan to enumerating every **cipher suite** the server is willing to negotiate, listed by strength category (NULL, export, weak, strong) |
| `--vulnerable` | Runs only the named-CVE vulnerability checks (Heartbleed, POODLE, BEAST, CRIME, FREAK, Logjam, etc.) without the full protocol/cipher enumeration — faster when vulnerability status is the only thing you need for a report |
| `target.com:443` | Target host and port — testssl.sh requires the port to be explicit in some invocation styles even though 443 is the TLS default, to avoid ambiguity when scanning non-standard ports (e.g., `8443`) |

### 7.3 Checking certificate details only

```bash
./testssl.sh --certificate-info target.com
```

| Flag | Meaning |
|---|---|
| `--certificate-info` | Outputs only the certificate chain details: issuer, validity window, signature algorithm, Subject Alternative Names, and whether the chain is complete and trusted — useful for quickly confirming expiry dates or weak signature algorithms across a large list of hosts |

### 7.4 Scanning a list of hosts in one run

```bash
./testssl.sh --file hosts.txt --logfile results.log --quiet
```

| Flag | Meaning |
|---|---|
| `--file hosts.txt` | Reads a **list of targets** (one host\:port per line) instead of scanning a single host — used when auditing an entire subdomain list gathered during recon |
| `--logfile results.log` | Writes the full scan output to a file in addition to (or instead of, depending on verbosity flags) the terminal — necessary for keeping evidence when scanning many hosts in one run |
| `--quiet` | Suppresses testssl.sh's startup banner and informational chatter, leaving only scan results — keeps large multi-host log files readable |

### 7.5 Outputting machine-readable results

```bash
./testssl.sh --jsonfile results.json --csvfile results.csv target.com
```

| Flag | Meaning |
|---|---|
| `--jsonfile results.json` | Writes results in structured **JSON**, useful for feeding into other automation, dashboards, or custom report-generation scripts rather than manually re-reading terminal output |
| `--csvfile results.csv` | Writes results in **CSV** format, the easiest format to drop directly into a findings spreadsheet for client deliverables |

### 7.6 Why testssl.sh, specifically, over a generic port scanner

Tools like `nmap` have TLS-related scripts (`ssl-enum-ciphers`, `ssl-cert`), but
testssl.sh is purpose-built and maintained specifically to track the *current* set of
named TLS vulnerabilities and grading criteria (closely mirroring what services like
Qualys SSL Labs check), making it the more authoritative single source for a
TLS-specific finding in a professional report.

---

## 8. Real-World Workflow Summary For This File

1. Run a full default `testssl.sh` scan first — it's comprehensive and low-effort, and
   most findings in this category are config-level facts, not something requiring
   exploitation to prove.
2. Treat protocol/cipher findings as a **single combined finding** in the report when
   multiple weak options are open at once (e.g., "TLS 1.0 enabled" + "RC4 cipher
   available") rather than as separate line items — they share the same root cause
   (overly permissive server configuration) and a client fixing one will usually fix the
   others in the same change.
3. Always check certificate expiry and signature algorithm separately, since these are
   often missed by teams who only think of TLS misconfiguration as "wrong protocol
   version."
4. Where padding oracle conditions (file 02, section 4) are found alongside CBC-mode
   ciphers in an old protocol version, explicitly call out the **downgrade-to-oracle
   attack chain** in the report rather than reporting the two findings as unrelated.

Continue to `05_Cheatsheet_and_Lab_Mapping.md` for the consolidated cheatsheet and the
PortSwigger Academy lab mapping.
