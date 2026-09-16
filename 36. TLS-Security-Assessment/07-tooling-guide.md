# 07 — Tooling Guide (Flag-by-Flag)

## 7.1 testssl.sh

The primary tool for this entire library — covers nearly every check in
files 01–05 in a single run.

```bash
./testssl.sh --full -oA report_hostname https://target.example.com
```
| Flag | Meaning |
|---|---|
| `--full` | Runs every check testssl.sh has (protocols, ciphers, certs, vulns, headers) |
| `-oA` | Output to all supported formats (log, csv, json, html) using the given prefix |

Targeted runs (faster, useful when re-checking a single finding):
| Flag | Checks |
|---|---|
| `-p` | Protocols only |
| `-e` / `--each-cipher` | Every cipher individually, per protocol |
| `-S` | Server preferences / cipher order |
| `-h` | Header checks (HSTS, etc.) |
| `-U` | All known vulnerabilities (Heartbleed, POODLE, FREAK, Logjam, DROWN, ROBOT, Sweet32, Lucky13 in one pass) |
| `-H` | Heartbleed only |
| `-O` | POODLE only |
| `-D` | DROWN only |
| `-B` | BEAST only |
| `-C` | CRIME/compression only |
| `-4` | Only IPv4 (useful when a host resolves to both and you want to scope the test) |

### Output interpretation
- Color coding: red = vulnerable/critical, yellow = weak/warning, green =
  ok. When exporting to JSON for reporting, the `severity` field mirrors
  this directly (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `OK`, `INFO`).
- Always run against every distinct hostname/SNI value, not just the bare
  IP — testssl.sh does not auto-discover other vhosts on the same server.

---

## 7.2 sslyze

Fast, scriptable, good for automating checks across many hosts (e.g., CI
pipelines or asset inventories) since it outputs structured JSON natively.

```bash
sslyze --regular target.example.com:443 --json_out=results.json
```
| Flag | Meaning |
|---|---|
| `--regular` | Runs the standard scan set (protocols, ciphers, certs, common vulns) |
| `--json_out` | Write machine-readable results to file |
| `--certinfo` | Certificate-specific checks only (validity, chain, hostname) |
| `--heartbleed` | Heartbleed-specific check only |
| `--robot` | ROBOT-specific check only |
| `--elliptic_curves` | Lists supported EC curves (feeds file 02.7) |

---

## 7.3 SSLScan

Lightweight, quick for a fast first pass before a full testssl.sh run.

```bash
sslscan --show-certificate --no-failed target.example.com:443
```
| Flag | Meaning |
|---|---|
| `--show-certificate` | Prints full certificate details inline |
| `--no-failed` | Suppresses ciphers the server rejected, showing only accepted ones (cleaner output for reporting) |
| `--tlsall` | Force-test all protocol versions including deprecated ones |

---

## 7.4 Nmap SSL Scripts

Useful when TLS assessment is part of a broader Nmap-driven recon pass
rather than a standalone step.

```bash
nmap --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params -p 443 target.example.com
```
| Script | Checks |
|---|---|
| `ssl-enum-ciphers` | Cipher enumeration with per-protocol letter grade |
| `ssl-cert` | Certificate details (validity, SAN, issuer) |
| `ssl-heartbleed` | Heartbleed |
| `ssl-poodle` | POODLE (SSLv3 CBC padding oracle) |
| `ssl-dh-params` | DH parameter strength (Logjam-relevant) |
| `ssl-ccs-injection` | CCS injection vulnerability (CVE-2014-0224) |

---

## 7.5 OpenSSL s_client (Manual Technique)

The manual fallback for confirming any automated tool's finding by hand —
important because automated tools occasionally misreport, and manual
confirmation is expected practice before including a finding in a report.

```bash
openssl s_client -connect target.example.com:443 -servername target.example.com -tls1_2
```
| Flag | Meaning |
|---|---|
| `-connect host:port` | Target |
| `-servername` | Sets SNI — required for any multi-tenant/CDN-fronted host |
| `-tls1`, `-tls1_1`, `-tls1_2`, `-tls1_3`, `-ssl3` | Force a specific protocol version to test if it's accepted |
| `-cipher` | Force a specific cipher/cipher list to test negotiation |
| `-showcerts` | Print the full certificate chain as sent by the server |
| `-status` | Request OCSP stapling and show the response |
| `-alpn` | Test ALPN negotiation for a given protocol list |

Combine with `openssl x509 -noout -text` (piped from a saved cert) to
inspect certificate fields as detailed throughout file 03.

---

## 7.6 SSL Labs (Qualys) — Methodology

Qualys SSL Labs is a hosted, third-party scanner — using it means the
target's TLS configuration snapshot is submitted to and cached by a
third-party service. Only use it against domains you're authorized to
publicly expose test results for (results are cacheable/visible via the
public results URL unless the "do not show results on the boards" option is
used).

```
https://www.ssllabs.com/ssltest/analyze.html?d=target.example.com
```
- Grading logic: overall letter grade (A+ to F) is a composite of
  protocol support, key exchange strength, cipher strength, and a set of
  deductions for specific vulnerabilities/misconfigurations found — read
  the individual category breakdown, not just the letter grade, since two
  very different configurations can land on the same letter.
- Useful specifically for: chain issues, HSTS preload list status, and a
  second independent opinion to cross-check testssl.sh findings before
  finalizing a report.
