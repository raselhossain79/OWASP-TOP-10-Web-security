# 05 — Known CVE-Class Vulnerabilities

Each entry below is a named, publicly documented TLS/SSL vulnerability class.
Where a check duplicates an item already detailed in files 01/02/04 (e.g.
POODLE relates directly to SSLv3 support), this file gives the exploit-level
view: what the attack actually does once the underlying weakness is present.

## 5.1 Heartbleed (CVE-2014-0160)

**Mechanism:** OpenSSL's heartbeat extension didn't validate that the
requested payload length matched the actual data sent, allowing a remote
attacker to read up to 64KB of server process memory per request — no
authentication required.
**Impact:** Critical. Memory disclosure can leak private keys, session
tokens, credentials, or any other in-memory secret.
**Detection:** `testssl.sh -H`, or `nmap --script ssl-heartbleed -p 443
target`. A vulnerable response returns more data than requested/expected.
**Remediation:** Patch OpenSSL (fixed in 1.0.1g+); **rotate the private key
and reissue the certificate** even after patching, since historical
exploitation before detection could have already leaked the key.

## 5.2 POODLE (CVE-2014-3566)

**Mechanism:** SSLv3's CBC-mode padding is not covered by the MAC, letting
an attacker who controls network position and can trigger repeated requests
(e.g., via malicious JavaScript in the browser) decrypt one byte of
ciphertext per ~256 requests.
**Impact:** Critical for session cookie/token theft.
**Detection:** `testssl.sh -O`. See also 01.4.
**Remediation:** Disable SSLv3 entirely (see 01.1); no partial mitigation is
considered acceptable.

## 5.3 BEAST (CVE-2011-3389)

**Mechanism:** Predictable IVs in TLS 1.0's CBC-mode ciphers let an attacker
with chosen-plaintext capability (again, typically via browser-executed
script) perform a block-wise chosen-boundary attack to decrypt data such as
cookies.
**Impact:** High historically; largely mitigated by modern browsers via
1/n-1 record splitting, but the server-side weakness (TLS 1.0 + CBC) is
still worth flagging since not all clients apply the mitigation.
**Detection:** `testssl.sh -B`.
**Remediation:** Prefer TLS 1.2+/AEAD ciphers (GCM); disabling TLS 1.0
resolves this alongside its other issues (see 01.1).

## 5.4 CRIME (CVE-2012-4929)

**Mechanism:** TLS-level compression creates a size-based side channel;
an attacker who can inject chosen plaintext alongside a secret (e.g., a
cookie) and observe compressed length can recover the secret byte-by-byte.
**Impact:** High.
**Detection:** `testssl.sh -C`. See also 04.5.
**Remediation:** Disable TLS compression (04.5).

## 5.5 BREACH (CVE-2013-3587)

**Mechanism:** The HTTP-layer analog of CRIME — targets *HTTP response*
compression (gzip), not TLS compression, so disabling TLS compression alone
does not fix this.
**Impact:** High — can leak CSRF tokens or other reflected secrets embedded
in compressed, attacker-observable responses.
**Detection:** Check whether responses containing secret values are also
gzip/deflate-compressed and whether an attacker-influenced parameter is
reflected in the same response.
**Remediation:** Disable compression for responses containing secrets,
randomize secret token placement/length per request, add unrelated
random padding, or set `Cache-Control: no-store` where relevant. This is an
application-layer fix, not a TLS config change — cross-reference the
cryptographic-failures file in the web vulnerability series.

## 5.6 FREAK (CVE-2015-0204)

**Mechanism:** Server accepts legacy export-grade RSA cipher suites
(512-bit); an attacker can factor the 512-bit key in a matter of hours with
modest cloud compute and forge the handshake.
**Impact:** Critical.
**Detection:** `testssl.sh` cipher listing — look for `EXP` ciphers offered.
See also 02.3.
**Remediation:** Remove all export cipher suites from the server config.

## 5.7 Logjam (CVE-2015-4000)

**Mechanism:** Similar to FREAK but targets Diffie-Hellman — servers using
weak, common 512/768/1024-bit DH groups are vulnerable to precomputation
attacks against those (widely-reused) groups.
**Impact:** High.
**Detection:** `testssl.sh` DH parameter check. See also 02.6.
**Remediation:** Use 2048-bit+ custom DH parameters or prefer ECDHE.

## 5.8 DROWN (CVE-2016-0800)

**Mechanism:** If a server (or any other server sharing the same private
key) supports SSLv2, an attacker can use SSLv2 as a decryption oracle
against modern TLS sessions protected by the same key, due to a cross-
protocol weakness in SSLv2's export cipher handling.
**Impact:** Critical.
**Detection:** `testssl.sh -D`, plus checking whether the same certificate/
key is reused on any SSLv2-enabled service (mail, FTP-over-TLS, etc.).
**Remediation:** Disable SSLv2 on every service sharing that key, or use
dedicated keys per service.

## 5.9 ROBOT (CVE-2017-13099 and related, per-vendor CVEs)

**Mechanism:** A revival of the 1998 Bleichenbacher padding oracle attack
against RSA PKCS#1 v1.5 key exchange — subtly different server error
behavior on malformed ciphertext lets an attacker decrypt captured RSA-
encrypted traffic or forge signatures over many queries.
**Impact:** Critical.
**Detection:** `testssl.sh -U` includes ROBOT; dedicated `robot-detect`
tooling from the original researchers is also available.
**Remediation:** Patch the TLS stack (most major vendors issued fixes);
prefer ECDHE key exchange over RSA key exchange, which sidesteps the
vulnerable code path entirely.

## 5.10 Sweet32 (CVE-2016-2183 / CVE-2016-6329)

**Mechanism:** 64-bit block ciphers (3DES, Blowfish) are vulnerable to a
birthday-bound collision attack when a large volume of traffic (~32GB) is
encrypted under the same key — collisions leak plaintext XOR relationships.
**Impact:** Medium-High, primarily relevant for long-lived, high-volume
connections (e.g., VPN tunnels) more than typical short web sessions, but
still a valid finding for any 3DES-enabled web server.
**Detection:** `testssl.sh` cipher listing — flag any `3DES`/`DES` suite as
offered. See also 02.2.
**Remediation:** Remove 3DES/64-bit block ciphers from the cipher suite
list.

## 5.11 Lucky13 (CVE-2013-0169)

**Mechanism:** A timing side-channel in CBC-mode MAC-then-encrypt padding
validation — subtle timing differences during MAC verification can leak
information about plaintext, similar in spirit to POODLE but timing-based
rather than a direct padding-oracle response difference.
**Impact:** Medium (requires precise timing measurement, generally harder
to exploit reliably than POODLE).
**Detection:** `testssl.sh -U` includes Lucky13 in its vulnerability sweep.
**Remediation:** Prefer AEAD ciphers (GCM/ChaCha20-Poly1305) over CBC mode
entirely, which removes the vulnerable code path.
