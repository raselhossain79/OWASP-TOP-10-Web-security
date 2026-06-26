# 02 — Hashing and Encryption Weaknesses

## 1. Weak/Broken Hashing Algorithms (MD5/SHA1 Misuse)

### What it is

MD5 and SHA1 are **cryptographic hash functions**, not encryption. They are designed to
be fast and deterministic — exactly the wrong properties for protecting passwords. Fast
hashing means an attacker with the hash can try billions of guesses per second on a GPU.
Both algorithms are also considered cryptographically broken for integrity purposes:
practical collision attacks exist for MD5 (since 2004) and SHA1 (Google's SHAttered
attack, 2017), meaning two different inputs can be crafted to produce the same hash.

### Why it happens

- Legacy code that predates modern guidance (bcrypt, scrypt, Argon2) and was never
  migrated
- Developers treating "hashed" and "secure" as synonyms without checking which algorithm
  or whether a salt is applied
- Hashing used for things it was never meant for: session tokens, "encrypting" data by
  hashing it (which is irreversible and breaks functionality, so developers often misuse
  reversible encoding like Base64 instead and call it "encryption")

### How to recognize it

| Hash type | Length (hex) | Notes |
|---|---|---|
| MD5 | 32 chars | `5f4dcc3b5aa765d61d8327deb882cf99` |
| SHA1 | 40 chars | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| SHA256 | 64 chars | Still fast — needs work-factor wrapping (PBKDF2/bcrypt) for passwords |
| bcrypt | starts with `$2a$`, `$2b$`, or `$2y$` | Includes cost factor and salt in the string itself |

A hash with no salt produces the **identical output** for the **identical input** every
time. If you see the same hash value appear twice for two different user accounts in a
database dump, that is direct proof of a missing salt — both users have the same
password.

### Real-world note

Unsalted SHA1/MD5 password databases are still found regularly in security
assessments of legacy internal applications, especially ones that have not had their
auth layer touched since initial development. The LinkedIn 2012 breach (unsalted SHA1)
is the textbook reference case: once leaked, attackers cracked the overwhelming majority
of hashes using precomputed rainbow tables because there was no salt to break the
table-lookup approach.

---

## 2. Hardcoded Secrets

### What it is

Cryptographic keys, API tokens, JWT signing secrets, or database credentials embedded
directly in source code, configuration files, mobile app binaries, or client-side
JavaScript bundles instead of being injected at runtime from a secure secrets manager
(Vault, AWS Secrets Manager, environment variables backed by a KMS).

### Where to look on an engagement

- `.git` history (`git log -p` on cloned repos, or tools like `trufflehog`/`gitleaks`)
- Decompiled mobile APKs/IPAs (`strings`, `jadx`, `apktool`)
- Client-side JS bundles served to the browser — `grep` for `secret`, `apiKey`,
  `Authorization`, `Bearer`, base64-looking strings
- Public GitHub repos for the target org (search by domain name, internal hostnames)
- Docker images pushed to public registries (`docker history`, layer inspection)

### Real-world note

Hardcoded secrets in JS bundles are one of the highest-volume bug bounty finding
categories precisely because the entire bundle is delivered to every visitor's browser —
no authentication is required to find them. A hardcoded JWT HMAC secret found this way is
a direct path to full authentication bypass (see file 03), which is why this technique is
always worth a few minutes on any engagement, regardless of the primary scope.

---

## 3. Weak Key Generation and Weak Randomness

### What it is

Using a non-cryptographic pseudo-random number generator (PRNG) where a
cryptographically secure PRNG (CSPRNG) is required. Standard library functions like
`Math.random()` (JavaScript), `rand()` (C), or `random.random()` (Python) are designed
for statistical distribution, not unpredictability — their internal state can often be
recovered or predicted from a handful of outputs.

### Why it matters

If session tokens, password reset tokens, or encryption keys are generated this way, an
attacker who can observe a few generated values may be able to predict future or past
values, effectively bypassing the randomness entirely.

### Correct vs incorrect generation

| Language | Insecure | Secure (CSPRNG) |
|---|---|---|
| JavaScript/Node | `Math.random()` | `crypto.randomBytes()` |
| Python | `random.random()` | `secrets.token_bytes()` |
| Java | `java.util.Random` | `java.security.SecureRandom` |
| PHP | `rand()`, `mt_rand()` | `random_bytes()` |

### How to test for it on an engagement

Burp Suite's **Sequencer** tool is the standard approach: capture a large sample of
generated tokens (session IDs, reset tokens, "stay-logged-in" cookies) and run entropy
analysis. A poor "overall quality" rating from Sequencer is a direct, demonstrable
finding — you don't need to break the underlying algorithm, you only need to prove the
output is statistically predictable.

---

## 4. Padding Oracle Attacks

### What it is

A padding oracle attack exploits applications that use a **block cipher in CBC
(Cipher Block Chaining) mode** and that reveal — through distinct error messages,
response timing, or status codes — whether decrypted ciphertext had **valid PKCS#7
padding**. An attacker who can repeatedly submit modified ciphertext and observe whether
padding validation succeeds or fails can decrypt the entire ciphertext byte-by-byte,
**without ever knowing the encryption key**.

### Why it works (the mechanism, broken down)

1. CBC mode XORs each plaintext block with the previous ciphertext block before
   encrypting. Decryption reverses this: decrypt the ciphertext block, then XOR with the
   previous ciphertext block to recover plaintext.
2. PKCS#7 padding fills the final block to the cipher's block size and encodes *how much*
   padding was added inside the padding bytes themselves (e.g., if 3 bytes of padding
   are needed, all 3 bytes have the value `0x03`).
3. If you flip bits in the second-to-last ciphertext block and resubmit, you change what
   the decrypted padding *looks like* without needing the key — because the XOR happens
   *after* decryption.
4. By systematically trying all 256 possible values for one byte at a time and watching
   whether the server says "padding OK" vs "padding invalid" (via error text, status
   code, or timing), you can determine — one byte per "oracle query block" — what the
   decrypted intermediate value was, which lets you recover the original plaintext byte
   through a XOR calculation.
5. Tools like **PadBuster** and **Burp's own Bit Flipper / "Hash any token"** extensions
   automate this entire byte-recovery loop.

### Real-world note

Padding oracle attacks were the mechanism behind several severe real-world findings,
most famously **Microsoft ASP.NET's "MS10-070"** (2010), where the framework's encrypted
`ViewState` parameter was vulnerable to a padding oracle that allowed full plaintext
recovery and, combined with other ASP.NET internals, remote code execution on affected
servers. The general lesson that came out of this and similar findings is now standard
guidance: **never use unauthenticated CBC mode for anything an attacker can submit back
to the server.** Modern guidance is to use **AEAD ciphers** (AES-GCM, ChaCha20-Poly1305)
which detect tampering before decryption even begins, making the oracle impossible to
construct.

### Why there's no PortSwigger lab for this

Padding oracle attacks require a stateful interaction loop (repeated submission +
oracle observation) that doesn't fit PortSwigger's typical single-flag lab format. This
is purely a real-world / external-tooling technique — see file 05 for how this is framed
in the lab-mapping cheatsheet.

---

## 5. hashcat — Full Usage Breakdown

`hashcat` is the industry-standard GPU-accelerated password and hash cracking tool. It is
the direct, professional-grade equivalent of what the PortSwigger "Offline password
cracking" and "Brute-forcing a stay-logged-in cookie" labs simulate manually through Burp
Intruder.

### 5.1 Identifying the hash before cracking

Before running hashcat, you need to know **which mode number** corresponds to the
algorithm. Use `hashcat --help | grep -i md5` (or check `hash-identifier` / `hashid`) to
confirm. Getting the mode wrong means hashcat will run against the wrong algorithm and
silently fail to crack anything that is actually crackable.

### 5.2 Core dictionary attack command

```bash
hashcat -m 0 -a 0 hashes.txt rockyou.txt -o cracked.txt --force
```

Breaking this down flag by flag:

| Flag | Meaning | Why it's there |
|---|---|---|
| `-m 0` | Hash **mode** = 0 | Mode `0` tells hashcat the hash type is raw MD5. Every algorithm has its own number (`100` = SHA1, `1400` = SHA256, `3200` = bcrypt). Without this, hashcat doesn't know what mathematical operation to reverse-test against. |
| `-a 0` | Attack **mode** = 0 (straight/dictionary attack) | Tells hashcat to take each word in the wordlist as-is and hash it, then compare to the target hash. Attack mode `3` would instead be brute-force mask attack; `6`/`7` are hybrid dictionary+mask. |
| `hashes.txt` | Input file containing the target hash(es) | One hash per line. Can also include `username:hash` format depending on mode. |
| `rockyou.txt` | The wordlist (dictionary) to test | `rockyou.txt` is the de facto standard wordlist in the industry — derived from a real 2009 breach of ~14 million plaintext passwords, making it highly representative of real human password choices. |
| `-o cracked.txt` | **Output** file for successfully cracked hash:plaintext pairs | Without `-o`, results are only shown on screen and written to hashcat's internal `.potfile`; explicit output makes results easy to hand off in a report. |
| `--force` | Bypass hardware/driver warnings | Used when hashcat detects a suboptimal GPU setup (e.g., running inside a VM without GPU passthrough) but you still want it to proceed using CPU/whatever device is available. Should not be used to silence warnings you haven't actually understood — only after confirming the warning is benign. |

### 5.3 Cracking a salted hash format (matching the PortSwigger "stay-logged-in" cookie structure)

The lab's cookie is `base64(username + ':' + md5(password))`. Once decoded, you have a
known username and an MD5 hash. To crack it with hashcat directly (instead of manual Burp
Intruder payload processing):

```bash
hashcat -m 0 -a 0 51dc30ddc473d43a6011e9ebba6ca770 /usr/share/wordlists/rockyou.txt
```

Here the hash is passed **directly on the command line** instead of via a file — hashcat
accepts either, and for a single hash this avoids creating a throwaway file. `-m 0`
still applies because, once base64-decoded, the secret being cracked is plain unsalted
MD5; the username prefix and the base64 wrapper are just *encoding*, not encryption, so
they are stripped before this step, not part of what hashcat operates on.

### 5.4 Mask attack (when you know the password's structure)

```bash
hashcat -m 0 -a 3 hashes.txt ?u?l?l?l?l?d?d?d
```

| Flag | Meaning |
|---|---|
| `-a 3` | Attack mode 3 = brute-force using a **mask** instead of a wordlist |
| `?u` | One uppercase letter |
| `?l?l?l?l` | Four lowercase letters |
| `?d?d?d` | Three digits |

This is used when you have intelligence on password policy (e.g., "must start with
capital, minimum 8 characters, ends in 3 digits" from a password policy page) — it is far
faster than a blind dictionary attack because it only tries combinations matching the
known structure.

### 5.5 Rule-based attack (dictionary + mutation rules)

```bash
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

| Flag | Meaning |
|---|---|
| `-r best64.rule` | Apply a **rule file** that mutates each dictionary word (e.g., appends `123`, capitalizes first letter, swaps `a`→`@`, reverses the string) before hashing it |

This is the realistic real-world attack pattern: humans pick a dictionary word and
predictably modify it ("password" → "P@ssword1"), so rule-based dictionary attacks crack
far more real-world passwords than either pure dictionary or pure brute-force alone.

### 5.6 Benchmark / verifying GPU acceleration is active

```bash
hashcat -b -m 0
```

| Flag | Meaning |
|---|---|
| `-b` | Run hashcat's built-in **benchmark** mode | Confirms the tool is correctly using available GPU acceleration before committing to a long crack job — if the reported hashes/second is unexpectedly low (matching CPU-only speeds), the GPU driver/OpenCL setup needs fixing first. |

### 5.7 Show already-cracked results without re-running

```bash
hashcat -m 0 hashes.txt --show
```

`--show` checks the supplied hash list against hashcat's `.potfile` (its running history
of every hash it has ever cracked) and prints matches immediately, without spending GPU
time re-cracking anything already solved in a previous session.

---

## 6. Real-World Workflow Summary For This File

On an actual engagement, the realistic order of operations is:

1. Identify weak hash usage from its fingerprint (length, charset, lack of salt
   indicators) rather than assuming.
2. Check first whether the hash is already in public breach databases / rainbow tables
   (fastest path — no cracking needed if the password is common).
3. If not, run hashcat with a targeted wordlist + rules before falling back to brute
   force, since rule-based dictionary attacks crack the large majority of real human
   passwords far faster than blind brute force.
4. Separately, search the same codebase/JS bundles/repos for hardcoded secrets — these
   are independent of password strength entirely and often yield faster, higher-impact
   results.
5. Report the **root cause** (algorithm choice, missing salt, missing KMS-backed secret
   storage) — not just the cracked value — since the cracked value is evidence, not the
   fix.

Continue to `03_JWT_Cryptographic_Attacks.md` for JWT-specific cryptographic flaws and the
jwt_tool deep-dive.
