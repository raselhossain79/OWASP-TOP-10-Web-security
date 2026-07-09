# 03 — JWT-Specific Cryptographic Flaws

## 1. JWT Structure Recap (Why It Even Belongs In "Cryptographic Failures")

A JWT is three base64url-encoded segments separated by dots: `header.payload.signature`.
The header and payload are **only encoded, not encrypted** — anyone can decode and read
them. The signature is the only part that provides any cryptographic guarantee, and it
only guarantees **integrity** (the token hasn't been tampered with), not confidentiality.
Every attack in this file is really an attack on how the **signature is generated or
verified** — which is exactly why this whole topic sits inside Cryptographic Failures
rather than under broken access control, even though the *impact* is almost always
authentication/authorization bypass.

## 2. alg:none — Unverified Signature

### What it is

The JWT spec defines `"alg": "none"` for explicitly **unsecured** tokens — tokens with no
signature at all. Some JWT libraries, when misconfigured or when the verifying code
doesn't explicitly check for this case, will accept a token whose header says `alg: none`
and whose signature segment is simply empty.

### Why it happens

The vulnerability isn't in the JWT spec allowing `none` to exist — it's in **server-side
verification code that trusts the algorithm named inside the token itself** instead of
enforcing an expected algorithm independently. The header is attacker-controlled data;
trusting it to decide *how to verify itself* is the root design flaw, and `alg:none` is
just the most direct way to exploit that flaw.

### Exploitation, step by step

1. Decode the JWT header, change `"alg": "HS256"` (or whatever it was) to `"alg": "none"`.
2. Modify the payload claims as desired (e.g., change `"sub": "wiener"` to
   `"sub": "administrator"`).
3. Re-encode header and payload, and submit the token with an **empty signature
   segment** — the token ends in a trailing dot with nothing after it:
   `eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.`
4. If the server's verification logic only checks "does the algorithm in the header say
   none, and if so, skip signature checks," the forged token is accepted.

### Real-world note

This exact flaw is what PortSwigger's lab calls "flawed signature verification" — and
it is a recurring, *not theoretical*, finding in production systems using older or
manually-implemented JWT handling, particularly in internal/legacy services that predate
hardened libraries like `jsonwebtoken` (Node) or `PyJWT`'s modern defaults, both of which
now reject `none` unless explicitly opted into.

---

## 3. Weak HMAC Secret (Brute-Forceable Signing Key)

### What it is

HS256/HS384/HS512 JWTs are signed using a single **symmetric secret** shared between
whoever issues tokens and whoever verifies them. If that secret is short, a dictionary
word, or a default value left over from a tutorial/example (`secret`, `your-256-bit-secret`,
`changeme`), it can be brute-forced offline once you have **one valid signed token** — you
don't need to compromise the server at all.

### Why it happens

Developers often generate the secret once during initial setup (sometimes copy-pasted
from documentation examples) and never rotate it, or use a short human-memorable string
instead of a properly generated high-entropy key.

### Exploitation, step by step

1. Capture any valid JWT issued by the target (your own session token is enough).
2. Run it against a wordlist of common/default JWT secrets using **hashcat** (mode `16500`
   for JWT) or **jwt_tool** (see section 5 below).
3. Once the secret is recovered, you can sign **arbitrary forged tokens** yourself —
   including ones with elevated privilege claims — because you now hold the same key the
   server uses to verify.

### hashcat command for this specific case

```bash
hashcat -m 16500 jwt.txt rockyou.txt
```

| Flag | Meaning |
|---|---|
| `-m 16500` | Hash mode specifically built for JWT (HS256/384/512) — hashcat internally reconstructs `HMAC(secret, header.payload)` for each wordlist candidate and compares it to the signature segment of the token |
| `jwt.txt` | File containing the full raw JWT (all three segments, dots included) |
| `rockyou.txt` | Wordlist — for this use case, a list specifically of common JWT secrets (e.g., the `jwt-secrets` lists circulated in the bug bounty community) is far more effective than a general password list |

---

## 4. jwk / jku / kid Header Injection

These three attacks exploit **attacker-controllable header parameters that tell the
server which key to use for verification** — turning the verification step itself into
something the attacker can redirect.

### 4.1 jwk (embedded JSON Web Key)

The `jwk` header parameter lets the token **carry its own public key** inline. If the
server is misconfigured to trust whatever key is embedded in the token rather than only
trusting its own pre-configured key, an attacker can:
1. Generate their own RSA keypair.
2. Sign a forged token (with elevated claims) using their **private** key.
3. Embed their **public** key in the `jwk` header.
4. The server reads the embedded public key, uses it to verify the signature
   (successfully, since the attacker signed with the matching private key), and trusts
   the forged claims.

### 4.2 jku (JWK Set URL)

Same root flaw, different delivery: instead of embedding the key directly, the header
contains a **URL** the server should fetch the key set from. If the server doesn't
restrict this to an allow-list of trusted hosts, the attacker hosts their own JWK Set
(containing their public key) at a URL they control, points `jku` at it, and the server
fetches and trusts it.

### 4.3 kid (Key ID) — Path Traversal / SQL Injection variant

`kid` tells the server *which* of its multiple known keys to use (e.g., a filename or DB
row lookup). If this value is used unsafely in a filesystem path or SQL query:
- **Path traversal**: set `kid` to `../../../../dev/null` (or another file with
  fully predictable contents) so the server reads that file *as if it were the signing
  key*. Since you now know the exact key content (an empty value, in the `/dev/null`
  case), you can sign a token using that same known value as the HMAC secret.
- **SQL injection**: if `kid` is interpolated into a query, classic SQLi techniques
  (see this account's SQL Injection series) can be used to manipulate which key is
  returned or to return attacker-controlled data as the "key."

---

## 5. Algorithm Confusion (RS256 → HS256)

### What it is

RS256 is **asymmetric** — the server signs with a private key and verifies with a
**public** key, which by design is not secret and is often exposed at a `/jwks.json` or
similar endpoint for legitimate client-side verification needs. HS256 is **symmetric** —
the same secret is used to sign and verify. Algorithm confusion exploits servers whose
verification code does **not pin the expected algorithm** and instead trusts the `alg`
field in the token header to decide which verification routine to run.

### Exploitation, step by step

1. Obtain the server's RSA **public** key (often exposed at a standard JWKS endpoint).
2. Forge a new token, setting the header's `alg` to `HS256` instead of `RS256`.
3. Sign this forged token using the **public key's raw bytes as if they were an HMAC
   secret**.
4. If the server's verification library doesn't enforce "this endpoint only accepts
   RS256," it runs HMAC verification using its own public key (which it has on hand) as
   the "secret" — and the signature matches, because that's exactly what you signed with.

This is genuinely one of the more conceptually subtle attacks in the JWT family: the
public key being public is *by design*, and the attack only works because the
**verification code, not the key**, fails to distinguish which algorithm family was
supposed to be used.

### Why no public key exposed isn't full protection

A related, more advanced variant exists for cases where the public key is **not**
directly exposed but two valid tokens signed by the server can be observed. Tools like
PortSwigger's `sig2n` use the mathematical relationship between RSA signatures to
calculate possible values of the public modulus `n`, then attempt forgery using each
candidate — this is significantly harder and is an Expert-difficulty technique.

---

## 6. jwt_tool — Full Usage Breakdown

`jwt_tool` is the standard purpose-built command-line tool for testing JWT
implementations, covering nearly every attack in this file in one utility.

### 6.1 Basic decode (no attack, just inspection)

```bash
python3 jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3aWVuZXIifQ.abc123
```

Run with no flags, jwt_tool simply parses and pretty-prints the header and payload JSON,
and flags anything notable (missing `exp` claim, use of `none`, weak-looking secrets,
etc.) before you've run any attack — useful as the first command on any JWT you encounter.

### 6.2 Tampering a claim and resigning with a known/guessed secret

```bash
python3 jwt_tool.py <token> -T -p secret123
```

| Flag | Meaning |
|---|---|
| `-T` | **Tamper** mode — opens an interactive prompt letting you edit header and payload claims one at a time before resigning |
| `-p secret123` | Supplies the **secret** key to use when resigning the modified token (use this once you already know or have cracked the HMAC secret) |

### 6.3 Dictionary attack against the HMAC secret

```bash
python3 jwt_tool.py <token> -C -d secrets_list.txt
```

| Flag | Meaning |
|---|---|
| `-C` | **Crack** mode — tells jwt_tool to attempt to determine the signing secret rather than assume it |
| `-d secrets_list.txt` | The **dictionary** file of candidate secrets to test against the token's signature |

This is jwt_tool's built-in equivalent of the hashcat `-m 16500` approach from section 3 —
useful when you want decode/tamper/crack to happen in one tool without switching to
hashcat, though hashcat is meaningfully faster for large wordlists due to GPU
acceleration.

### 6.4 Forcing the alg:none bypass

```bash
python3 jwt_tool.py <token> -X a
```

| Flag | Meaning |
|---|---|
| `-X a` | Runs jwt_tool's pre-built **exploit module "a"** — the alg:none attack. jwt_tool automatically rewrites the header to `alg: none`, strips the signature, and outputs the ready-to-submit forged token, rather than requiring you to manually edit and re-encode base64 segments by hand |

### 6.5 RS256-to-HS256 algorithm confusion (using a known public key)

```bash
python3 jwt_tool.py <token> -X k -pk public_key.pem
```

| Flag | Meaning |
|---|---|
| `-X k` | Runs exploit module **"k"** — the known-key / algorithm-confusion attack |
| `-pk public_key.pem` | Path to the server's **public key** file, which jwt_tool will treat as the raw bytes to HMAC-sign the forged HS256 token with |

### 6.6 jwk header self-signing injection attack

```bash
python3 jwt_tool.py <token> -X i -ju
```

| Flag | Meaning |
|---|---|
| `-X i` | Runs exploit module **"i"** — the **i**njection attack, which generates a fresh RSA keypair, embeds the public half in a `jwk` header parameter, and signs the token with the matching private key automatically |
| `-ju` | Tells jwt_tool to use the **jwk** embedding method specifically (as opposed to `-jw` for jku-style external hosting, which requires you to separately host the generated key set somewhere reachable by the target server) |

### 6.7 Scanning for common misconfigurations automatically

```bash
python3 jwt_tool.py <token> -M pb
```

| Flag | Meaning |
|---|---|
| `-M pb` | Runs **playbook mode**, which automatically runs a battery of jwt_tool's built-in checks (none algorithm, weak secrets from its bundled wordlist, common header injection variants) against the supplied token in one pass and reports which ones succeeded |

---

## 7. Real-World Workflow Summary For This File

The realistic order of operations on an engagement involving JWTs:

1. Decode the token first (no attack) — confirm algorithm, claims, and presence/absence
   of an `exp` (expiry) claim, since a token that never expires is itself a separate
   finding worth reporting regardless of crypto strength.
2. Check if `alg: none` is accepted — this is the fastest possible win and costs nothing
   to test.
3. Run a secret-cracking pass (jwt_tool `-C` or hashcat `-m 16500`) against a small
   curated wordlist of known default/example secrets before reaching for a large
   general-purpose wordlist — default secrets from tutorials and boilerplate code are
   disproportionately common in the wild.
4. Check for `jwk`/`jku`/`kid` parameters in the header — their mere presence is worth
   testing even if you don't yet know the backend's exact verification logic.
5. If the application exposes a JWKS endpoint, always test the algorithm confusion
   attack — it's a near-zero-cost test once the public key is in hand.
6. Report impact in terms of what the forged claim achieves (admin access, account
   takeover) — "JWT signature bypass" alone undersells the severity to a non-technical
   stakeholder reading the executive summary.

Continue to `04_TLS_Transport_Layer_Failures.md` for transport-layer cryptographic
failures and the testssl.sh deep-dive.
