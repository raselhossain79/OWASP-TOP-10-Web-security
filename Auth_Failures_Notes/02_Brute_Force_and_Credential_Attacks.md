# 02 — Brute Force and Credential Attacks

## 1. Concepts and Definitions

**Brute force** — systematically trying many password guesses against one
or a small set of known usernames, with no prior knowledge of which password
is correct.

**Credential stuffing** — using username/password pairs already known to be
valid from a previous, unrelated breach. This is not guessing; it relies on
password reuse across services and is far more effective per-attempt than
brute force because the credentials are already known-good somewhere.

**Username enumeration** — determining whether a given username exists on
the system at all, usually as reconnaissance before a brute-force or
credential-stuffing run, since attacking a confirmed-real account is far
more efficient than guessing usernames and passwords simultaneously.

**Weak password policy exploitation** — abusing the fact that a site allows
short, common, or pattern-based passwords (e.g., `Company2026!`,
`Welcome123`), which makes targeted dictionary attacks far more efficient
than pure brute force.

## 2. Real-World Framing

Verizon's annual Data Breach Investigations Report has, for years running,
listed stolen or weak credentials as one of the top initial access vectors
in confirmed breaches. The reason credential attacks remain so effective at
scale is economic, not technical: attackers don't need a clever exploit,
they need a list (from a breach dump or a generated wordlist) and a tool
that can fire requests fast enough to make trying that list worthwhile.
This is exactly why rate limiting and lockout (File 03) exist as a control
category — the attack itself is trivial to execute and trivial to describe;
the only thing standing between "trivial attack" and "compromised account"
is how well the target throttles repeated attempts.

In bug bounty and pentest reports, this category is usually written up
under "Insufficient Authentication Controls" or "Broken Brute-Force
Protection," and severity is almost always driven by what an attacker can
reach once one valid credential is found — a single compromised low-privilege
account is rarely the headline; what it unlocks (lateral movement, PII
access, financial functions) is.

## 3. Username Enumeration Techniques

These three techniques map directly to PortSwigger Academy labs 1, 4, and 5
(Apprentice → Practitioner progression), and in practice they're usually
tested in this exact order because each is a deeper level of the same idea:
the server is leaking whether a username exists, just through increasingly
subtle channels.

### 3.1 Enumeration via different responses (Lab 1)
The server returns an outright different error message for "user does not
exist" versus "user exists, wrong password" — e.g., `Invalid username` vs.
`Invalid password`. This is the crudest and easiest to spot; just submit a
clearly fake username and a clearly fake-but-plausible one and diff the
response bodies.

### 3.2 Enumeration via subtly different responses (Lab 4)
The error message text is identical, but something else differs — an extra
space, a different HTTP status code, a slightly different response length,
a different number of headers. This requires diffing raw responses
byte-for-byte rather than just reading the rendered error text, which is why
Burp's Intruder result grid (with the **Length** and **Status code**
columns sorted) is the standard tool for spotting it.

### 3.3 Enumeration via response timing (Lab 5)
If the backend only hashes/checks the password when the username is valid
(skipping that expensive operation entirely for invalid usernames), valid
usernames take measurably longer to respond. This is detected by sending
many requests per candidate username and comparing **average** response
time (a single sample is too noisy due to network jitter; PortSwigger's own
lab guidance recommends multiple requests per candidate and discarding
outliers).

### 3.4 Enumeration via account lock (Lab 7)
If lockout triggers only for valid accounts (e.g., the server tracks failed
attempts per real user object, so locking only happens when the username
exists), the lockout message itself becomes the enumeration oracle: submit
several wrong passwords for a candidate username, then check whether the
*next* response says "account locked" (username exists) or just "invalid
credentials" again (username doesn't exist, so no lockout counter to trip).

## 4. Burp Intruder — Full Technique Reference

Burp Intruder is the primary manual/semi-automated tool for all of the
above, and for credential attacks against modern web apps (JSON APIs, CSRF
tokens, custom headers) it's usually more practical than Hydra, which is
built around protocol modules rather than arbitrary HTTP.

### 4.1 Attack Types

| Attack type | Behavior | When to use |
|---|---|---|
| **Sniper** | One payload set, cycled through each marked position one at a time, all other positions held at their original value | Single-parameter fuzzing — e.g., just the username, or just the password, while the other stays fixed |
| **Battering ram** | One payload set, the *same* payload value inserted into **all** marked positions simultaneously | When the same value must appear in two places at once, e.g., a username repeated in both a form field and a custom header |
| **Pitchfork** | Multiple payload sets, one per position, all advancing in lockstep (request *n* uses item *n* from every list) | Testing **paired** credentials — e.g., a list of known username:password pairs from a breach dump, one list for usernames and a parallel list for passwords, same line number = same pair |
| **Cluster bomb** | Multiple payload sets, every combination of every list tested against every other (full cross-product) | Classic brute force where you don't have known pairs — e.g., 50 usernames × 200 passwords = 10,000 requests testing every combination |

For **credential stuffing** specifically: use **Pitchfork**, not Cluster
bomb, because credential-stuffing pairs are not interchangeable — you want
request *n* to test `breached_user[n]:breached_pass[n]`, not every user
against every password (which would just be a noisy, slow brute force using
stuffing data as if it were a wordlist).

### 4.2 Configuring an Attack — Flag-by-Flag Walkthrough

1. **Send to Intruder** — right-click the captured `POST /login` request in
   Proxy > HTTP history. This loads the raw request into the Intruder tab.
2. **Positions tab** — Burp auto-marks likely positions with `§...§`
   delimiters. Clear these (`Clear §`) and manually mark only the
   `username` and `password` parameter values. Marking too many positions
   (e.g., the CSRF token) will break the attack, since CSRF tokens are
   single-use and won't match between requests.
3. **Payload type: Simple list** — for a known wordlist (usernames or
   passwords pasted directly or loaded from file).
4. **Payload type: Runtime file** — for very large wordlists (millions of
   entries) where loading the whole list into memory as a Simple list would
   be wasteful; Intruder streams it from disk line by line instead.
5. **Resource Pool** (Intruder > Resource Pool, or a named pool under
   Project options > Resource Pool) — controls concurrent request threads
   and a maximum requests-per-second cap. This is the throttling control
   referenced in File 03 for staying under WAF/rate-limit thresholds.
6. **Grep — Match** (Options tab) — define a string to flag in the
   results grid as a new column (e.g., flag responses containing `Invalid
   username` vs. ones that don't, to make enumeration results scannable at
   a glance instead of opening every response).
7. **Grep — Extract** — pulls a specific substring out of each response
   into its own results column (e.g., extracting a reflected token or a
   session ID per attempt), useful when chaining brute force into a
   follow-on step.
8. **Start attack** — fires the configured attack. Sort the results grid by
   **Length**, **Status**, or **Response received** (timing) depending on
   which oracle (Section 3) is in play for the target.

### 4.3 Why Burp Intruder Over Hydra for Web Apps

Hydra's HTTP modules assume a relatively simple, static form structure.
Burp Intruder operates on the literal captured request, so it transparently
handles JSON bodies, multi-step CSRF-token-bound forms (when combined with
Burp's session handling rules to auto-refresh tokens between requests), and
custom headers — all common in modern apps and rare in Hydra's intended use
case (classic protocol/form auth).

## 5. Hydra — Full Usage Reference

Hydra remains the standard tool for brute-forcing **network service**
authentication (SSH, FTP, RDP, SMB) and for simple HTTP/HTTPS form logins
that don't require dynamic per-request tokens. It is the natural complement
to Burp Intruder: use Hydra when the target is a non-HTTP service or a
trivial static login form, use Burp Intruder when CSRF tokens, JSON, or
multi-step flows are involved.

### 5.1 Core Syntax

```
hydra -l <user> -P <passlist> <target> <service> [service-specific-options]
```

| Flag | Meaning | Notes |
|---|---|---|
| `-l <user>` | Single, fixed username (lowercase L) | Use when only one username is being tested |
| `-L <userlist>` | File of candidate usernames (uppercase) | Combine with `-P` for a username × password cross-product, identical concept to Burp's Cluster bomb |
| `-p <password>` | Single, fixed password (lowercase P) | Rare — usually you want a list, not a single guess |
| `-P <passlist>` | File of candidate passwords (uppercase) | Standard for dictionary attacks |
| `-e nsr` | Try empty password (`n`), password = username (`s`), reversed username (`r`) as extra automatic guesses | Cheap wins against weak policies before burning through the real wordlist |
| `-t <n>` | Number of parallel connection threads | Default is usually 16; higher = faster but more likely to trip rate limiting or crash a fragile service — directly relevant to File 03's throttling guidance |
| `-T <n>` | (Some builds) explicit task count, same concept as `-t` | Tool-version dependent; check `hydra -h` on your build |
| `-f` | Stop as soon as the **first** valid credential pair is found, for the *whole run* | Use when you only need to prove one set of valid creds exists, not enumerate all of them |
| `-F` | Stop only for the **current** username once it's cracked, but keep going for other usernames in `-L` | Use when testing many accounts and you want one hit per account, not just one hit total |
| `-V` | Verbose — show every attempt as it happens | Useful for debugging why an attack isn't matching correctly |
| `-vV` | Very verbose | Even more detail, including failed attempt bodies — heavy log volume |
| `-o <file>` | Write found credentials to a file | Persists results past the terminal session |
| `-s <port>` | Override the default port for the service module | Needed when the target runs the service on a non-standard port |
| `-I` | Ignore an existing restore file and start fresh | Hydra checkpoints progress; use this to force a clean restart |
| `-R` | Resume from a previous interrupted session | Reads the restore file Hydra writes automatically |

### 5.2 SSH Module Example

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.5 -t 4 -V
```

Breakdown:
- `-l admin` — fixed username `admin`, no username guessing in this run.
- `-P /usr/share/wordlists/rockyou.txt` — the password list to try, one
  password per line.
- `ssh://10.10.10.5` — target service and host; the `ssh://` scheme tells
  Hydra to load its SSH module.
- `-t 4` — only 4 parallel connections. SSH daemons commonly rate-limit or
  temporarily ban IPs after a handful of rapid failed logins
  (`MaxAuthTries`, `fail2ban`), so a low thread count here is deliberate,
  not a performance compromise — going faster usually just gets you banned
  faster with zero extra successful guesses.
- `-V` — show each attempt so you can confirm the tool is actually
  connecting and not silently failing due to a network issue.

### 5.3 HTTP POST Form Module — Full Breakdown

This is the module relevant to classic, non-dynamic web login forms:

```
hydra -L users.txt -P passwords.txt 10.10.10.5 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -t 10 -o found.txt
```

Breakdown of the `http-post-form` argument string, which is itself a single
colon-separated string with **three** required fields:

1. **Path field** — `/login`: the URL path the POST request is sent to.
2. **Body field** — `username=^USER^&password=^PASS^`: the literal POST
   body template. `^USER^` and `^PASS^` are placeholder tokens Hydra
   substitutes with each candidate from `-L`/`-P` on every request — this
   must exactly match the real form's field names, captured from a browser
   or Burp first.
3. **Failure condition field** — `Invalid credentials`: a string Hydra
   searches for in the response. If this string **is present**, Hydra
   treats the attempt as a **failure**. Getting this string wrong (e.g.,
   matching on something that appears on both success and failure pages,
   like a shared footer) is the single most common reason Hydra reports
   zero hits even when a valid password is in the list — it's a tooling
   misconfiguration, not proof the credentials don't exist.
   - Optionally prefix this field with `F=` to be explicit about it being a
     failure string, or use `S=` instead to match on a **success** string
     (present only on a successful login, e.g., `S=Location: /dashboard`)
     — `S=` is often more reliable than `F=` because success pages tend to
     be more uniquely identifiable than generic error text.

Remaining flags:
- `10.10.10.5` — target host (HTTP module infers port 80/443 unless told
  otherwise with `-s`).
- `-t 10` — 10 parallel threads.
- `-o found.txt` — save any hits to disk.

For HTTPS targets, use `https-post-form` in place of `http-post-form` —
same syntax, TLS handled automatically.

### 5.4 HTTP GET Form Module

For logins or sensitive actions submitted via GET (less common, but seen in
legacy apps and some admin panels):

```
hydra -l admin -P passwords.txt 10.10.10.5 http-get-form \
  "/login.php?user=^USER^&pass=^PASS^:Login failed"
```

Same three-field structure as `http-post-form`, but the credentials are
placed directly in the query string of the path field rather than in a
separate POST body field — note there are only **two** colon-delimited
fields here (path+query combined, then failure condition), since there's no
separate body.

### 5.5 FTP Module Example

```
hydra -L users.txt -P passwords.txt ftp://10.10.10.5 -t 6
```

- `ftp://10.10.10.5` — selects the FTP module.
- Otherwise identical structure to the SSH example; FTP servers vary widely
  in whether they implement any lockout at all, so threading is less
  dangerous here than against SSH, but still worth keeping moderate to
  avoid triggering IDS/IPS alerting on the wire.

### 5.6 Practical Failure Modes to Know

- **Wrong success/failure string** → false negatives (real credentials
  reported as wrong). Always verify the string by performing one manual
  login and one manual failed login first, and diff the raw responses.
- **CSRF-protected forms** → Hydra's basic HTTP modules don't fetch a fresh
  token per request by default; against CSRF-protected logins, Burp
  Intruder with session-handling rules (Section 4) is the correct tool
  instead.
- **Account lockout triggering mid-run** → once an account locks, every
  subsequent attempt for that username will "fail" regardless of password
  correctness, silently wasting the rest of that username's password list.
  Pair Hydra runs with monitoring of File 03's lockout-detection signals so
  you know to stop and pivot rather than keep burning requests against a
  dead account.

## 6. Weak Password Policy Exploitation

When recon (e.g., a company's public breach history, or simply observing
the password policy text on the registration page) reveals weak complexity
requirements, prioritize:

- **Seasonal/pattern passwords**: `CompanyName2026!`, `Welcome1`, `Spring2026`
- **Keyboard-walk patterns**: `Qwerty123!`, `1qaz2wsx`
- **Industry-specific terms** combined with a year and symbol, especially
  for service accounts and admin panels created by IT staff under time
  pressure during setup.

This is why the Academy's own "Securing your authentication mechanisms"
guidance specifically recommends real-time password strength checkers (e.g.,
the `zxcvbn` library) over static complexity rules — static rules (length,
one uppercase, one digit, one symbol) are trivially satisfied by exactly the
predictable patterns above, while a strength-scoring approach actually
penalizes them.

## 7. Offline Password Cracking (Lab 10)

Distinct from online brute force: if a vulnerability elsewhere (e.g.,
information disclosure, a backup file, an exposed database dump) yields
password **hashes** rather than plaintext, the attack moves offline using
`hashcat` or `john`. Full hashcat/John usage is documented separately in
this repository's dedicated Hashcat and John the Ripper notes; the relevant
point for A07 classification purposes is that the *root cause* enabling
offline cracking is almost always a separate failure (excessive information
disclosure, weak hashing algorithm choice — itself an A02 Cryptographic
Failures issue) that exposes credential material in the first place. A07
and A02 frequently chain together in real findings for exactly this reason.

## 8. Password Brute-Force via Password Change (Lab 12)

A distinct bypass of normal login-rate-limiting: if the "change password"
endpoint requires the **current** password as a field, but doesn't apply
the same lockout/rate-limit policy that the login form does, an attacker
with a valid session (e.g., from a low-privilege account they already
control, or a stolen session token) can brute-force a *different* user's
current password through this endpoint instead of the login form,
sidestepping the login form's defenses entirely. This is a clean example of
why every authentication-adjacent endpoint needs its own threat-modeling
pass — securing the login form alone is not sufficient.
