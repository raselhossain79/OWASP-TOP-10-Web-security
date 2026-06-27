# 06 — Multi-Factor Authentication (MFA) Bypass

## 1. Real-World Framing

As MFA adoption has grown — driven by both compliance requirements and the
sheer scale of credential-stuffing attacks documented in File 02 —
attackers have correspondingly shifted focus away from trying to defeat the
underlying cryptography of MFA (which is generally sound) and toward
attacking the **implementation logic** that wires the second factor into
the rest of the login flow. This is a consistent theme across all three
Academy labs in this file: every one of them is a flow/logic bug, not a
cryptographic break of the second factor itself. This mirrors a broader,
well-documented industry trend (heavily reported in the context of
large-scale phishing/MFA-fatigue campaigns and SIM-swap-adjacent attacks
against SMS-based codes) where the second factor itself is sound, but the
*process* around it has gaps.

## 2. 2FA Simple Bypass (Lab 2)

### 2.1 The Vulnerability

The most basic version of this flaw: after submitting a correct
username/password, the application redirects the user to a 2FA
verification page — but the **session is already partially or fully
privileged** at that point, and the 2FA page is enforced only by the
client-side flow (i.e., by which page the browser happens to be sent to),
not by a server-side check on every subsequent privileged request.

### 2.2 How to Test

1. Log in normally with valid credentials up to the point the 2FA prompt
   appears.
2. Instead of submitting a 2FA code, manually navigate directly to a
   known authenticated URL (e.g., `/my-account`) that should only be
   reachable post-2FA.
3. If the application serves that page anyway, the second factor is
   advisory only — purely a UI-level gate the attacker can walk around by
   simply not following the link the application expects them to follow.

### 2.3 Real-World Note

This exact pattern is common in applications that bolt 2FA onto an
existing authentication system as an afterthought: the original
single-factor login already sets a fully authenticated session cookie at
the password step, and the 2FA page is added in front of it as a new
**UI** step without re-architecting the backend to track a distinct
"password verified, 2FA pending" intermediate state.

## 3. 2FA Broken Logic (Lab 8)

### 3.1 The Vulnerability

A step up in subtlety from Lab 2: the server **does** correctly track an
intermediate "awaiting 2FA" session state, but the verification step itself
contains a logic flaw — most commonly, the 2FA endpoint identifies *which
account's* code to check using a value that the client controls and can
tamper with (e.g., a hidden `username` field resubmitted alongside the 2FA
code), rather than strictly using the identity already bound to the
in-progress session from the password step.

### 3.2 How to Test

1. Log in as your own low-privilege test account up to the 2FA prompt.
2. Inspect the 2FA verification request for any parameter identifying the
   account (`username`, `account`, `userId`), separate from the 2FA code
   field itself.
3. Submit your **own valid 2FA code** but change that identity parameter to
   point at a different (target) account.
4. If the server accepts this — effectively checking "is this a valid 2FA
   code for *some* session" rather than "is this the correct 2FA code for
   *this specific* victim's pending login" — the attacker can complete
   login as the victim using only their own correctly-functioning 2FA
   device, with no knowledge of the victim's actual code.

### 3.3 Why This Pattern Recurs

This is structurally the same root-cause class as the password-reset
identity-binding flaw in File 05 (Section 2.1): a multi-step flow where a
later step trusts a client-supplied identity parameter instead of strictly
deriving identity from server-side session state established earlier in the
flow. Recognizing this as one repeating architectural anti-pattern — rather
than three unrelated bugs in three different files — is a useful framing
when reviewing any multi-step authentication-adjacent flow from scratch.

## 4. 2FA Bypass Using a Brute-Force Attack (Lab 14)

### 4.1 The Vulnerability

If the 2FA verification endpoint does not apply its **own** independent
rate limiting/lockout (distinct from whatever protects the primary login
form), and the code itself is short (commonly a 4–6 digit numeric OTP), the
second factor can simply be brute-forced directly:

- A 4-digit numeric code has only 10,000 possible values.
- A 6-digit numeric code has 1,000,000 — larger, but still entirely
  feasible to brute-force online within a typical code validity window
  (often 5–30 minutes) if there is no attempt limiting and the application
  can sustain a moderate request rate.

### 4.2 How to Test

This combines directly with the Burp Intruder methodology from File 02:

1. Get to the 2FA entry step using valid credentials for a test account
   (this lab — and most real instances of this bug class — assumes the
   attacker already has a valid username/password, since 2FA is, by
   definition, the *second* factor sitting after that first one).
2. Send the 2FA verification request to Intruder.
3. Mark the code field as the payload position.
4. Use a **Numbers** payload type configured to generate every value across
   the code's full range (e.g., `0000`–`9999` for a 4-digit code, with
   leading zeros preserved — check the "min/max integer digits" setting in
   the payload options so `7` doesn't get sent as `7` instead of `0007`).
5. Check whether the session remains in the "awaiting 2FA" state across all
   attempts (no separate lockout on this specific step), and whether the
   attack completes within the code's validity window.

### 4.3 Why This Specifically Needs Its Own Rate Limiting

This lab is a direct, concrete illustration of why "the login form has rate
limiting" is an insufficient security claim on its own — every distinct
verification step in a multi-step authentication flow is its own attack
surface and needs its own independently-enforced throttling. A team that
hardened the login form against File 02/03-style attacks but treated 2FA
verification as a "fast path" with no separate controls has not actually
raised the bar much, since the 2FA code, on its own, is frequently the
weaker secret (fewer possible values, shorter validity window) compared to
a well-chosen password.

## 5. Additional Real-World MFA Bypass Patterns (Beyond the Three Labs)

These are not covered by a current Academy lab but are standard checks in
real engagements and frequently reported in bug bounty programs:

- **"Remember this device" / trusted-device cookie abuse**: if a device
  marked as "trusted" after a successful 2FA skips the second factor on
  future logins, test whether that trust token is bound tightly enough to
  the original device (and not just guessable/replayable from a different
  browser or machine) — this connects directly to the token-entropy
  methodology in File 04, Section 3.
- **Backup/recovery code abuse**: many MFA implementations issue a set of
  one-time backup codes for when the primary factor (phone, authenticator
  app) is unavailable. Test whether these have the same rate limiting as
  the primary 2FA code, and whether they are properly invalidated (single
  use) rather than reusable.
- **Downgrade via password-reset flow**: a frequently-seen real-world
  pattern (not Academy-covered) where the password reset flow itself does
  not require completing 2FA after setting a new password — letting an
  attacker who has compromised only the email account (not the MFA device)
  reset the password and then log in, having functionally downgraded a
  2FA-protected account back to single-factor by routing around the front
  door entirely. This is the clearest practical reason File 05 (password
  reset) and this file should always be reviewed together, never in
  isolation from each other.
- **OAuth/SSO bridge bypassing local MFA**: if an account can be accessed
  both via local password+2FA login **and** via a linked OAuth/social
  login, confirm that the OAuth path doesn't grant equivalent access
  without ever satisfying the local MFA requirement — this overlaps with
  this repository's separate OAuth/JWT-focused notes where relevant.
