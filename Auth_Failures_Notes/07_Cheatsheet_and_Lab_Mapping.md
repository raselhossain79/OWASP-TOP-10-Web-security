# 07 — Cheatsheet and Full Lab Mapping

## 1. Master Testing Checklist

A condensed, engagement-ready version of the methodology spread across
Files 01–06. Use this as the working checklist; refer back to the
individual files for full technique depth.

### Credential attacks (File 02)
- [ ] Test all three username-enumeration oracles: different responses,
      subtly different responses, response timing.
- [ ] Test account-lock-based enumeration separately from the three above.
- [ ] Identify password policy weaknesses from registration/change-password
      UI; build a targeted pattern-based wordlist before brute-forcing
      blindly.
- [ ] Run credential-stuffing test (Pitchfork in Intruder, or Hydra with
      paired lists) using realistic breach-pattern data if in scope.
- [ ] Test the password-change endpoint for brute-forceability independent
      of the login form's own protections.

### Rate-limit / lockout bypass (File 03)
- [ ] Characterize the real lockout/rate-limit trigger (status code,
      message, headers, timing) before attempting bypass.
- [ ] Test `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`
      header spoofing against the rate limiter.
- [ ] Test whether the rate limit is per-IP only (vulnerable to password
      spraying across many accounts) vs. per-account only (vulnerable to
      credential stuffing from one source).
- [ ] Test array/batch parameter injection on JSON login endpoints
      (multiple credentials per request).
- [ ] If header spoofing fails, confirm whether real distributed
      infrastructure is in scope before attempting it.

### Session management (File 04)
- [ ] Compare session cookie value before and after login — flag if
      unchanged (fixation).
- [ ] Check whether the app accepts session IDs via URL parameters.
- [ ] Run Burp Sequencer against session/reset/persistent-login tokens;
      review effective entropy estimate, not just visual randomness.
- [ ] Check `HttpOnly`, `Secure`, `SameSite` cookie attributes.
- [ ] Confirm server-side session invalidation on logout, not just
      client-side cookie clearing.

### Password reset (File 05)
- [ ] Map every identity-carrying parameter across the full reset flow.
- [ ] Test cross-account parameter tampering at the final reset step.
- [ ] Test token reuse and expiry independently.
- [ ] Test `Host` and `X-Forwarded-Host` header manipulation on the
      reset-request step; verify against the actual emailed link.
- [ ] Check `Referrer-Policy` on the reset confirmation page.
- [ ] Confirm "change password while logged in" requires the current
      password.

### MFA (File 06)
- [ ] Attempt direct navigation past the 2FA prompt after password-only
      login.
- [ ] Test identity-parameter tampering on the 2FA verification request.
- [ ] Brute-force the 2FA code directly if no dedicated rate limiting
      exists on that endpoint.
- [ ] Test "remember this device" token strength and binding.
- [ ] Test backup/recovery code rate limiting and single-use enforcement.
- [ ] Confirm password reset cannot be used to downgrade/bypass MFA.

## 2. Quick Tool Reference

### Hydra
```
hydra -l <user> -P <wordlist> <target> http-post-form \
  "/path:param1=^USER^&param2=^PASS^:FailureString" -t <threads> -o out.txt
```
- `-l/-L` username(s), `-p/-P` password(s) — lowercase = single value,
  uppercase = list file.
- `http-post-form` argument = `path:body_template:failure_or_S=success_string`.
- `-t` thread count — keep low against services with real lockout.
- `-f`/`-F` stop conditions; `-o` save results.

### Burp Intruder attack types
- **Sniper** — one list, one position at a time.
- **Battering ram** — one list, same value into all positions at once.
- **Pitchfork** — multiple lists, lockstep (paired credentials).
- **Cluster bomb** — multiple lists, full cross-product (classic brute force).

### Burp Sequencer
- Send token-issuing request/response to Sequencer → Live capture or
  manual load → gather large sample → review character-level, bit-level,
  and effective entropy analysis.

## 3. Full PortSwigger Authentication Lab Mapping (Official Academy Order)

| Order | Lab Name | Difficulty | Sub-topic | File | Core Concept |
|---|---|---|---|---|---|
| 1 | Username enumeration via different responses | Apprentice | Password-based | 02 | Distinct error text reveals valid usernames |
| 2 | 2FA simple bypass | Apprentice | Multi-factor | 06 | Direct navigation skips 2FA enforcement |
| 3 | Password reset broken logic | Apprentice | Other mechanisms | 05 | Identity-binding gap in reset flow |
| 4 | Username enumeration via subtly different responses | Practitioner | Password-based | 02 | Byte-level response diffing reveals usernames |
| 5 | Username enumeration via response timing | Practitioner | Password-based | 02 | Timing side-channel reveals usernames |
| 6 | Broken brute-force protection, IP block | Practitioner | Password-based | 03 | X-Forwarded-For spoofing bypasses IP-based block |
| 7 | Username enumeration via account lock | Practitioner | Password-based | 02 | Lockout-trigger itself becomes the oracle |
| 8 | 2FA broken logic | Practitioner | Multi-factor | 06 | Client-controlled identity parameter at 2FA step |
| 9 | Brute-forcing a stay-logged-in cookie | Practitioner | Other mechanisms | 04 | Predictable persistent-login token construction |
| 10 | Offline password cracking | Practitioner | Password-based | 02 | Disclosed hash cracked offline (chains with A02) |
| 11 | Password reset poisoning via middleware | Practitioner | Other mechanisms | 05 | Host/X-Forwarded-Host header poisons reset link |
| 12 | Password brute-force via password change | Practitioner | Password-based | 02 | Password-change endpoint lacks login-form protections |
| 13 | Broken brute-force protection, multiple credentials per request | Expert | Password-based | 03 | Array-wrapped credentials bypass per-request rate counting |
| 14 | 2FA bypass using a brute-force attack | Expert | Multi-factor | 06 | Short OTP brute-forced due to missing 2FA-step rate limit |

**Gaps acknowledged honestly:** no Academy lab currently exists for classic
session fixation or raw session-token entropy analysis as standalone
exercises — both are covered in File 04 using real-world methodology and
tooling (Burp Sequencer) rather than a fabricated lab reference.

## 4. Report-Writing Language Templates

For translating findings from this series into pentest/bug-bounty report
language:

- **Username enumeration**: "The application discloses whether a submitted
  username corresponds to a valid account through [differing error
  messages / response length / response timing / lockout behavior],
  allowing an attacker to build a list of valid accounts prior to a
  credential-stuffing or password-spraying attack."
- **Broken brute-force protection**: "The application's rate-limiting
  control for the login endpoint can be bypassed by [spoofing the
  X-Forwarded-For header / submitting credentials as an array within a
  single request], allowing an effectively unlimited number of password
  guesses against a target account."
- **Session fixation**: "The application does not regenerate the session
  identifier upon successful authentication, allowing an attacker who can
  fix a victim's pre-authentication session ID to gain access to the
  resulting authenticated session."
- **Password reset poisoning**: "The application constructs password reset
  links using an attacker-controllable [Host / X-Forwarded-Host] header
  without validation, allowing an attacker to redirect a legitimate reset
  token to an attacker-controlled domain and capture it for account
  takeover."
- **2FA logic bypass**: "The application's two-factor verification step
  [does not enforce server-side state after password verification / trusts
  a client-supplied identity parameter independent of the authenticated
  session], allowing an attacker to [skip the second factor entirely /
  complete the second factor for an arbitrary victim account using their
  own valid code]."

Severity in all of the above should be framed around **what the attacker
gains downstream** of the authentication bypass (account takeover scope,
data accessible, privileged functions reachable) rather than the mechanics
of the bypass alone — this is consistent with how both PortSwigger's own
guidance and major bug bounty triage teams typically calibrate severity for
this category.
