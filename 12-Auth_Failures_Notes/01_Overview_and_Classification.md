# 01 — Overview and Classification: A07:2021 Identification and Authentication Failures

## 1. Definition

A07:2021 covers any failure that allows an attacker to compromise the
identity verification process of an application — either by impersonating a
legitimate user, hijacking an active session, defeating a second
authentication factor, or abusing supplementary identity flows such as
password reset. It absorbed and expanded the old A2:2017 "Broken
Authentication" category, and now explicitly folds in session management
failures that used to be treated as a separate concern.

The core idea: authentication is not just the login form. It is the login
form, the session that follows it, the second factor that supposedly
strengthens it, and the recovery flow that exists in case it fails. A
weakness in any one of these breaks the whole chain.

## 2. CWE Mapping

| CWE | Title | Where it shows up in this series |
|---|---|---|
| CWE-287 | Improper Authentication | General login logic flaws |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | File 02, 03 |
| CWE-384 | Session Fixation | File 04 |
| CWE-613 | Insufficient Session Expiration | File 04 |
| CWE-330 | Use of Insufficiently Random Values | File 04 (token entropy) |
| CWE-640 | Weak Password Recovery Mechanism | File 05 |
| CWE-620 | Unverified Password Change | File 02 (password-change brute force) |
| CWE-798 | Use of Hard-coded Credentials | File 02 (default creds) |
| CWE-308 | Use of Single-factor Authentication | File 06 |
| CWE-303 | Incorrect Implementation of Authentication Algorithm | File 06 (2FA logic flaws) |
| CWE-521 | Weak Password Requirements | File 02 |

## 3. Failure Taxonomy Used in This Series

This series splits A07 into six practical attack surfaces, each given its own
file so the methodology and tooling for each stays self-contained:

1. **Credential attacks** — brute force, credential stuffing, weak password
   policy exploitation, username enumeration.
2. **Defense evasion** — bypassing the rate limiting and account lockout
   controls that are supposed to stop #1 from working.
3. **Session management flaws** — fixation, predictable/low-entropy tokens,
   improper session termination.
4. **Password reset flaws** — broken reset logic, poisoned reset links,
   token leakage.
5. **MFA bypass** — logic flaws that let an attacker skip, reuse, or
   brute-force a second factor.
6. **Tooling** — Hydra and Burp Intruder, documented once at the depth
   needed to support every technique above (in File 02), rather than
   repeated shallowly in each file.

## 4. Real-World Framing

Authentication failures remain one of the most consistently exploited
categories in actual breaches because, unlike many injection bugs, they
don't require finding an obscure parsing flaw — they exploit business logic
and operational gaps that exist by default unless someone specifically
closes them:

- **Credential stuffing** is now treated as its own threat category by major
  CDN/WAF vendors (Cloudflare, Akamai, Imperva all ship dedicated credential
  stuffing protection products) because billions of breached
  username/password pairs are continuously reused against unrelated sites.
- **Password reset abuse** is one of the most common account-takeover
  vectors reported in bug bounty programs (HackerOne and Bugcrowd both have
  large public categories of P1/P2 reports under "broken authentication" and
  "improper access control" that trace back to reset-flow logic).
- **Session fixation** is rarer in modern frameworks that regenerate session
  IDs on privilege change by default (Django, Rails, most modern PHP
  frameworks), but it reappears constantly in legacy and custom-built
  authentication layers, especially in regulated industries (banking,
  insurance, government portals) where legacy code persists longest.
- **MFA bypass** has grown in importance precisely because MFA adoption has
  grown — attackers now specifically target the *implementation* of the
  second factor (rate limiting on OTP entry, logic order, "remember this
  device" cookies) rather than trying to defeat the cryptography behind it.

## 5. Testing Methodology Checklist

Before diving into the technique files, a tester should walk through this
checklist against the target's authentication surface:

- [ ] Identify every distinct authentication entry point (web login, mobile
      API login, SSO/OAuth bridge, password change, password reset, MFA
      enrollment, MFA verification, "remember me" / stay-logged-in cookie).
- [ ] For each entry point, determine the response signal set (status code,
      response length, response time, error message wording, redirect
      target) under valid vs. invalid input.
- [ ] Test whether username existence can be inferred from any of those
      signals (enumeration).
- [ ] Test whether the same account can be attacked beyond the apparent rate
      limit using a different vector (IP rotation, header spoofing, multiple
      credentials in one request, password-change endpoint instead of
      login endpoint).
- [ ] Capture and statistically evaluate any session, reset, or "remember
      me" token for predictability.
- [ ] Walk the password reset flow end-to-end, capturing every request, and
      check token binding, expiry, and reuse behavior.
- [ ] If MFA is present, test whether it can be skipped by manipulating
      flow order, response codes, or by brute-forcing the code itself.

## 6. PortSwigger Web Security Academy — Authentication Topic, Full Lab List

The Authentication topic on the Academy contains 14 labs across three
sub-topics: **Password-based login**, **Multi-factor authentication**, and
**Other authentication mechanisms**. The table below lists them in the exact
order they appear on the Academy (this is the order used throughout this
series for lab references — never grouped by theme):

| # | Lab | Difficulty | Sub-topic | Covered in |
|---|---|---|---|---|
| 1 | Username enumeration via different responses | Apprentice | Password-based | File 02 |
| 2 | 2FA simple bypass | Apprentice | Multi-factor | File 06 |
| 3 | Password reset broken logic | Apprentice | Other mechanisms | File 05 |
| 4 | Username enumeration via subtly different responses | Practitioner | Password-based | File 02 |
| 5 | Username enumeration via response timing | Practitioner | Password-based | File 02 |
| 6 | Broken brute-force protection, IP block | Practitioner | Password-based | File 03 |
| 7 | Username enumeration via account lock | Practitioner | Password-based | File 02 |
| 8 | 2FA broken logic | Practitioner | Multi-factor | File 06 |
| 9 | Brute-forcing a stay-logged-in cookie | Practitioner | Other mechanisms | File 04 |
| 10 | Offline password cracking | Practitioner | Password-based | File 02 |
| 11 | Password reset poisoning via middleware | Practitioner | Other mechanisms | File 05 |
| 12 | Password brute-force via password change | Practitioner | Password-based | File 02 |
| 13 | Broken brute-force protection, multiple credentials per request | Expert | Password-based | File 03 |
| 14 | 2FA bypass using a brute-force attack | Expert | Multi-factor | File 06 |

**Honest note on coverage gaps:** the Academy's Authentication topic does
not currently include a dedicated lab for classic session fixation or for
raw session-token entropy analysis as standalone exercises. File 04 covers
both techniques using real-world methodology and the closest genuinely
related lab (#9, stay-logged-in cookie brute-forcing), and says so directly
rather than inventing a mapping that doesn't exist.
