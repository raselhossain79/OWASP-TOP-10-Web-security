# Case Studies — Real-World Insecure Design Scenarios

These scenarios are written the way you'll actually encounter insecure design in a real engagement — not as a clean, single-purpose lab, but woven into ordinary-looking functionality. Each one follows the same structure: **Scenario → Request Sequence → Step-by-Step Exploitation → Why It Works → Real-World Industry Note.**

---

## Case Study 1: Password Reset Token Not Bound to the Username (Password Reset Poisoning / Broken Reset Logic)

**Scenario:** A SaaS platform's "Forgot password" flow emails a reset link containing a token. The reset-confirmation request submits the token *and* a username field separately, rather than the server looking up "which account does this token belong to" purely from the token itself.

**Request sequence:**
```
Step 1 — Request a reset for your own account:
POST /forgot-password
username=attacker

Step 2 — Server emails a reset link to attacker's inbox:
GET /reset-password?token=a1b2c3d4...

Step 3 — Submit the new password:
POST /reset-password
token=a1b2c3d4...&username=attacker&new-password=Passw0rd!
```

**Step-by-step exploitation:**
1. Request a password reset for your own attacker-controlled account and retrieve the valid token delivered to your inbox.
2. Submit the reset-confirmation request, but **swap the `username` parameter to the victim's username while keeping your own valid token**.
3. Observe whether the server resets the password for whichever username is in the parameter, or whether it independently verifies the token actually belongs to that username.
4. If the server only checks "is this token valid and unexpired" without checking "does this token belong to *this* username," the victim's password is now reset to a value you chose.

**Why it works:** The design treats the token and the username as two independent, separately-trusted inputs, when the entire security property of the reset flow depends on them being **cryptographically bound together** — the token should encode, or be looked up by, the account it was issued for, full stop. No amount of "the token is long and random" matters if the server never checks whose token it is.

**Real-world industry note:** This exact class of bug ("password reset poisoning") has been reported and paid out repeatedly in bug bounty programs, frequently in self-built authentication systems rather than vetted identity providers — another reason mature orgs increasingly outsource auth to platforms like Auth0/Okta/Cognito rather than rolling their own reset logic. When you encounter a custom-built reset flow during an engagement, treat the token-to-identity binding as priority #1 to test.

---

## Case Study 2: 2FA Verification Step That Doesn't Verify Who It's Generating a Code For

**Scenario:** A banking-style web app uses two-step login: username/password, then a one-time code sent to the registered device. The OTP-generation request and the OTP-verification request both reference the target account by a parameter the client controls.

**Request sequence:**
```
Step 1 — Normal login (your own account):
POST /login
username=attacker&password=correcthorse

Step 2 — OTP generated for whichever account is named here:
POST /login2
verify=attacker

Step 3 — Submit the OTP code:
POST /login2
verify=attacker&mfa-code=1234
```

**Step-by-step exploitation:**
1. Log in normally as yourself to observe the OTP request format. Note that `verify=attacker` in step 2 names the account to generate a code *for* — and this parameter is attacker-controlled, not derived from the already-authenticated session.
2. Change `verify=attacker` to `verify=victim`. The server dutifully generates and sends an OTP to the victim's registered device — but the *response on your screen* still presents the OTP-entry form, now in the context of the victim's account.
3. Capture the OTP-submission request in Burp Repeater. Since the OTP is commonly a short numeric code (e.g., 4 digits = 10,000 possibilities), send it to Burp Intruder with `verify=victim` fixed and `mfa-code` as the brute-force position.
4. Run the attack. With no server-side lockout after failed OTP attempts, you will land on the correct code well within a few thousand requests.

**Why it works:** Two separate design failures stack here: (1) the account-to-verify is taken from a client-controlled parameter instead of the server-side session established in step 1, and (2) there's no rate limiting or lockout on OTP attempts — a *missing control by design*, not a misconfigured one, because nobody anticipated this endpoint being brute-forceable in isolation from the password check.

**Real-world industry note:** This pattern shows up frequently in mobile-app-to-web-API backends where the API was built to be "stateless" and ended up trusting client-supplied identifiers at every step instead of a single server-side session anchor. It's a textbook trust-boundary violation: the server should never let the *second factor's target identity* be something the client gets to name after the first factor already established who they are.

---

## Case Study 3: Discount Stacking via Workflow-State Manipulation (Domain-Specific Logic Flaw)

**Scenario:** An e-commerce checkout offers a single-use referral discount code and a separate first-purchase discount code. Both are individually capped at one use per account — but the cart-recalculation logic re-evaluates discounts independently at each step rather than as a locked total once applied.

**Request sequence:**
```
POST /cart/coupon       coupon=REFER10
POST /cart/coupon       coupon=FIRSTBUY15   (rejected: REFER10 already active this session)
POST /cart/remove       couponId=REFER10
POST /cart/coupon       coupon=FIRSTBUY15
POST /cart/coupon       coupon=REFER10      (accepted again — session no longer has "REFER10 active" flag)
```

**Step-by-step exploitation:**
1. Apply the first coupon. The server flags "a coupon is active" at the session level, which blocks applying a *second different* coupon while one is active — a sensible-looking control.
2. Remove the first coupon via the cart's normal "remove coupon" function. This clears the "a coupon is active" session flag.
3. Apply the second coupon. It succeeds, and a new gift-card/credit balance or discount is generated as the legitimate single-use reward for that coupon.
4. Re-apply the **first** coupon again. Because the active-coupon flag was cleared when you removed it in step 2, the server treats this as a "fresh" coupon application, not a reapplication, even though it's the same account and the same coupon code.
5. Loop this remove/reapply cycle to accumulate discount/credit far beyond the "one coupon per account" rule the design intended.

**Why it works:** The single-use restriction was implemented as **session-flag state** ("is a coupon active right now") rather than as a **persistent, append-only ledger** of which coupons this account has redeemed historically. Removing and reapplying resets transient state without resetting the underlying entitlement — the design conflated "currently applied" with "ever redeemed."

**Real-world industry note:** Discount/coupon abuse is one of the highest-frequency, highest-payout bug classes in e-commerce bug bounty programs precisely because discount logic is usually built fast, under product-team time pressure, with security review treated as secondary to "does the discount apply correctly in the happy path." Treat every promo/loyalty/referral system you encounter as a high-probability target for this category.

---

## Case Study 4: Design-Level Race Condition in a "Redeem Once" Action (Time-of-Check / Time-of-Use Flaw)

**Scenario:** A platform allows users to redeem a single welcome bonus into their account balance. The redemption endpoint checks "has this user already redeemed?" and, if not, credits the balance and marks the bonus as redeemed — but these are two separate steps rather than one atomic database operation.

**Request sequence (sent concurrently, not sequentially):**
```
POST /account/redeem-bonus   (fired 20–30 times simultaneously)
```

**Step-by-step exploitation:**
1. Identify that the redeem endpoint follows a "check-then-act" pattern: `SELECT redeemed FROM users WHERE id=?` followed later by `UPDATE users SET balance = balance + 50, redeemed = true WHERE id=?`.
2. Using Burp's "Send group in parallel" (Repeater) or a scripted concurrent request tool, fire the same `POST /account/redeem-bonus` request 20–30 times at once, all authenticated as the same account, all dispatched in as tight a time window as possible (ideally within the same network round-trip so they arrive at the server within microseconds of each other).
3. Because every one of those concurrent requests performs its "have I redeemed yet?" check *before* any of the earlier requests has finished writing the "redeemed = true" update, multiple requests read "not yet redeemed" and proceed to credit the balance.
4. The account balance ends up credited multiple times for what was supposed to be a strictly one-time bonus.

**Why it works:** This is a design flaw, not a typo — the developer correctly wrote logic for "check eligibility, then grant reward." The flaw is the *absence of atomicity* in that check-then-act sequence: nobody designed the system to assume that two requests from the same user could ever be processed in genuine parallel. The fix isn't "add a check" — it's redesigning the operation to be atomic (e.g., a single conditional database update with a unique constraint, or a distributed lock), which is a structural design decision, not a line-level patch.

**Real-world industry note:** This is the design-level cousin of what PortSwigger now treats as its own dedicated "Race Conditions" topic — and it's worth knowing that in real engagements, race-condition-class business logic flaws (multi-redeem bonuses, multi-apply coupons, over-limit withdrawals, duplicate order submission) are consistently among the highest-severity findings in fintech and e-commerce programs, because the dollar impact scales directly with how many parallel requests you can squeeze into the race window.

---

## Case Study 5: Multi-Step KYC/Onboarding Workflow Bypass

**Scenario:** A fintech app requires identity verification (KYC) before a user can withdraw funds. The onboarding flow is: register → upload ID → verification pending → verification approved (sets `kyc_status=approved` server-side) → withdrawal unlocked in the UI. The withdrawal endpoint itself, however, only checks `kyc_status` from a value cached in the **session**, which is set once at login time, not re-checked live against the database on every withdrawal request.

**Request sequence:**
```
Step 1 — Login while still pending verification:
POST /login                       (session created, kyc_status=pending cached in session)

Step 2 — Admin approves KYC in the backend while your session is still active:
(server DB updated: kyc_status=approved)

Step 3 — Withdrawal attempted using the stale session:
POST /withdraw     amount=5000    (still works — but this isn't the interesting case)

Real bypass — attacker never waits for approval:
POST /withdraw     amount=5000    fired immediately after registration, before any KYC review at all
```

**Step-by-step exploitation:**
1. Map the onboarding flow and notice the UI only *hides* the withdraw button until `kyc_status=approved` — a client-side gate.
2. Test the `/withdraw` endpoint directly, immediately after registration, before submitting any ID document at all.
3. If the server-side withdrawal handler checks only "does a session exist for this user" and not "what is this user's current, authoritative `kyc_status` in the database," the withdrawal succeeds despite zero verification ever having occurred.

**Why it works:** The actual security control (identity verification) was designed into the *UI flow* and into a one-time session flag, but never enforced as a **hard server-side gate on the specific sensitive action it's meant to protect**. This is the same root cause as Category 1 in file 02 (excessive trust in client-side controls), but elevated to a regulatory/compliance-risk scenario — this isn't just "lost money," it's an AML/KYC compliance failure, which is exactly the kind of business-impact framing you should include in a real report for this class of finding.

**Real-world industry note:** In real fintech engagements, always test sensitive financial actions (withdrawals, transfers, limit increases) **independently of the UI's perceived state**, directly against the API, as early in the account lifecycle as possible. Onboarding/KYC bypass findings are routinely rated Critical/High in fintech bug bounty programs specifically because of the regulatory exposure, not just the direct financial loss.

---

## Pattern Recap Across All Five Case Studies

| Case Study | Root Design Failure |
|---|---|
| 1. Password reset poisoning | Token not cryptographically bound to identity |
| 2. 2FA target-account bypass | Client-controlled identity parameter + missing rate limit |
| 3. Coupon stacking | Single-use enforced via transient flag, not persistent ledger |
| 4. Redeem-bonus race condition | Check-then-act sequence not atomic |
| 5. KYC withdrawal bypass | Sensitive action gated by UI/session, not live server-side state |

Every one of these is a case where the code "worked as written." The vulnerability lived entirely in what the design assumed was safe to trust. Move to `04_Engagement_Checklist.md` to turn this pattern recognition into a repeatable testing process.
