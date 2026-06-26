# Engagement Checklist — Identifying Insecure Design

A practical, copy-into-your-notes checklist for surfacing insecure design / business logic flaws during a real penetration test or bug bounty engagement. Unlike a payload checklist, this is a **question checklist** — run through it at every workflow you encounter, not just once per app.

---

## 0. Before You Start Clicking — Map the Application Like a Business, Not Just a Target

- [ ] List every distinct **workflow** in the app (registration, login, password reset, checkout, withdrawal, profile update, admin actions, API-only flows).
- [ ] For each workflow, write down in one sentence **what the business is trying to prevent** (e.g., "checkout exists to prevent people getting items without paying the correct, current price").
- [ ] Identify which workflows touch **money, identity, or privilege** — these get tested first and most thoroughly.
- [ ] Note any workflow that's a **multi-step process** (anything spanning more than one request to complete) — these are prime insecure-design territory.

---

## 1. Client-Side Trust Boundary Checks

- [ ] For every form, intercept the submission in Burp Proxy and check whether **price, quantity, discount, role, or permission values are present as parameters** rather than being derived purely server-side from session/account state.
- [ ] Disable JavaScript and/or use Burp Repeater to submit requests with disabled/hidden fields re-enabled or modified.
- [ ] Check whether any "calculated" value shown in the UI (total price, remaining quota, discount %) is also submitted back to the server as a parameter on the next request — if so, test changing it directly.

## 2. Unconventional Input Testing

- [ ] Submit **negative numbers** anywhere a quantity, amount, or count is accepted.
- [ ] Submit **zero** where a minimum of 1 might be assumed but not enforced.
- [ ] Submit **very large numbers** to probe for integer overflow (test values near `2147483647` / `9223372036854775807` boundaries, and slightly beyond).
- [ ] Submit **abnormally long strings** in text fields, especially ones tied to identity/domain checks (email, username), and check for truncation-related logic mismatches.
- [ ] Try removing each parameter entirely (name and value) one at a time from a multi-parameter request — note any change in behavior or any new code path reached.
- [ ] Try duplicate parameters with conflicting values (`quantity=1&quantity=-1`) — different frameworks resolve duplicates differently and inconsistently.

## 3. Multi-Step Workflow / Sequence Testing

- [ ] Map every request involved in a multi-step process (signup, checkout, password reset, KYC) in the order the UI presents them.
- [ ] Try **skipping a step** — forced-browse directly to a later step's endpoint without completing the earlier ones.
- [ ] Try **repeating a step** more than once.
- [ ] Try **revisiting an earlier step** after completing a later one, and observe whether state becomes inconsistent.
- [ ] Try sending steps **out of order** entirely.
- [ ] For any step that returns an error (e.g., "insufficient funds," "verification required"), test whether the **next** step in the chain can be reached directly anyway.

## 4. Authentication / Session State Machine Testing

- [ ] If login is multi-step (password → role select → MFA, etc.), test **dropping each intermediate step** and going straight to an authenticated page.
- [ ] Check whether the **target identity** of any step (e.g., "which account is this OTP for") is taken from a client-supplied parameter rather than the already-established session.
- [ ] Test for **missing rate limiting / lockout** on every authentication-adjacent endpoint individually: login, OTP/2FA verification, password reset request, password reset confirmation. Don't assume one rate limiter covers all of them — they're often separate code paths with separate (or absent) protections.
- [ ] Check whether session state set at login time (role, KYC status, subscription tier) is **re-validated live** at the point of each sensitive action, or just cached from login and trusted thereafter.

## 5. Password Reset / Account Recovery Specific Checks

- [ ] Verify the reset token is **cryptographically bound to the account** it was issued for — attempt submitting a valid token for your own account alongside a different target username.
- [ ] Check whether the reset-confirmation endpoint requires the current password in some flows and not others (dual-use endpoint pattern) — test omitting fields you'd expect to be conditionally required.
- [ ] Check token expiry and check whether tokens can be reused after a successful reset.
- [ ] Check for rate limiting on reset-request submission (mass-mail / enumeration abuse).

## 6. Discount / Coupon / Loyalty / Referral Logic

- [ ] Test applying, then removing, then reapplying the same coupon/discount — check whether "already used" is enforced as a **persistent record** or just **transient session state**.
- [ ] Test alternating between two or more independently-valid discounts to see if a combined application bypasses a "one discount at a time" rule.
- [ ] Test whether a discount remains active after the condition that earned it (e.g., minimum cart value) is no longer true.
- [ ] Test referral/bonus mechanisms for self-referral or circular referral patterns.

## 7. Race Condition / Concurrency-Sensitive Actions

- [ ] Identify every "redeem once," "use this code once," "apply this discount once" type of action.
- [ ] Fire the same redeem/apply request multiple times **in parallel** (Burp Repeater's "send group in parallel," or a small concurrent-request script) and check whether the limit holds under concurrency, not just sequential testing.
- [ ] Test concurrent requests against withdrawal/transfer/balance-deduction endpoints specifically — these have the highest real-world dollar impact if check-then-act logic isn't atomic.

## 8. Encryption / Token Reuse Across Trust Levels

- [ ] Identify any feature where user-controllable input is reflected back encrypted/encoded/signed (cookies, "remember me" tokens, exportable signed URLs).
- [ ] Check whether the same encryption/signing key or algorithm is reused across features of meaningfully different sensitivity (a low-trust comment form vs. a high-trust auth cookie).
- [ ] If you can control plaintext and observe the resulting ciphertext/signature, test substituting that crafted value into the more sensitive feature.

## 9. Privilege / Identity Parameter Testing

- [ ] On every request that includes an identity-like parameter (`user_id`, `account`, `role`, `verify`, `target`), test substituting a **different valid identity** while keeping your own authenticated session.
- [ ] Test whether role/permission is derivable **only** from the authenticated session, or whether it can be influenced by any request parameter at all.
- [ ] For internal/admin-looking endpoints discovered via content discovery, test direct access even with no UI link to them — "no button for it" is not access control.

## 10. Missing-Control-by-Design Sweep

- [ ] For every sensitive action, ask explicitly: **"If I do this 100 times in 10 seconds, what happens?"** — sending feedback, requesting a reset email, applying a coupon, submitting a support ticket, generating an export, requesting an OTP.
- [ ] Note any endpoint where the answer is "nothing stops me" and there's a plausible abuse case (spam, resource exhaustion, enumeration, financial gain) — this is a missing-control-by-design finding even without a clever exploit chain attached.

## 11. Domain-Knowledge Pass (Do This Last, With Fresh Eyes)

- [ ] Step back from the technical checklist and ask: **"If I were trying to hurt this specific business, what would I actually want to do?"** (free items, fake reviews, mass account creation, unlimited free trials, follower/like inflation, bypassing a paywall, evading a usage cap).
- [ ] Re-walk the application specifically hunting for the functionality that would let you do that thing, even if it doesn't map neatly to any item above.
- [ ] Write down every assumption you can identify that the developers seem to have made about user behavior, and explicitly test violating each one.

---

## Reporting Note

When writing up a finding from this category, always state explicitly in the report:
1. **The assumption that was violated** (not just "the price can be changed," but "the server assumes the client-submitted price can be trusted").
2. **The business impact in concrete terms** (financial loss per exploit cycle, compliance exposure, abuse potential at scale) — insecure design findings are judged on business impact more than on technical novelty, so make that case clearly.
3. **That the fix is a design change, not a patch** — recommend the control that should exist (server-side re-validation, atomic operations, persistent ledgers, bound tokens), since this guides remediation conversations differently than a typical injection finding would.
