# Business Logic Flaw Categories — Mapped to PortSwigger Labs

This file breaks down every major category of business logic flaw under Insecure Design, with the PortSwigger Web Security Academy lab(s) that teach it, **listed in verified difficulty progression** (APPRENTICE → PRACTITIONER). Work through this file in order alongside the labs for maximum retention.

> Note on tool support: there is no automation tool listed in this file (no sqlmap-equivalent). Every technique here is found and exploited through **manual analysis with Burp Suite** (Proxy/HTTP history, Repeater, Intruder for brute-force-style steps, and occasionally a short Python script to script a multi-step exploit chain — not to "scan" for the bug).

---

## Category 1: Excessive Trust in Client-Side Controls

**The flawed assumption:** users will only ever interact with the app through the browser, so client-side validation (JS, hidden fields, disabled buttons) is sufficient.

**Why it works as an attack:** Burp Proxy sits between the browser and the server. Anything the client "decided" — a price, a quantity limit, a disabled form field — can be intercepted and changed before it reaches the server. If the server doesn't independently re-validate, the client-side control was never a security control at all, just a UX nicety.

**What to look for:** prices, quantities, discount flags, or role/permission fields submitted as parameters from the client rather than derived server-side from session state.

**Lab:** `Excessive trust in client-side controls` (APPRENTICE)
- The product price is sent as a parameter in the `POST /cart` request.
- **Step-by-step breakdown:**
  1. Add a cheap item to the cart with Burp Proxy intercepting.
  2. Observe the `POST /cart` request — it includes a `price` parameter (the client computed and sent it).
  3. Forward the request normally once to confirm the baseline.
  4. Add the expensive target item, intercept the `POST /cart` request, and change the `price` parameter to an arbitrary low value before forwarding.
  5. **Why it works:** the server trusts the price parameter from the client instead of looking up the authoritative price for that `productId` server-side. The trust boundary (client input vs. server-authoritative data) was never enforced.

---

## Category 2: Failing to Handle Unconventional Input

**The flawed assumption:** numeric/text inputs will only ever fall within the "sensible" range a normal user would enter.

**Sub-cases:**
- Negative numbers where only positive ones make business sense.
- Integer overflow at numeric boundaries (e.g., 32-bit signed integer max: 2,147,483,647).
- Abnormally long strings that get silently truncated server-side, with truncation happening at a point that's exploitable.

### Lab: `High-level logic vulnerability` (APPRENTICE)
- **Step-by-step breakdown:**
  1. Log in and add the target jacket to the cart — note you don't have enough balance.
  2. Intercept the `POST /cart` request; the `quantity` parameter is attacker-controlled.
  3. Submit a **negative quantity** for a cheap item already in the cart. The server recalculates the cart total but doesn't reject negative quantities.
  4. By balancing negative-quantity cheap items against the target item, drive the cart total down to an affordable (or near-zero) value.
  5. **Why it works:** the server assumes quantity will always be a positive, sensible integer. It performs arithmetic on whatever is submitted without a `quantity >= 1` (or similar) server-side check.

### Lab: `Low-level logic flaw` (APPRENTICE)
- **Step-by-step breakdown:**
  1. Same cart mechanism, but here the exploit targets **integer overflow** in the backend price calculation.
  2. Increase the quantity of a product until `unit_price * quantity` exceeds the maximum value of the backend's signed integer type (2,147,483,647). The value wraps around to a large negative number.
  3. Use Burp Intruder (or a short script) to iterate the quantity until the wrapped total lands in a range that, when combined with other cart items, produces a final total at or below zero / an affordable value.
  4. **Why it works:** the server validates that the *final total* isn't negative, but never validates the *intermediate* multiplication against overflow. The design assumed quantities would always be "reasonable," so no upper bound was set relative to the integer type's limits.

### Lab: `Inconsistent handling of exceptional input` (APPRENTICE)
- **Step-by-step breakdown:**
  1. Find a registration or profile form with an email field that has a hidden server-side length cap (commonly 255 characters in many real backends).
  2. Submit an email address engineered so that the **legitimate-looking prefix is padded with filler characters**, and the actual domain you want to be recognized as (e.g., an internally-trusted domain) lands exactly at the truncation boundary.
  3. The server silently truncates the string at its length limit — discarding the attacker-supplied padding tail and leaving the trusted-looking domain in the validated record, even though the original full string would have failed validation as a real address for that domain.
  4. **Why it works:** input length validation and business-rule validation ("does this email belong to the trusted domain") happen in different layers that don't agree on what the "real" value is after truncation. The design never asked "what if validation and truncation disagree?"

---

## Category 3: Inconsistent Security Controls

**The flawed assumption:** once a user/action is validated at one entry point, that trust can be carried safely to every other entry point that performs a related action.

**Lab:** `Inconsistent security controls` (APPRENTICE)
- **Step-by-step breakdown:**
  1. Identify a restricted action (e.g., access to an admin panel) that's gated by checking something like an email domain.
  2. Find a *second* entry point into the same restricted area — typically a registration flow — that performs the domain check less strictly than the primary login/access-control path.
  3. Register through the weaker path, satisfying its check, and gain access that should have required passing the stricter check used elsewhere.
  4. **Why it works:** the same business rule ("only users from this domain may access this") was implemented twice, in two different code paths, with two different levels of rigor. Insecure design here is the failure to centralize the control — every place a rule is enforced is another place it can be enforced inconsistently.

---

## Category 4: Weak Isolation on a Dual-Use Endpoint

**The flawed assumption:** a single endpoint that legitimately serves two different purposes (e.g., "set my password" vs. "reset someone's password via token") can tell those two cases apart safely just by which parameters happen to be present.

**Lab:** `Weak isolation on dual-use endpoint` (PRACTITIONER)
- **Step-by-step breakdown:**
  1. Trigger a password reset for your own account; note the reset link/token format, e.g., `POST /my-account/change-password` with `current-password`, `new-password-1`, `new-password-2`, and a hidden `username`-style field tied to the reset session.
  2. Observe that the **same endpoint** is reused both for "logged-in user changing their own password" (which should require `current-password`) and "user resetting password via emailed token" (which should not require knowing the current password at all).
  3. Remove the `current-password` parameter entirely from the request, and change the `username`/identity-bearing field to a victim account, while keeping the request authenticated as yourself.
  4. **Why it works:** the endpoint doesn't strictly verify *which* of the two legitimate flows the request belongs to. It infers "this must be a self-service change" or "this must be a token reset" based on which fields are present — and an attacker can simply present the field combination that satisfies the *weaker* of the two code paths while supplying someone else's identity.

---

## Category 5: Flawed Assumptions About Sequence — Insufficient Workflow Validation

**The flawed assumption:** users will always progress through a multi-step process (cart → checkout → confirm → complete) in the order the UI presents, and therefore each step doesn't need to independently re-verify the preconditions the *previous* step was supposed to guarantee.

**Lab:** `Insufficient workflow validation` (PRACTITIONER)
- **Step-by-step breakdown:**
  1. Add an expensive item to the cart, intentionally without sufficient balance, and walk through checkout normally with Burp Proxy capturing every request.
  2. At the point where the server returns an "insufficient funds" error (typically on a `POST /cart/checkout` step), notice that a **separate, later request** — e.g., `GET /cart/order-confirmation?order-confirmed=true` — exists as its own step in the chain.
  3. Replay (forced-browse to) the order-confirmation request directly, **skipping the checkout step that performed the balance check**.
  4. **Why it works:** the design treats "confirm order" as a step that simply *follows* a successful checkout, rather than a step that *independently re-verifies* the funds/eligibility check. Nothing stops you from invoking it out of sequence because the server has no server-side state machine enforcing "you may only reach order-confirmation if checkout just succeeded for this session."

---

## Category 6: Authentication Bypass via Flawed State Machine

**The flawed assumption:** a multi-step authentication flow (e.g., username/password → role selection → MFA) will always be driven start-to-finish by the legitimate client, so the server can rely on the client to "remember" which step it's on.

**Lab:** `Authentication bypass via flawed state machine` (PRACTITIONER)
- **Step-by-step breakdown:**
  1. Log in with valid low-privilege credentials. Observe the flow includes a second step, e.g., `GET /role-selector`, where you choose to log in as a restricted role.
  2. Intercept the request to `/role-selector` (the second step) and **drop it instead of forwarding it** — preventing the server from ever recording your restricted role choice.
  3. Browse directly to the application's home/dashboard page.
  4. **Why it works:** the server-side session was actually instantiated with a default/elevated role at the first authentication step, and the role-selector step exists only to *downgrade* it for legitimate users who choose a restricted role. By never completing that downgrade step, the session retains its original elevated privilege — the state machine has an implicit "if this step is skipped, fall back to the most-privileged state" default, which is exactly backwards from a secure design.

---

## Category 7: Domain-Specific Flaws — Flawed Enforcement of Business Rules

**The flawed assumption:** a business rule (like "10% off orders over $1000" or "one coupon per order") will only ever be evaluated against the *final* state of an order, so checking the rule once at the moment it's applied is sufficient.

**Lab:** `Flawed enforcement of business rules` (PRACTITIONER)
- **Step-by-step breakdown:**
  1. Add enough items to the cart to cross a discount threshold (e.g., a 10% discount triggers above a spending threshold).
  2. Apply the discount/coupon — the server checks the cart total *at that moment* and approves the discount.
  3. Remove the expensive items that pushed you over the threshold, leaving only the cheap item(s) you actually wanted, while the discount remains applied to the now-much-smaller order.
  4. Complete checkout with the discount still active on a cart that no longer satisfies the rule that granted it.
  5. **Why it works:** the rule ("10% off orders over $1000") is enforced only at the instant the coupon is applied, not re-validated at the instant the order is finally placed. The design treats discount eligibility as a one-time gate rather than an invariant that must hold throughout the transaction.

---

## Category 8: Infinite Money / Resource Logic Flaws

**The flawed assumption:** a one-time bonus, credit, or coupon mechanism can only be triggered once per user because the UI only shows it once — and combining multiple *legitimate* mechanisms together was never considered as a single combined abuse case.

**Lab:** `Infinite money logic flaw` (PRACTITIONER)
- **Step-by-step breakdown:**
  1. Find two independent legitimate discount mechanisms — e.g., a newsletter-signup coupon (`SIGNUP30`) and a generic new-customer coupon (`NEWCUST5`) — that each work once individually and are each correctly blocked from being reapplied back-to-back.
  2. Test applying coupon A, then coupon B, then coupon A again. Notice the server blocks "the same coupon twice in a row" but does **not** track total redemptions per coupon per account across an alternating sequence.
  3. **Alternate** between coupon A and coupon B repeatedly (`A, B, A, B, A, B, ...`), each time generating a small net credit/discount via a connected mechanism like a purchasable, redeemable gift card.
  4. Automate the alternating request sequence (Burp session-handling macro or a short script) to repeat the cycle enough times to accumulate sufficient store credit to purchase the target item outright.
  5. **Why it works:** each individual rule ("can't apply the same coupon twice in a row") was correctly designed and correctly implemented. The flaw is that the *combination* of two individually-safe rules creates an unbounded resource-generation loop — a design failure to consider the cumulative effect of chaining legitimate, individually-rate-limited actions.

---

## Category 9: Providing an Encryption Oracle

**The flawed assumption:** if user-controllable data is encrypted before being handed back to the user (e.g., embedded in a cookie or a "remember me" token), the user can't make meaningful use of having "their own data" encrypted — because they already know what went in.

**Lab:** `Authentication bypass via encryption oracle` (PRACTITIONER)
- **Step-by-step breakdown:**
  1. Locate a feature that accepts user input and returns it back to you in an encrypted/obfuscated form elsewhere in the app (e.g., a blog comment form whose "stay logged in" cookie format uses the same encryption routine as another sensitive cookie elsewhere on the site).
  2. Use the comment form as a controllable encryption oracle: submit crafted plaintext (e.g., a serialized structure resembling `{"username":"administrator"}` padded to match expected block boundaries) and capture the resulting ciphertext the application hands back to you (e.g., in a `Set-Cookie` header on the comment-confirmation response).
  3. Substitute that attacker-chosen, validly-encrypted ciphertext into the **other**, security-sensitive cookie that uses the same encryption key/algorithm (e.g., a "stay-logged-in" authentication cookie).
  4. The server decrypts the substituted cookie using the shared key, trusts the resulting plaintext, and authenticates you as the identity you encoded.
  5. **Why it works:** the same encryption key and algorithm is reused across two functionally unrelated features with very different trust levels (a public comment form vs. an authentication cookie). The design never considered that giving an attacker controllable plaintext-to-ciphertext access on one feature hands them a tool to forge trusted tokens on a completely different feature.

---

## Quick-Reference Mapping Table

| # | Flaw Category | PortSwigger Lab | Tier |
|---|---|---|---|
| 1 | Excessive trust in client-side controls | Excessive trust in client-side controls | APPRENTICE |
| 2 | Unconventional input (negative/overflow) | High-level logic vulnerability | APPRENTICE |
| 2 | Unconventional input (integer overflow) | Low-level logic flaw | APPRENTICE |
| 2 | Unconventional input (truncation mismatch) | Inconsistent handling of exceptional input | APPRENTICE |
| 3 | Inconsistent enforcement across code paths | Inconsistent security controls | APPRENTICE |
| 4 | Dual-use endpoint weak isolation | Weak isolation on dual-use endpoint | PRACTITIONER |
| 5 | Sequence/workflow skipping | Insufficient workflow validation | PRACTITIONER |
| 6 | Authentication state machine flaw | Authentication bypass via flawed state machine | PRACTITIONER |
| 7 | Business rule enforced once, not as invariant | Flawed enforcement of business rules | PRACTITIONER |
| 8 | Combining safe mechanisms into unsafe loop | Infinite money logic flaw | PRACTITIONER |
| 9 | Shared encryption key across trust levels | Authentication bypass via encryption oracle | PRACTITIONER |

Proceed to `03_Case_Studies_Real_World_Scenarios.md` to see these same patterns reframed as real-world engagement scenarios beyond the lab environment.
