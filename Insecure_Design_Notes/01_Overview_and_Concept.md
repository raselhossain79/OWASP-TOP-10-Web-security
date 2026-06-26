# Overview & Concept — Insecure Design (OWASP A04:2021)

## 1. What OWASP Means by "Insecure Design"

OWASP introduced **A04:2021 – Insecure Design** as a new category in the 2021 Top 10 revision, separate from A05 (Security Misconfiguration) and A03 (Injection). The distinction OWASP draws is deliberate and important:

> "Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design.' ... An insecure design cannot be fixed by a perfect implementation, as by definition, the needed security controls were never created to defend against specific attacks."

That last sentence is the entire point of this category. You can have:

- Zero SQL injection
- Zero XSS
- Perfect input encoding
- A fully patched, hardened server

...and still be completely compromised, because the **application was never designed to prevent the abuse case in the first place**. The code does exactly what it was told to do. The problem is what it was told to do was wrong.

## 2. Insecure Design vs. Insecure Implementation

This is the single most important distinction to internalize before testing for A04, because it changes how you think during an engagement.

| Insecure Implementation | Insecure Design |
|---|---|
| Developer wrote `$query = "SELECT * FROM users WHERE id=" . $_GET['id']` | Developer correctly parameterized every query, but the password reset workflow never checks whether the reset token actually belongs to the username supplied alongside it |
| Fix: change the code | Fix: change the *workflow* — there's nothing to "patch" line-by-line; the logic itself needs new rules |
| Found by: payload injection, fuzzing | Found by: reading the workflow, asking "what did the developer assume here, and is that assumption safe?" |

A useful mental shortcut: **implementation bugs are "the code is broken." Design flaws are "the code works exactly as intended, and that's the problem."**

## 3. Trust Boundaries

A trust boundary is any point where data or control crosses from a less-trusted context into a more-trusted one — client to server, unauthenticated to authenticated, low-privilege to high-privilege, one microservice to another.

Insecure design frequently shows up as a **trust boundary violation**: the application trusts something on the wrong side of the boundary.

Classic examples:

- **Trusting client-side validation as a security control.** JavaScript can enforce a price field for UX, but if the server doesn't independently re-validate that price, the trust boundary has effectively been erased — the client, not the server, is making the security decision.
- **Trusting a parameter that originated from the user to determine privilege.** If a request includes `role=admin` and the server trusts it without checking what role the authenticated session is actually entitled to, the trust boundary between "what the user claims" and "what the server has verified" has collapsed.
- **Trusting that an internal API will only ever be called by your own front end.** Internal endpoints exposed without independent authorization checks (because "the UI doesn't expose a button for it") rely on obscurity, not a trust boundary.
- **Trusting that a multi-step process will always be completed in order.** If step 3 assumes steps 1 and 2 already validated something, and step 3 is independently reachable, the trust boundary between "validated state" and "attacker-controlled state" doesn't actually exist.

When testing for insecure design, you are constantly asking: **"At this point in the workflow, what is the server trusting, and did it earn the right to trust it?"**

## 4. Missing Rate Limiting / Controls "By Design"

A subtle but very common design flaw: a control that's *missing entirely*, not weak. Not a misconfigured rate limiter — no rate limiter was ever designed for that endpoint, because nobody on the design team considered it an abuse surface.

Examples:

- A coupon-redeem endpoint has no limit on how many times it can be called, because the design only considered "one customer applying one coupon once" as the use case.
- A password-reset email-send endpoint has no cooldown, because the design assumed "users only request resets when they're locked out," not "an attacker can use this as a mass-mailing or enumeration oracle."
- An OTP/2FA verification endpoint has no lockout after failed attempts, because the design assumed "users only mistype their code once or twice," not "an attacker can brute-force a 4-digit code with no limit."

This is different from a misconfiguration (where a rate limiter exists but was set too loosely). Here, the abuse case was never part of the threat model, so no control exists to find or misconfigure. This is purely a design gap.

## 5. Business Logic Vulnerabilities — The Practical Core of A04

PortSwigger's Web Security Academy treats "Business Logic Vulnerabilities" as effectively synonymous with the testable, exploitable side of insecure design, and that mapping is accurate for offensive testing purposes. PortSwigger's own definition:

> "Business logic vulnerabilities are flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior. This potentially enables attackers to manipulate legitimate functionality to achieve a malicious goal."

This series treats **Business Logic Vulnerabilities as the operational subset of Insecure Design that you will actually test for and exploit**, while file 01 (this file) keeps the broader OWASP framing so you understand where business logic flaws sit inside the bigger A04 picture.

## 6. Why Automated Scanners Almost Always Miss This Category

This matters enough that it shapes your entire engagement approach:

- A scanner has no concept of "this discount should not apply after these items were removed from the cart." It does not understand your business rules — it doesn't even know what the business is.
- A scanner cannot determine that a 2FA flow can be skipped by browsing directly to `/my-account` after step 1, because nothing in the HTTP response *looks* abnormal — it's a 200 OK to a valid request.
- A scanner has no domain knowledge. Understanding that "letting users follow other users for free is bad for a social platform's ad-revenue model" requires a human who understands what the business actually depends on.

This is precisely why insecure design / business logic flaws are one of the highest-value areas for **manual testers and bug bounty hunters** — the entire category is structurally invisible to tools, which means it's underreported and under-remediated even in mature programs.

## 7. The Mental Model for Testing This Category

Every technique in file 02 and every case study in file 03 reduces to the same five questions, asked at every step of every workflow you encounter:

1. **What assumption is the server making about my input, my identity, or my state right now?**
2. **Can I violate that assumption without the server noticing?**
3. **What happens if I skip a step, repeat a step, or do steps out of order?**
4. **What happens at the edges — negative numbers, zero, massive numbers, empty values, duplicate values?**
5. **What does this functionality protect, and what would an attacker actually want to do with it?** (This is the domain-knowledge question — you need to think like the business, not just like a fuzzer.)

Keep these five questions in mind as you move into file 02.
