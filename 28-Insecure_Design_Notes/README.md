# Insecure Design — OWASP Top 10 A04:2021

A GitHub-ready, engagement-focused note series on **Insecure Design**, the OWASP Top 10 2021 category A04. This series follows the same structural depth as the SQL Injection series, but the subject matter requires a different approach: Insecure Design is not a single payload-based vulnerability class. It is a **methodology and mindset category** that covers flawed business logic, missing security controls by design, and trust boundary violations that exist even when the code is implemented perfectly.

---

## Why This Series Looks Different From SQLi / XSS / SSTI / etc.

| | SQL Injection / XSS / SSTI | Insecure Design |
|---|---|---|
| Root cause | Implementation bug (bad sanitization, bad parsing) | Architecture / requirements / threat-modeling failure |
| Fix | Patch the code (parameterize, encode, sandbox) | Redesign the workflow or control |
| Detection | Payload injection, error-based / blind testing | Logical reasoning, workflow mapping, abuse-case thinking |
| Automation tool | sqlmap, dalfox, tplmap, etc. | **None** — this is inherently manual, human-judgment-driven |
| WAF bypass relevance | High (filter evasion is central) | Largely irrelevant — a WAF does not understand business logic |

This is why this series has **no automation-tool file and no WAF-bypass file**. Forcing those into an Insecure Design series would misrepresent the category. A WAF can block a `UNION SELECT`; it cannot tell that your password-reset workflow trusts a parameter it should never trust.

---

## File Index

1. **[01_Overview_and_Concept.md](01_Overview_and_Concept.md)**
   What Insecure Design means under OWASP A04:2021, how it differs from "insecure implementation," trust boundaries, missing rate-limiting-by-design, and why automated scanners almost always miss this category.

2. **[02_Business_Logic_Flaw_Categories.md](02_Business_Logic_Flaw_Categories.md)**
   Every major category of business logic flaw (excessive client-side trust, unconventional input handling, flawed assumptions about user behavior, domain-specific flaws, encryption oracles, missing rate limiting), each mapped to the corresponding PortSwigger Web Security Academy lab in verified difficulty progression.

3. **[03_Case_Studies_Real_World_Scenarios.md](03_Case_Studies_Real_World_Scenarios.md)**
   Real-world-style scenarios with full step-by-step request/response breakdowns: password reset poisoning, 2FA logic bypass, workflow-step skipping, coupon/discount stacking, integer overflow pricing, encryption oracle abuse, and design-level race conditions.

4. **[04_Engagement_Checklist.md](04_Engagement_Checklist.md)**
   A practical checklist to run during a real penetration test or bug bounty engagement to systematically surface insecure design issues, organized by workflow type (auth, payments, multi-step processes, APIs, trust boundaries).

---

## How to Use This Series

- Read file 01 first — you need the conceptual frame before the lab mapping makes sense.
- Use file 02 while working through PortSwigger's Business Logic Vulnerabilities labs in the listed order — it is structured to match your lab progression exactly.
- Use file 03 as your "what does this look like in a real engagement" reference.
- Use file 04 as a living checklist on every engagement — copy it into your engagement notes and tick items off as you test them.

## Scope Note

OWASP A04:2021 (Insecure Design) is broader than just "business logic vulnerabilities" — it also covers things like missing threat modeling, insecure design patterns for sensitive workflows, and lack of segregation of tiers. This series focuses on the **practically testable subset** that you will actually encounter and exploit during web application penetration testing and bug bounty work, since that is the actionable core of the category for an offensive tester. Architectural/SDLC-level design review (threat modeling documents, secure design patterns at the org level) is mentioned in file 01 for completeness but is not the operational focus of this series.
