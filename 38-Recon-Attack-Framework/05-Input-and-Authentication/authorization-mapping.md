# Authorization Mapping

## 1. Purpose
Map roles and permission boundaries so that IDOR and broken-access-control (BAC)
testing is targeted at real boundaries, rather than guessed at randomly.

## 2. When to Use
After authentication mapping, before `idor.md` or `business-logic.md` testing.

## 3. Prerequisites
At least two test accounts with different privilege levels if the application has
roles (e.g. a regular user and an admin, or two regular users to test horizontal
access). Using only one account makes most authorization testing impossible.

## 4. Methodology
1. List every role the application defines (often visible in the UI, admin panel
   presence, or in JWT claims/API responses).
2. For each role, document what actions/resources are supposed to be accessible.
3. Identify resource identifiers (IDs, UUIDs, slugs) that belong to a specific user
   — these are the targets for horizontal access testing (one regular user
   accessing another regular user's data).
4. Identify role-gated actions/endpoints — these are the targets for vertical
   access testing (a lower-privileged role attempting a higher-privileged action).

## 5. Commands
```bash
# Capture the same request as two different users, compare directly
curl -s "https://target.com/api/orders/105" -H "Cookie: session=<USER_A_SESSION>"
curl -s "https://target.com/api/orders/105" -H "Cookie: session=<USER_B_SESSION>"
```

## 6. Command Breakdown
No special flags here — the technique is the comparison itself: the same resource
ID (`105`, known to belong to User A), requested while authenticated as User B. A
response containing User A's actual data when requested as User B is the core IDOR
signal (see `06-Vulnerability-Testing/idor.md` for the full testing workflow).

## 7. Expected Output
A role/permission matrix: which roles exist, which resources/actions are supposed
to be restricted to which role, and a list of resource IDs known to belong to
specific test accounts for later horizontal-access testing.

## 8. Interpretation
This matrix is the map that `idor.md` and `business-logic.md` test against — it
turns "try some IDs and see what happens" into "User B should not be able to see
Order 105, which belongs to User A — test that specific boundary."

## 9. False Positives
- Some resources are intentionally shared/public (e.g. public profile pages) —
  confirm a resource is actually meant to be private before treating cross-account
  access to it as a finding.

## 10. Next Action
Proceed to `06-Vulnerability-Testing/idor.md` and `business-logic.md` with this
matrix as the test plan.

## 11. Safety Considerations
Use only test accounts you control for both sides of this comparison. Never use a
real other user's session/credentials, even if encountered during testing — that
is a line into unauthorized access, not authorized testing.

## 12. Documentation
Record the role matrix and which account/resource pairs were used for each
comparison — this is the evidence structure an IDOR/BAC report needs.
