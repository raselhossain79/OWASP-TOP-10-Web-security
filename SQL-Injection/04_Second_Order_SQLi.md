# Second-Order (Stored) SQL Injection

> Second-order = the malicious input isn't used in a query immediately. It's **stored**
> (in a DB, file, etc.) at point A, and only triggered when a *different* feature reads
> that stored value and uses it unsafely in a query at point B.

---

## 1. Why This Is Easy to Miss

Standard testing usually goes: inject in field → check response from that same request.
Second-order injection breaks that assumption entirely — the field you inject into may
look completely safe (might even be parameterized correctly at the point of storage), but
some **other** part of the application reads that stored data later and builds an unsafe
query with it.

This is one of the most commonly missed vuln classes in automated scans, because scanners
test request → response in isolation and don't model multi-step stored workflows.

## 2. Classic Example: Change Password / Username Flow

**Step 1 — Register or update an account with a malicious username:**
```
username = admin'--
```
Stored safely (e.g. via parameterized insert) — nothing happens yet, registration
succeeds normally.

**Step 2 — Trigger a different feature that reads that username unsafely**, e.g. a
"change password" feature that does:
```sql
UPDATE users SET password='newpass' WHERE username='admin'--'
```
Because the original query truncates after the username (the `--` comments out the rest,
including the original `WHERE` clause restricting it to *your* account), you just changed
the **admin** account's password instead of your own.

## 3. General Methodology for Finding Second-Order SQLi

1. **Map every place user input gets stored** — profile fields, comments, support
   tickets, file names, order notes, anything persisted.
2. **Map every place that stored data gets read back into a query** — not just
   "displayed," but specifically used inside a `SELECT`/`UPDATE`/`INSERT` elsewhere in
   the app (search-by-username, admin panels, reporting/export features, audit logs).
3. **Inject benign markers first** (e.g. `test123'"<>`) into every storage point, then
   walk through every feature that might read it, watching for errors or odd behavior.
4. **Once a read-back point is found, escalate** to confirmed injection payloads
   (UNION/boolean/time-based as appropriate for that specific query context).

## 4. Real-World Notes
- Second-order SQLi is extremely common in **admin panels** that display/search
  user-submitted data — support ticket systems, CRMs, and order management tools are
  prime targets because they're built around "store now, query later" workflows by
  design.
- This is also why **stored XSS hunting and stored SQLi hunting overlap procedurally** —
  the same "where does this field get read back elsewhere" mapping exercise applies to
  both vuln classes, so doing this mapping once during an engagement pays off twice.
- Report writing tip: second-order findings need **two steps documented clearly** —
  the storage request and the trigger request — because a one-step PoC won't make sense
  to a reviewer otherwise. Always include both in your report's reproduction steps.
- In automated tooling (sqlmap, scanners), second-order is rarely detected automatically —
  this is one of the strongest arguments for manual workflow mapping during an
  engagement rather than relying purely on scanner output.

## 5. PortSwigger Lab
- Second-order SQL injection

Continue to → `05_WAF_Bypass_and_Filter_Evasion.md`
