# Second-Order (Stored) SQL Injection

## 1. Core Mechanism

Second-order SQLi splits the attack across two distinct points in the application:

1. **Injection point (sink #1):** A field where input is stored *safely* — often properly
   escaped or parameterized when it's first written to the database (e.g., a "change display
   name" form using a prepared statement for the `INSERT`/`UPDATE`).
2. **Trigger point (sink #2):** A *different* feature that later reads that stored value and
   uses it unsafely — concatenated directly into a new SQL query — without realizing the value
   originated from user input.

The payload sits dormant in storage between steps 1 and 2. This is why it's invisible to
testing that only inspects the immediate response to the original input — the vulnerability
only manifests somewhere else, later, often in a completely different feature/page.

## 2. Classic Example — "Change Email" Triggering A Later "Password Reset" Query

**Step 1 — Storing the payload (this part itself looks safe):**

A user updates their profile email field to:

```
attacker'-- 
```

Breakdown:
- `attacker` — a normal-looking partial value, so the field passes any basic format
  validation the app might apply (e.g., "must contain @"? then use `attacker@evil.com'--` —
  adjust to whatever validation exists; the point is plausible-looking storage).
- `'--` — the actual payload: a closing quote followed by a comment marker. It does nothing
  yet because the `UPDATE` statement storing the email is parameterized/escaped — the quote
  and comment are stored as a literal, harmless string in the `email` column.

**Step 2 — The trigger.** Suppose a separate, vulnerable internal admin tool later runs:

```sql
SELECT * FROM users WHERE email = '" . $storedEmail . "'
```

When `$storedEmail` is pulled from the database and concatenated *unsafely* this time, the
stored string `attacker'--` produces:

```sql
SELECT * FROM users WHERE email = 'attacker'--'
```

Breakdown:
- `'attacker'` — the original string literal now closes naturally at the quote that was part
  of our stored payload, instead of at the position the developer intended.
- `--'` — comments out the trailing quote the application's template still appends, keeping
  the query syntactically valid despite our early termination.
- Net effect: the `WHERE` clause becomes `email = 'attacker'`, an entirely attacker-defined
  condition, even though the original input passed through a perfectly safe parameterized
  `INSERT`/`UPDATE` at storage time.

## 3. Realistic Variant — Username Field Reused In A Reporting Query

```sql
admin'+(SELECT CASE WHEN (1=1) THEN '' ELSE 1/0 END)+'
```

Breakdown:
- `admin'` — closes the literal early at registration time storage (again, safely stored as a
  literal string since the registration `INSERT` is parameterized).
- `+(SELECT CASE WHEN ... END)+` — MSSQL string concatenation (`+`) wrapping a conditional
  expression (same `CASE WHEN` pattern from file 03), allowing this stored value to later be
  used as a live blind-injection probe wherever a downstream report or audit-log query
  concatenates the stored username unsafely.
- `'` — re-opens a string literal at the end, balancing quote syntax so whatever the
  downstream query appends afterward doesn't break.
- This demonstrates that second-order payloads aren't limited to simple comment-outs — they
  can carry a *full* blind/time-based/UNION payload that only "detonates" once read back by
  the vulnerable second sink.

## 4. Finding Second-Order SQLi On An Engagement

Because there's no immediate feedback, this requires deliberate, methodical testing:
1. **Map every feature that writes user-controllable data to storage** (profile fields,
   filenames, support ticket subjects, order notes, etc.) — these are candidate sink #1s.
2. **Map every feature that subsequently reads and uses that same stored field** in *any*
   query, especially less obvious internal/admin/reporting/export/search features — these are
   candidate sink #2s.
3. **Store a benign canary payload** (e.g., `test'"--` with no real attack logic) in each
   candidate field, then exercise every downstream feature that touches it, watching for any
   error or behavioral anomaly — confirming the unsafe concatenation exists before committing
   to a full payload.
4. Once a sink #2 is confirmed vulnerable, escalate the stored value to a real UNION/blind/
   time-based payload (same payload bodies as files 02–03), informed by which DBMS and
   context sink #2 uses.

PortSwigger lab mapping (Practitioner): **"SQL injection vulnerability allowing login bypass"**
covers first-order login bypass, but the Academy's broader **"Second-order SQL injection"**
concept is most directly exercised in custom/CTF-style labs and real engagements rather than a
single dedicated Academy lab — treat the methodology above as the primary reference, applying
the same UNION/blind techniques from files 02–03 once a second-order sink is confirmed.

## 5. Real-World Notes

- **Common mistake:** Declaring a field "not injectable" after testing only the immediate
  response, without tracing where that stored value is read again elsewhere in the
  application — second-order bugs are systematically missed by automated scanners and
  surface-level manual testing alike, for exactly this reason.
- **Engagement reality:** Second-order SQLi is especially common in:
  - Admin/internal dashboards that display "raw" user-submitted data in management views.
  - Logging/audit systems that later query against logged user-controlled strings.
  - Batch/cron jobs that process stored user data asynchronously, far removed in time from
    the original submission — making root-cause tracing harder for both you and the dev team.
- **Report-writing tip:** Second-order findings need *two* request examples in the writeup —
  the storage request (showing what was submitted, even though it looked harmless) and the
  trigger request (showing the downstream feature that actually executes the payload). A
  reviewer who only sees the storage request will assume it's a false positive — always show
  both halves of the chain explicitly.

## Next File
→ `06-manual-waf-bypass.md` — Manual WAF/filter evasion techniques.
