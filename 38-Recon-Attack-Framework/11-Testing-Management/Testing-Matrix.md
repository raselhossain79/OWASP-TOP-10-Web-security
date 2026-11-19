# Testing Matrix

A tracking template for systematic coverage during an engagement — prevents both
gaps (an input never actually tested) and duplicate effort (re-testing the same
input/hypothesis without realizing it was already covered).

## Why This Exists
Without a tracked matrix, testing tends to drift toward whatever's easiest to
try rather than what the input surface and context actually suggest (see
`12-Workflow-Examples/` for how to choose a hypothesis per endpoint rather than
testing everything everywhere). This matrix is the record that makes that
choice visible and reviewable.

## Columns

| Column | What goes here |
|---|---|
| Asset / Endpoint | The full URL or route, e.g. `/api/orders/{id}` |
| HTTP Method | `GET`, `POST`, `PUT`, `DELETE`, etc. |
| Input Parameter & Location | e.g. `id` (path), `status` (JSON body), `session` (cookie) |
| Authentication Context | Which account/role was used — or "unauthenticated" |
| User Role / Ownership | e.g. "User B testing User A's resource" — relevant for IDOR/BOLA rows |
| Vulnerability Hypothesis | The specific class being tested and *why* (e.g. "numeric sequential ID → horizontal IDOR candidate") |
| Test Status | `Not Started` / `In Progress` / `Blocked (WAF)` / `Complete` |
| Evidence Reference | Link/path to the saved request-response pair or screenshot |
| Final Result | `Confirmed Vulnerable` / `Not Vulnerable` / `Inconclusive` / `Out of Scope` |

## Reusable Template (copy per engagement)

```markdown
| Asset / Endpoint | Method | Input (Location) | Auth Context | Role / Ownership | Hypothesis | Status | Evidence | Result |
|---|---|---|---|---|---|---|---|---|
| /api/orders/{id} | GET | id (path) | User B session | User B accessing User A's order | Horizontal IDOR — sequential numeric ID | Complete | evidence/idor-orders-001.md | Confirmed Vulnerable |
| /search | GET | q (query) | Unauthenticated | N/A | Reflected XSS — unescaped in HTML body context | Complete | evidence/xss-search-001.md | Not Vulnerable (output HTML-encoded) |
| /api/profile/update | PUT | role (JSON body) | Low-priv session | N/A | Vertical BFLA — client-trusted role field | In Progress | — | — |
| /import | POST | url (JSON body) | Test account | N/A | SSRF — server fetches arbitrary URL | Blocked (WAF) | — | — |
```

## Usage Notes
- **One row per input per hypothesis** — not one row per endpoint. An endpoint
  with 3 parameters and 2 plausible vulnerability classes per parameter is 6
  rows, not 1.
- **Fill "Hypothesis" with a reason, not just a vulnerability name** — "testing
  for SQLi" is not useful on review; "numeric ID directly used in a visible
  query-like URL pattern → SQLi candidate" is.
- **"Inconclusive" is a valid, honest final result** — don't force every tested
  row into Vulnerable/Not Vulnerable if the evidence genuinely didn't settle it
  (e.g. a WAF blocked further testing and the program's policy didn't permit
  bypass attempts). Document why it's inconclusive.
- Update Test Status as you go — a matrix only filled in retroactively after
  testing loses most of its value as a coverage-tracking tool.

## Next Action
Completed rows with `Confirmed Vulnerable` feed directly into
`08-Validation-and-Evidence/` and then `09-Reporting/professional-reporting.md`.
