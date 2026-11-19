# Professional Reporting

## 1. Purpose
Write up a finding so a triager/client can understand, reproduce, and prioritize it
without back-and-forth — the quality of the report determines whether a real
finding gets acted on.

## 2. When to Use
After `08-Validation-and-Evidence/` has produced a reproducible, minimal piece of
evidence.

## 4. Standard Structure

```markdown
## Title
[Vulnerability class] in [specific endpoint/parameter] allows [specific impact]

## Severity
[Critical / High / Medium / Low] — state the reasoning, don't just assert a label
(e.g. "High — allows horizontal access to other users' order data, including
[specific sensitive field], confirmed via direct testing")

## Summary
1–3 sentences: what the issue is and why it matters, in plain language before any
technical detail.

## Steps to Reproduce
1. [Exact numbered steps, including the exact request]
2. [...]
Include the literal request (method, full URL, relevant headers, body) and the
literal response that confirms it — not a paraphrase.

## Impact
What a real attacker could actually do with this, stated concretely rather than
generically ("could lead to data breach" is weaker than "allows any authenticated
user to read any other user's full order history and shipping address by
incrementing the `order_id` parameter").

## Evidence
Request/response pairs, screenshots, timing data — whatever
`08-Validation-and-Evidence/` produced.

## Remediation
A specific, actionable fix suggestion (e.g. "enforce an authorization check
verifying the requesting user owns `order_id` before returning order data"), not
just "fix the vulnerability."
```

## 9. Common Reporting Mistakes to Avoid
- **Overstating severity**: a theoretical issue with no demonstrated impact should
  be labeled and described as such, not inflated to match a desired bounty tier.
- **Underspecifying reproduction steps**: if a triager can't reproduce it from your
  steps alone, expect the report to be marked "needs more info" or closed —
  include literally everything needed, including auth/session setup.
- **Reporting the bypass instead of the vulnerability**: if a WAF bypass was
  needed to demonstrate an issue, the report is about the underlying vulnerability
  (e.g. the SQLi), with the bypass method documented as part of reproduction — not
  "I bypassed your WAF" as the headline finding (unless the WAF bypass itself, with
  no underlying vulnerability, is explicitly in scope as its own class of finding
  for that program).
- **Mixing confirmed findings with hypotheses**: if something is suspected but not
  validated (e.g. "this might also be injectable but I didn't confirm it"), say so
  explicitly rather than presenting it with the same confidence as a validated
  finding.

## 11. Safety / Ethical Considerations in Reporting
- Do not include more of another user's real data in a report than needed to
  prove the issue (e.g. redact most fields, show that *a* private field was
  exposed rather than reproducing a full record).
- Follow the program's disclosed reporting channel and any disclosure timeline
  policy — do not publicly disclose a finding before the program's agreed
  timeline, even after submission.

## 12. Documentation
The report itself is the final documentation artifact of the entire framework —
everything from scope confirmation through evidence collection exists to produce
this document.
