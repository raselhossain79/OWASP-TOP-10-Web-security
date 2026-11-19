# Authorized Bypass Testing

## 1. Purpose
Apply specific evasion techniques, grounded in the normalization gaps explained in
`request-parsing.md`, only when doing so is within the program's rules and serves
to confirm (not just work around) an underlying vulnerability.

## 2. When to Use — and When Not To
Use only when:
- A WAF/filter is confirmed to be blocking a test (`waf-detection.md`).
- The program's scope/rules do not prohibit filter-evasion testing. Some programs
  explicitly state "do not attempt to bypass our WAF" — that is a hard stop, not a
  suggestion, regardless of technical feasibility.
- You have a specific reason to suspect a real vulnerability exists behind the
  filter (not just "let's see if anything gets through").

**Stop entirely if**: the program's policy prohibits it, you've tried a reasonable,
targeted set of techniques without success (continuing indefinitely has diminishing
value and increasing risk of being flagged as abusive traffic), or the only way
forward would require volume/aggression inconsistent with rate-limit expectations.

## 3. Prerequisites
Confirmed WAF/filter presence and, ideally, some characterization of which layer
is involved (edge WAF vs. application-level) from `waf-detection.md`.

## 4–6. Techniques, Commands, and Breakdown

| Technique | Example | Mechanism (see `request-parsing.md`) |
|---|---|---|
| Case manipulation | `UnIoN SeLeCt` | WAF signature case-sensitive, SQL engine isn't |
| Comment/whitespace insertion | `UNI/**/ON SEL/**/ECT` | Breaks literal keyword match while SQL engine still parses it |
| Alternate whitespace | `%09` (tab), `%0a` (newline) in place of a space | Same mechanism, different character |
| Parameter pollution | `?id=1&id=1' OR '1'='1` | WAF and backend may pick different occurrences of a duplicated parameter |
| Content-type switch | Sending the same payload as XML/multipart instead of JSON | WAF rule coverage may be uneven across content types |
| Encoding variation | Single vs. double URL-encoding the payload | WAF and app may decode a different number of layers |

```bash
curl -s "https://target.com/search?q=UNI%2F%2A%2A%2FON%20SEL%2F%2A%2A%2FECT%201"
```
This sends the comment-insertion technique URL-encoded — `%2F%2A%2A%2F` decodes to
`/**/`. Test the unencoded version first; only add encoding if the raw characters
themselves are being blocked before reaching the parser stage.

## 7–8. Expected Output / Interpretation
A technique "working" means the request is no longer blocked by the filter layer —
**this still does not confirm a vulnerability**. You must still run the full
detection loop from `06-Vulnerability-Testing/` against the now-unblocked request
to actually confirm the underlying issue. Getting past a WAF is a means to test,
not itself a finding.

## 9. False Positives
- A technique "working" once and not reproducing consistently may indicate
  rate-limiting or WAF rule caching rather than a real evasion — repeat before
  concluding a technique is reliable.

## 10. Next Action
Immediately re-run the relevant `06-Vulnerability-Testing/` file's detection steps
against the now-unblocked request — don't stop at "bypass succeeded."

## 11. Safety Considerations
- Confirm program policy explicitly permits this before starting (see Section 2).
- Keep volume minimal — a handful of targeted attempts per technique category is
  enough to know if it works; this is not a step that benefits from brute-forcing
  every known encoding variant.
- If no technique works after a reasonable, documented attempt, that is itself a
  valid outcome to report: the filtering held, and testing of that specific input
  through that specific vector could not be completed. This is useful information
  for the program, not a failure to hide.

## 12. Documentation
Record every technique attempted, whether it succeeded in passing the filter, and
— separately and explicitly — whether the subsequent application-layer test
confirmed an actual vulnerability. These are two different facts and must not be
conflated in a report.
