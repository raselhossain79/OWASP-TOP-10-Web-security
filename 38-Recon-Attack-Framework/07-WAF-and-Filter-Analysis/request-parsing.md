# Request Parsing & Normalization Differences

## 1. Purpose
Explain the actual mechanism behind most filter-evasion techniques: a WAF and the
backend application each parse/normalize an HTTP request independently, and they
don't always agree on what the "real" content is. Evasion exploits the gap between
the two interpretations — it is not magic, and it does not work universally.

## 2. When to Use
Before attempting any specific bypass technique (`authorized-bypass-testing.md`) —
understanding *why* a technique might work tells you which ones are worth trying
against a specific target, rather than trying all of them blindly.

## 4. The Core Mechanism
A request passes through (at minimum) two parsers: the WAF's inspection engine,
and the application's own request/body parser. If they decode, case-normalize, or
interpret the same bytes differently, a payload can be "invisible" to the WAF's
check while still being "live" to the application.

Concrete mechanisms:
- **Encoding layers**: if the WAF inspects the raw request but the application
  decodes a layer of encoding the WAF didn't also decode (e.g. double URL-encoding,
  or an encoding the WAF doesn't unwrap at all), the WAF sees encoded-looking noise
  while the application sees the final decoded payload.
- **Case sensitivity**: a WAF signature written to match `UNION SELECT` literally
  may not match `uNiOn SeLeCt`, while SQL engines are generally case-insensitive
  for keywords — the WAF's rule is simply narrower than the thing it's trying to
  catch.
- **Whitespace/comment handling**: a WAF signature expecting a literal space
  between keywords won't match if a comment (`/**/`) or alternate whitespace
  character sits there instead, if the SQL engine still treats that as equivalent
  to a space.
- **Parameter precedence differences**: if a parameter is supplied twice, different
  web servers/frameworks pick the first, the last, or concatenate both —
  inconsistently from whatever the WAF chose to inspect.
- **Content-type assumptions**: a WAF ruleset tuned heavily for one content type
  (commonly JSON or form-encoded) may apply weaker or no inspection to a less
  common one (XML, multipart) that the backend framework still parses and acts on.

## 9. Important Limitation — This Is Not Universal
None of these gaps are guaranteed to exist on any given target. A well-maintained,
modern WAF (especially managed-rule or ML/behavioral products like current
Cloudflare or Akamai configurations) may normalize encoding, case, and whitespace
*before* signature matching specifically to close these gaps, and may also use
behavioral signals (request velocity, header fingerprinting) that classic payload
mutation does nothing to address. **Presenting any single bypass technique as
"the" way to beat a WAF is inaccurate — it depends entirely on how that specific
WAF, and that specific backend, each parse the request.**

## 10. Next Action
Use this understanding to choose which specific technique in
`authorized-bypass-testing.md` is worth trying first for a given target
(e.g. if the WAF is a known, well-maintained managed product, don't expect basic
case-swapping to work — look at content-type or parameter-pollution angles
instead, and expect that none of them may work).

## 12. Documentation
If a specific normalization gap is found to work, document *which* gap (encoding,
case, whitespace, content-type, parameter precedence) rather than just "bypass
worked" — this is useful both for the report and for understanding the target's
actual defensive posture.
