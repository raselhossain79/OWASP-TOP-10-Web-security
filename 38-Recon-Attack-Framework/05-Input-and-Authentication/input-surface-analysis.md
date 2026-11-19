# Input Surface Analysis

## 1. Purpose
Build a complete, per-endpoint catalog of every place data enters the application,
so vulnerability testing is systematic rather than ad hoc.

## 2. When to Use
Once endpoints and parameters are mapped, before any vulnerability-class-specific
testing begins.

## 3. Prerequisites
Output from `04-Attack-Surface-Mapping/` (endpoints, parameters, API schema).

## 4. Methodology
For each endpoint, explicitly list:
- Query string parameters
- POST/PUT body fields (form-encoded, JSON, XML, multipart)
- Cookies read by the endpoint
- Custom headers the app reads (`X-Forwarded-For`, API key headers, custom
  tracking headers)
- File upload fields (filename, content-type, content, embedded metadata)
- WebSocket/SSE message fields, if applicable

## 5. Commands
```bash
# Capture a full request/response through a proxy to see everything sent
curl -s -v "https://target.com/profile?id=1" \
  -H "Cookie: session=abc123" 2>&1 | grep -E "^> |^< "
```
Realistically, this cataloging step is done primarily through a proxy tool (Burp
Suite / Caido) reviewing captured traffic while using the app normally — the
`curl -v` command above is a quick manual spot-check, not a replacement for
proxy-based traffic review across the whole app.

## 6. Command Breakdown
- `-v`: verbose mode prints the full request/response headers curl sends/receives.
- `grep -E "^> |^< "`: filters to just the lines curl prefixes with `>` (sent) and
  `<` (received), cutting out body noise for a quick header-focused look.

## 7. Expected Output
A table per endpoint, e.g.:

| Endpoint | Input | Location | Notes |
|---|---|---|---|
| `/profile` | `id` | query param | numeric, visible in URL |
| `/profile` | `session` | cookie | auth token |
| `/api/update` | `role` | JSON body | not shown in UI form, found via `parameter-discovery.md` |

## 8. Interpretation
This table is the direct input to `06-Vulnerability-Testing/` — each row is a
candidate for the generic test loop, per vulnerability class relevant to that
input's context (e.g. a numeric ID parameter is a natural IDOR candidate; a
free-text search field is a natural XSS/SQLi candidate).

## 9. False Positives
Not applicable at this stage — this is a cataloging step, not a detection step.

## 10. Next Action
Cross-reference each input against `authentication-mapping.md` and
`authorization-mapping.md` to know which inputs are reachable pre-auth vs.
require specific roles, before testing.

## 11. Safety Considerations
Purely observational if done by reviewing your own normal traffic through a proxy —
no additional requests needed beyond using the application as intended.

## 12. Documentation
Keep the per-endpoint input table as a living document — it's the master reference
the rest of the testing phase works from.
