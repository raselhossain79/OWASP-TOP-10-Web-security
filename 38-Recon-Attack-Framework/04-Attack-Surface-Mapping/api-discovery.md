# API Discovery

> **Correction in this revision**: an exposed Swagger/OpenAPI file or enabled
> GraphQL introspection is **not, by itself, a vulnerability**. Both are common,
> often intentional (many APIs document themselves this way on purpose, including
> in production). Report them as a vulnerability only when you can demonstrate
> actual security impact — see Section 8 below.

## 1. Purpose
Map the REST/GraphQL/other API surface specifically — APIs often have a much larger
and less-documented attack surface than the visible web UI that calls them.

## 2. When to Use
Once JS analysis and endpoint discovery have surfaced API-shaped paths
(`/api/`, `/graphql`, `/v1/`, etc.).

## 3. Prerequisites
Candidate API base paths from `javascript-analysis.md` / `endpoint-discovery.md`.

## 4. Methodology
1. Check for self-documenting API specs first (Swagger/OpenAPI JSON, GraphQL
   introspection) — if exposed, this hands you the full schema directly.
2. If no spec is exposed, map manually by observing real requests the app makes
   (via a proxy) while using the application normally.
3. For GraphQL specifically, test whether introspection is enabled.

## 5. Commands
```bash
# Check for an exposed OpenAPI/Swagger definition
curl -s https://target.com/api/swagger.json
curl -s https://target.com/api/v1/openapi.json

# GraphQL introspection check
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'
```

## 6. Command Breakdown
- Swagger/OpenAPI paths are checked at common conventional locations first — if
  found, the returned JSON is a complete, documented map of every endpoint,
  parameter, and expected type the API exposes, which is far more reliable than
  any inferred/guessed mapping.
- The GraphQL query `{__schema{types{name}}}` asks the introspection system
  (enabled by default in many GraphQL server frameworks unless explicitly disabled)
  to list every type defined in the schema — a response with real type names
  confirms introspection is on and gives you the full schema to query further.

## 7. Expected Output
Either a full machine-readable API schema, or (if no spec is exposed) a manually
built list of endpoints/methods/parameters observed via proxy traffic while using
the app.

## 8. Interpretation — Do Not Report the Schema Itself as the Finding
An exposed schema is a **discovery tool**, not a finding. Before reporting
"Swagger exposed" or "GraphQL introspection enabled" as a vulnerability, confirm
actual impact:
- Does the schema document **genuinely internal/privileged endpoints** that are
  not meant to be reachable from outside the network you're testing from (and you
  can actually reach them)? That's an information-disclosure finding about the
  endpoints, not about introspection being "on."
- Does the schema reveal field names/mutations that materially shortcut other
  testing (e.g. a mutation name revealing an undocumented admin action)? Note it
  as attack-surface information that fed into a *separate* confirmed finding, not
  as a standalone issue.
- If neither applies — the schema just documents what a legitimate API consumer
  would already need to know to use the API as intended — this is not reportable
  on its own in most programs' scoring, since it's often an accepted/normal
  development practice. Many public APIs (and many bug bounty program policies)
  explicitly treat exposed API documentation as out-of-scope/informative-only.

## 9. False Positives
- A Swagger file describing an endpoint doesn't confirm that endpoint is still live
  or reachable from outside the network it was documented for (internal-only APIs
  sometimes get documented in a shared repo that also covers public-facing ones).

## 10. Next Action
Every documented/observed endpoint feeds into `input-surface-analysis.md` and then
`06-Vulnerability-Testing/` per input, same as any other discovered endpoint.

## 11. Safety Considerations
GraphQL introspection queries are read-only and low-risk. Treat a discovered
internal/undocumented API the same as any other newly found asset — check it
against scope before testing further.

## 12. Documentation
Save the raw schema/spec file if found — it's the most precise record of the API
surface at the time of testing.
