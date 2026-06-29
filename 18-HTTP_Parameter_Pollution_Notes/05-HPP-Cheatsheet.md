# 05 — HTTP Parameter Pollution: Cheatsheet

## 1. The parsing table (the single most important reference in this series)

| Technology / Stack | `?id=1&id=2` resolves to | Behavior |
|---|---|---|
| ASP.NET / ASP Classic (IIS) | `1,2` | All, comma-joined |
| PHP (`$_GET`/`$_POST`) | `2` | Last value wins (`id[]=` syntax = array of all) |
| Node.js / Express (`qs` default parser) | `['1','2']` | All, as array |
| Python / Flask (`.get()`) | `1` | First value wins (`.getlist()` = all) |
| Python / Django (direct index) | `2` | Last value wins (`.getlist()` = all) |
| Java / Servlet containers (`getParameter()`) | `1` | First value wins (`getParameterValues()` = all) |
| Perl (CGI.pm) | `1,2` or array | Context-dependent |
| Ruby on Rails (Rack) | `2` | Last value wins (`id[]=` syntax = array) |
| Apache (as proxy) | passes both through | Unresolved at this layer |
| Nginx (as proxy) | passes both through | Unresolved at this layer |
| Typical WAF default rule sets | inspects `1` only | First value inspected |

**Rule of thumb when testing a black-box target:** if you can't fingerprint the stack, send
`?param=A&param=B` against a feature with observable output (reflection, error message, or
calculated value) and watch which value (`A`, `B`, both comma-joined, or both as array-derived
output) actually surfaces. That single test tells you which row of this table you're dealing
with — and therefore which technique below is worth trying.

## 2. Payload / probe library

| Goal | Payload pattern | What it tests |
|---|---|---|
| Detect duplicate-param resolution | `?param=marker1&param=marker2` | Which value surfaces in output |
| Bypass first-value-only WAF | `?param=benign&param=<payload>` | Filter inspects 1st, app executes 2nd (needs last-wins backend) |
| Bypass last-value-only filter | `?param=<payload>&param=benign` | Filter inspects last, app executes 1st (needs first-wins backend) |
| Truncate query string at fragment | `username=admin%23` (`#`) | Backend embeds input unsafely into a 2nd request's query string |
| Re-inject a parameter past truncation | `username=admin%23%26field=x` | Inject attacker-controlled sibling parameter into internal request |
| Detect path-segment placement | `username=admin%3F` (`?`) | Confirms input lands in URL path of a server-to-server request |
| Path-traversal probe | `./val`, then `../val`, then `../../../../#` | Walk out of intended internal API path to its root |
| Array-stacking abuse | `?code=X&code=X&code=X` | Backend iterates duplicates without dedup (Node/Express-style array binding) |
| OAuth redirect override | `redirect_uri=legit.com&redirect_uri=evil.com` | Authorization server vs. client app duplicate-handling mismatch |
| Built-in Burp wordlist | "Server-side variable names" payload list (Intruder) | Brute-force unknown internal field/param names once truncation is confirmed |

## 3. Detection checklist (run in this order on every target)

1. [ ] Identify the backend stack (headers, error pages, framework fingerprints) and look up
   its row in the parsing table above.
2. [ ] Send `?param=A&param=B` on a parameter with visible output. Confirm which resolution
   behavior matches the table.
3. [ ] If a WAF/CDN sits in front of the target, repeat the test with one clean value and one
   payload value in different orders. Confirm whether the WAF's inspected value differs from
   what the app executes (file `02`).
4. [ ] On any parameter controlling price, quantity, role, or discount: test duplication
   against both the validation step (if separately observable, e.g. a distinct API call) and
   the final persisted/charged value (file `03`).
5. [ ] On any feature that clearly proxies to a second, internal request (password reset,
   user lookup, search-to-API bridges): probe with `#`, `&`, `=`, and `../` per file `04`'s
   worked examples. Watch for changed error messages — that's your signal the backend
   recognized an injected parameter.
6. [ ] If step 5 succeeds, brute-force the internal field/parameter vocabulary with Burp
   Intruder before assuming a dead end.

## 4. PortSwigger Web Security Academy — full lab map for this series

| Sub-class | Academy lab(s) | Status |
|---|---|---|
| WAF / filter-bypass HPP (file `02`) | — | **No dedicated Academy lab.** Practice via personal WAF+backend test harness or real engagements/bug bounty. |
| Business logic HPP (file `03`) | — | **No dedicated Academy lab.** Price/role manipulation labs exist on the Academy but use other mechanisms (not duplicate-parameter precedence). Practice via a self-built two-service test harness. |
| Server-side parameter pollution (file `04`) | 1. Lab: Exploiting server-side parameter pollution in a query string 2. Lab: Exploiting server-side parameter pollution in a REST URL | **Fully covered**, both under API Testing → Server-side parameter pollution, in this exact order. |

## 5. One-paragraph summary for quick recall

HPP is not a single bug — it's what happens whenever two components in a request's path
disagree about which value wins when a parameter name repeats. Look up the relevant stacks in
the parsing table, find the disagreement, and then ask what that disagreement controls: a
security filter's blind spot (file `02`), a price/role/quantity decision (file `03`), or a
second request your app builds on the user's behalf (file `04` — the one with real, working
Academy labs). Every payload in this series is just a different syntactic way of forcing that
disagreement into the open.
