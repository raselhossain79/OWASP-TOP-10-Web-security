# 02 — Documented Real-World Chain Patterns

Each pattern below follows the same structure: **what bug A produces**, **how bug B
consumes it**, **the mechanism connecting them**, and **why the combination is more
severe than either bug alone**. These are documented patterns seen repeatedly across
public bug bounty writeups and pentest reports — they are categories of chain, not
one-off anecdotes, and you should expect variations of each on real targets.

---

## 1. IDOR + Broken Access Control → Full Account Takeover

**Bug A (IDOR):** An endpoint like `GET /api/users/{id}/profile` returns another
user's profile data when you change `{id}`, because the server checks "is this user
ID valid" but never checks "does the requesting session own this user ID."

**Bug B (Broken Access Control):** A separate endpoint, often
`POST /api/users/{id}/password-reset-token` or `PUT /api/users/{id}/email`, performs
the same missing-ownership-check mistake, but this time on a *state-changing* action
rather than a read.

**Mechanism:** The IDOR alone only leaks data — annoying, but bounded. The access
control flaw on the write endpoint is the actual primitive that matters: it lets you
target *any* user ID for a mutating action. The reason these two are described as a
chain rather than just "another IDOR" is that you typically need the read-IDOR first
to **enumerate valid user IDs and confirm which ones are high-value targets** (admin
accounts, finance team accounts) before spending your write-primitive on the right
target. In a real engagement you rarely get handed a target's internal user ID
numbering scheme — the read-IDOR is how you build that map.

**Resulting impact:** Set an arbitrary user's password, password-reset token, or
email address to one you control, then log in as them. Full account takeover.

---

## 2. SSRF + Cloud Metadata + Exposed Credentials → Cloud Account Compromise

**Bug A (SSRF):** An application feature that fetches a URL on the server's behalf
(image-from-URL upload, webhook tester, PDF-from-URL exporter, link preview generator)
doesn't restrict the target host.

**Bug B (Cloud metadata exposure):** Cloud providers expose an instance metadata
service on a link-local address — historically `http://169.254.169.254/` for AWS,
with equivalents for GCP and Azure — which is reachable *only* from inside the VM/
container and is **not supposed to require authentication from that vantage point**.

**Mechanism:** The SSRF gives you a way to make an HTTP request that originates from
inside the cloud environment, not from your machine. Pointing the SSRF at the
metadata endpoint (e.g. `http://169.254.169.254/latest/meta-data/iam/security-
credentials/<role-name>`) returns the temporary IAM credentials currently assigned to
that instance's role. AWS's IMDSv2 mitigation (requiring a `PUT`-issued session token
via a custom header before metadata reads succeed) blocks *naive* SSRF, but many SSRF
primitives — especially ones that let you control headers and HTTP method, such as a
webhook configuration field — can still complete the IMDSv2 handshake if the app
forwards arbitrary headers/methods to the target URL.

**Resulting impact:** The leaked temporary credentials can be used with the AWS/GCP/
Azure CLI to enumerate and access whatever resources the instance role is permitted
to touch — frequently S3 buckets, RDS connection strings stored in Secrets Manager, or
other internal services. This routinely escalates an SSRF rated "medium" in isolation
into a critical cloud-account-compromise finding.

---

## 3. Stored XSS + CSRF Token Theft → Full Account Takeover

**Bug A (Stored XSS):** A comment field, profile bio, or support-ticket message
stores attacker-controlled HTML/JS that executes in the context of any user (often
specifically an admin or support agent) who views it.

**Bug B (the "protected" action):** A sensitive action — change email, change
password, add an API key — is protected by a CSRF token, which would normally stop a
plain cross-site CSRF attack because the attacker's external page can't read the
victim's token.

**Mechanism:** CSRF tokens defend against an attacker acting *from a different
origin*. They do nothing against script that's already executing *on the
application's own origin*, because same-origin JavaScript can simply read the CSRF
token out of the page's DOM or a same-origin API response, then issue the protected
request itself with that token attached. The stored XSS is the delivery mechanism;
the CSRF token theft is just same-origin `fetch()` reading a value that was never
designed to be secret from same-origin code.

**Resulting impact:** The XSS payload silently reads the victim's CSRF token, then
fires an authenticated `POST` to the change-email or add-API-key endpoint, fully
compromising the account with no visible warning to the victim. This is why CSRF
tokens are described as defense against forgery, not defense against XSS — they were
never meant to be the second layer here, but in practice they're frequently the only
thing standing between stored XSS and full takeover, and that layer fails completely.

---

## 4. SQL Injection + File Write → Remote Code Execution

**Bug A (SQLi):** A classic injection point, often in a search or filter parameter,
confirmed via the standard boolean/time-based/error-based techniques from the SQLi
series.

**Bug B (file write primitive):** Many database engines expose a file-write function
when the connecting account has sufficient privilege — MySQL's `INTO OUTFILE`/
`INTO DUMPFILE`, MSSQL's `xp_cmdshell` (or writing via `OPENROWSET`/`BULK INSERT`
abuse), PostgreSQL's `COPY ... TO/FROM PROGRAM` (superuser-only) or large object
export.

**Mechanism:** SQLi alone gives you read access to the database and, depending on the
engine, the ability to run arbitrary SQL statements — but reading data is the
*injection bug's* native capability, not code execution. The chain step is using that
SQL execution capability to write a file **into a location the web server will
execute**, such as the document root, if the database process has filesystem write
permission to that path (commonly true on misconfigured shared-hosting style setups,
less common on properly segmented production database servers — this is itself
useful recon: if the write succeeds, it tells you about the deployment architecture).
A typical sequence: confirm injection → confirm `FILE` privilege on the DB account →
use `SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/uploads/
shell.php'` (MySQL syntax, exact path depends on recon) → request the dropped file to
execute commands as the web server user.

**Resulting impact:** SQLi escalates from "I can read your database" to "I can
execute arbitrary commands on your server," which is a different severity tier
entirely and typically the ceiling of web application impact.

---

## 5. SSTI → RCE

**Note:** unlike the other entries in this list, this is less a *chain of two
distinct bug classes* and more a direct escalation path within a single bug class —
included here because it's one of the most commonly underestimated severities in
triage and because understanding *why* it escalates is genuinely a chaining skill
(it's the same "what does this primitive let me reach" question).

**Bug A (SSTI):** User input is concatenated into a server-side template (Jinja2,
Twig, Freemarker, Velocity, etc.) before rendering, rather than being passed in as
template *data*.

**Mechanism:** A template engine's syntax isn't just string interpolation — it's
typically a constrained expression language with access to the engine's runtime
objects. In Jinja2, for example, confirming SSTI with `{{7*7}}` rendering `49`
demonstrates expression evaluation; from there, Python's object introspection lets you
walk from any object back to its base classes
(`{{ ''.__class__.__mro__[1].__subclasses__() }}`) to find a class that exposes
process execution (historically `subprocess.Popen` reachable via specific
subclasses), and call it with attacker-controlled arguments. Each template engine has
its own equivalent escalation path (Freemarker's `freemarker.template.utility.Execute`,
Twig's sandbox-escape gadgets), but the underlying mechanism is the same: the
"template expression" surface is really "a constrained scripting language with access
to the host language's object graph," and the chain is walking that object graph to a
command-execution primitive.

**Resulting impact:** Confirmed SSTI should be treated and reported as RCE-equivalent
even before you've built the full payload, because the escalation path exists for
essentially every major template engine — this is the single most common
"under-severity-rated" finding new hunters make.

---

## 6. Open Redirect + OAuth Misconfiguration (redirect_uri manipulation) → Account Takeover

**Bug A (Open Redirect):** A parameter like `?next=` or `?returnUrl=` redirects to an
attacker-controlled domain after some intermediate step, without validating that the
target stays on the same origin.

**Bug B (OAuth redirect_uri validation flaw):** The OAuth/OIDC identity provider (or
the relying party's OAuth client config) validates `redirect_uri` with a check that's
too loose — commonly prefix-matching (`https://app.example.com` matches
`https://app.example.com.attacker.com`) or allowing any path under a registered host
without validating query parameters, where that registered host happens to contain
the vulnerable open-redirect endpoint from Bug A.

**Mechanism:** OAuth authorization codes are single-use, short-lived tokens delivered
via redirect to whatever `redirect_uri` the identity provider considers valid for that
client. If the provider's validation allows `redirect_uri=https://app.example.com/
open-redirect-endpoint?next=https://attacker.com`, the attacker crafts an
authorization link, sends it to a victim, and when the victim authenticates, the
identity provider redirects to the *legitimate, registered* `app.example.com`
endpoint carrying the authorization code — which then immediately bounces the
victim's browser (carrying that code in the URL) to the attacker's domain via the
open redirect. The attacker's page captures the code from the URL and exchanges it
for an access token.

**Resulting impact:** The open redirect is what makes the loose `redirect_uri`
validation exploitable at all — without it, a loosely-validated `redirect_uri` that
still points only to *legitimate* application paths has nowhere useful to send the
stolen code. The two together produce a full account takeover via stolen OAuth
authorization code, without ever touching the victim's password.

---

## 7. Subdomain Takeover + Cookie Scoping → Session Hijacking

**Bug A (Subdomain Takeover):** A DNS record (commonly a `CNAME`) points to a
third-party service (cloud storage bucket, PaaS app, CDN endpoint) that has been
decommissioned, leaving the DNS entry dangling. Registering the same resource name on
the third-party service lets an attacker serve content from the organization's own
subdomain.

**Bug B (Cookie scoping):** The application sets its session cookie with a broad
`Domain` attribute — e.g. `Domain=.example.com` instead of scoping it to
`app.example.com` — so the cookie is sent to *every* subdomain of `example.com`,
including the abandoned one.

**Mechanism:** Cookie scoping via the `Domain` attribute is opt-in *broadening*: by
default a cookie is scoped only to the exact host that set it, but setting
`Domain=.example.com` explicitly tells the browser to attach that cookie to requests
for any subdomain. Combined with the takeover, the attacker now controls a page
served from `forgotten.example.com` that receives the victim's session cookie on any
request, simply because the browser doesn't distinguish "subdomain we still control"
from "subdomain an attacker now controls" — it only checks the domain string.

**Resulting impact:** An attacker-controlled page on the takeover subdomain can read
or exfiltrate the session cookie (if not `HttpOnly`) directly, or — even if
`HttpOnly` is set — can still trigger same-site authenticated requests using the
victim's session, since the cookie is attached automatically by the browser
regardless of script access. Severity depends on cookie flags, but the takeover alone
is frequently under-rated until the scoping issue is identified and the path to
session hijacking is made explicit.

---

## 8. File Upload + LFI → Remote Code Execution

**Bug A (File Upload):** An upload feature accepts attacker-controlled file content,
even if it restricts the *extension* (e.g. blocks `.php` but allows `.jpg`, `.png`,
`.txt`) and stores the file somewhere on disk, often outside the web root or with
execution disabled at that path specifically.

**Bug B (LFI):** A separate, unrelated feature includes a local file by path based on
user input — a template-selection parameter, a "load report" feature, a language-file
selector — and that inclusion is vulnerable to path traversal or direct path control.

**Mechanism:** Neither bug is sufficient alone. The upload alone can't execute code
if the upload directory isn't web-accessible or doesn't have script execution enabled.
The LFI alone is "only" a local file *read* in most contexts — but many LFI
primitives are actually *local file include*, meaning the included file's content is
*executed* (not just displayed) if it's a server-side script in a language the
LFI-vulnerable function can interpret (PHP's `include()`/`require()` being the classic
case). The chain: upload a file containing PHP code disguised with an allowed
extension or content-type (or exploit a weaker upload filter that only checks MIME
type, not content), note the file's stored path (directly returned by the app, or
inferred/brute-forced), then use the LFI to `include` that uploaded file by path. The
LFI vulnerability is what executes content the upload feature merely stored inertly.

**Resulting impact:** Full RCE, combining two findings that are each often rated
medium in isolation (a content-type-only upload filter; a local file inclusion
without obvious immediate impact) into a critical.

---

## 9. HTTP Request Smuggling + Web Cache Poisoning → Mass Client-Side Compromise

**Bug A (Request Smuggling):** A discrepancy between how a front-end proxy/CDN and
the back-end server parse the boundary of an HTTP request (`Content-Length` vs.
`Transfer-Encoding` disagreement, or more subtle parsing-quirk variants) lets you
smuggle a second, hidden request that the back-end processes as if it were the start
of the *next* user's request.

**Bug B (Web Cache Poisoning):** The front-end cache keys responses on a subset of
the request (typically just the URL path), while the *origin's* response can vary
based on headers the cache doesn't include in its key (such as `X-Forwarded-Host` or
a custom header reflected into the response).

**Mechanism:** On their own, request smuggling without a cache layer mostly lets you
desync individual requests/responses for whichever connections happen to be
multiplexed behind you — disruptive, but limited blast radius. Cache poisoning
without smuggling requires you to find a header the *cache ignores but the origin
uses*, which not every target has. Combined: smuggling lets you prepend a malicious
request that the back-end will respond to in a way that gets cached — and because the
smuggled request rides on the connection used for many other users' subsequent
requests, the poisoned, attacker-controlled response gets written into the shared
cache under a URL path that *every visitor* subsequently requests. From that point
forward, the cache itself serves the malicious response (e.g. one containing an
injected `<script>` payload) to every visitor of that path, with zero further action
from the attacker per victim.

**Resulting impact:** A single exploitation attempt poisons a cache entry served to
every subsequent visitor of that URL — this is the mechanism behind several
disclosed mass-XSS-via-cache incidents, and it's rated critical specifically because
impact scales with cache traffic rather than per-victim attacker effort.

---

## 10. Race Condition + Business Logic Flaw → Multiple Redemption / Fund Duplication

**Bug A (Race Condition):** An action that should be "check balance/eligibility, then
deduct/consume" is implemented as two separate steps without a database-level lock or
atomic transaction, leaving a window (a TOCTOU — time-of-check to time-of-use gap)
where the check and the consumption aren't synchronized.

**Bug B (Business Logic Flaw):** The deducted resource — coupon use count, account
balance, rate-limited action count — has no secondary, idempotency-key-based or
database-constraint-based safeguard.

**Mechanism:** Sending a single request to a vulnerable "redeem coupon" or "withdraw
funds" endpoint is harmless — the check-then-use logic works correctly under normal
sequential load. The race condition becomes exploitable specifically because an
attacker can send many copies of the same request **concurrently** (using HTTP/2
single-packet attack techniques, or simple thread-parallel requests), so that
multiple requests pass the "check" step (e.g. "is the coupon still valid / is balance
sufficient") *before any of them has completed the "use" step that would normally
invalidate it for the next check*. Each parallel request independently sees a valid
pre-consumption state.

**Resulting impact:** A coupon meant for single use is redeemed N times in the
concurrent window; a withdrawal meant to be capped at account balance withdraws
multiples of that balance. This is described as a chain with "business logic" rather
than a pure race condition write-up because the *severity* depends entirely on what
the consumed resource is — a race condition on a non-financial, non-limited action is
a curiosity; the same race condition on a funds-transfer or coupon-redemption endpoint
is directly monetizable, which is the business-logic half of the analysis a report
needs to make explicit.

---

## 11. Mass Assignment + Missing Access Control → Privilege Escalation to Admin

**Bug A (Mass Assignment):** An API endpoint (commonly a profile-update or
registration endpoint) binds the entire request body directly to an internal data
model/ORM object, rather than allowlisting specific fields — so sending an unexpected
field like `"role": "admin"` or `"isAdmin": true` in the JSON body gets persisted even
though the UI never exposes that field.

**Bug B (Missing Access Control on the field itself):** The backend has no
server-side check preventing a non-admin-authenticated request from setting a
privilege-related field, because the assumption was that the *UI* simply doesn't show
that input — security relying on obscurity of the form rather than enforcement at the
data layer.

**Mechanism:** These are frequently described as a single bug ("mass assignment to
privilege escalation") rather than two distinct ones, but it's worth separating them
because the *fix* and the *discovery method* differ: discovering the mass-assignment
behavior (does the endpoint accept and persist unexpected fields at all?) is step
one, typically found by diffing the documented/UI-visible request body against a body
with extra guessed fields appended, often informed by field names leaked elsewhere
(API docs, JS bundle inspection, error messages naming internal model fields).
Confirming that the *specific* extra field you control has no separate authorization
check is step two — some apps accept arbitrary extra fields harmlessly (ORM ignores
unknown fields) but specifically guard privilege fields with a role check; others
don't guard anything.

**Resulting impact:** A standard "update my profile" request, sent by any
authenticated low-privilege user, silently grants that user admin role — a full
privilege escalation from a feature that looks entirely benign in the UI.

---

## 12. CORS Misconfiguration + Authenticated Endpoint → Cross-Origin Token/Session Theft

**Bug A (CORS Misconfiguration):** The server reflects the requesting `Origin`
header back in `Access-Control-Allow-Origin` (instead of validating it against an
allowlist) and sets `Access-Control-Allow-Credentials: true`.

**Bug B (Authenticated, sensitive-data-returning endpoint):** Any endpoint that
returns sensitive data — an API key, account details, a CSRF token, a session-bound
object — when called with the victim's existing session cookie.

**Mechanism:** Same-origin policy is the default browser protection that the CORS
misconfiguration disables for this specific combination: with
`Access-Control-Allow-Credentials: true` and a reflected `Origin`, the browser will
allow a script on the *attacker's* origin to make a `fetch()`/`XHR` request to the
target's API **with the victim's cookies attached** (since `credentials: 'include'` is
permitted), and — critically — will let the attacker's JavaScript **read the
response body**, which a same-origin-policy-respecting cross-origin request would
normally block from being read even if the request itself succeeded. The
misconfiguration doesn't create new server behavior; it removes the browser-side
read restriction on a response that already contained sensitive, session-bound data.

**Resulting impact:** A victim simply visiting an attacker-controlled page (no click
needed) results in the attacker's script silently fetching the victim's sensitive
endpoint data and exfiltrating it — the CORS misconfiguration is the entire
vulnerability here; the "second bug" is really just "the app has any authenticated
endpoint with sensitive data," which is true of nearly every application, which is
why this misconfiguration is rated so consistently high.

---

## 13. Host Header Injection + Password Reset → Full Account Takeover via Poisoned Reset Link

**Bug A (Host Header Injection):** The application builds absolute URLs (including
the password-reset link emailed to users) using the `Host` header from the incoming
request rather than a hardcoded, server-side-configured domain.

**Bug B (Password Reset Flow):** The reset email contains a clickable link with a
reset token, generated by and trusted by the application.

**Mechanism:** Requesting a password reset for a victim's email address while sending
a forged `Host` header (or `X-Forwarded-Host`, depending on which header the app
trusts when behind a proxy) causes the application to build the reset link using the
attacker's domain instead of its own — e.g.
`https://attacker.com/reset?token=<valid-token-for-victim>` — and email that link to
the *actual victim*. If the victim clicks the link (it appears to come from the
legitimate service's email template, so it's far more convincing than a generic
phishing link), the valid reset token is sent in the request to the attacker's
server, where the attacker captures it from their own access logs.

**Resulting impact:** The attacker now holds a valid password-reset token for the
victim's account without ever needing the victim to enter credentials anywhere — they
replay the captured token against the real application's reset-completion endpoint
and set a new password. This is a clean illustration of why Host header trust is
dangerous: the vulnerability isn't in the password reset logic at all, it's in a
completely separate piece of URL-building logic that the reset flow happens to depend
on.

---

## 14. Clickjacking + Sensitive State-Changing Action → Forced Action via Session Riding

**Bug A (Clickjacking):** A sensitive page (e.g. "confirm withdrawal," "change
account email," "approve API key request") is missing `X-Frame-Options`/
`frame-ancestors` protections and can be loaded inside an invisible iframe on an
attacker's page.

**Bug B (the underlying state-changing action):** The action itself only requires the
victim's existing authenticated session (cookie-based auth with no re-authentication
or step-up confirmation) — there is no CSRF token requirement *or* there is a CSRF
token requirement, but the clickjacking still allows interaction with the legitimate
page's own form, so the legitimately-set token is submitted along with the click,
since the user is genuinely interacting with the real page — just hidden.

**Mechanism:** A reflected/stored CSRF token defends against *forged* cross-origin
requests, but clickjacking doesn't forge a request — it tricks the victim into
*genuinely* submitting the real form on the real origin, just visually disguised
underneath attacker-controlled bait content (a "claim your prize" button precisely
overlaid on the real "confirm" button, with the iframe's opacity set near zero). Because
the actual click lands on the real page, in the real origin, with the real session and
the real CSRF token already present in that page's DOM, none of the request-forgery
defenses apply — the request isn't forged, it's coerced.

**Resulting impact:** The victim, believing they clicked something benign, has
actually executed a sensitive authenticated action (fund transfer confirmation, email
change, permission grant) on their own real account. The combination is specifically
dangerous on *exactly* the actions CSRF tokens are usually relied on to fully protect,
which is why missing frame protections on sensitive pages should always be evaluated
against what specific action sits behind that page, not treated as a generic low-
severity finding.

---

## How to use this catalog on a live target

Don't treat this as a checklist to test top-to-bottom in isolation. Treat it as a
reference for the *shape* of a chain once you've found an individual bug: when you
confirm any bug class, ask "which row in this table has this bug class as 'Bug A,'
and does this target have anything resembling the corresponding 'Bug B' nearby?" File
`03` covers how to build the attack-surface map that makes spotting these adjacent
pieces possible in the first place.
