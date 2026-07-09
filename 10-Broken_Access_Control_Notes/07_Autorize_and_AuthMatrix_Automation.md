# Autorize and AuthMatrix — Automated Access Control Testing

## 1. Why These Are the "Automation Tool" for This Category

Every other OWASP injection category in this note library has a natural automation tool (sqlmap for SQLi, tplmap for SSTI, XXEinjector for XXE, NoSQLMap for NoSQL, commix for command injection) because those vulnerability classes have a detectable *signal*: an error, a timing difference, a reflected payload. Access control vulnerabilities have no such universal signal — a successful IDOR or privilege escalation returns a perfectly well-formed `200 OK` with legitimate-looking data. The only way to detect it programmatically is to **replay the same request under a different identity and compare the results.** That comparison, done by hand, is exactly what a manual tester does when chasing IDOR — and it's exactly what **Autorize** and **AuthMatrix** automate, at the scale of an entire Burp proxy history instead of one request at a time.

Both are free Burp Suite extensions (installed via the BApp Store, available in Burp Community and Professional).

## 2. Autorize — Continuous, Passive Authorization Testing

### 2.1 What It Does

Autorize sits passively in Burp and watches every request that flows through the proxy while you browse the application normally as a **high-privilege user**. For each request it sees, it automatically re-sends that exact request — same method, same path, same parameters — but swaps in a **lower-privilege session token** that you configured ahead of time. It then compares the original (authorized) response against the replayed (unauthorized) response and flags whether the unauthorized replay returned substantially the same content.

### 2.2 Setup, Piece-by-Piece

1. **Capture a low-privilege session token.** Log in as the lower-privileged test account (e.g. PortSwigger's `wiener`) in a separate browser session or incognito window, and copy that session's cookie value from Burp's proxy history.
   - *Why this matters:* this token is what Autorize will substitute into every request it replays. If you copy a stale or already-logged-out token, every replay will correctly fail authorization for the trivial reason that the session itself is dead — producing false positives where everything looks "protected" because nothing was actually re-authenticated as the low-priv user.
2. **Paste that token into Autorize's configuration tab**, in the header/cookie field it asks for (typically the `Cookie` header, replacing the `session=` value).
3. **Browse the application as the high-privilege user** (e.g. `administrator`) through Burp's proxy, normally, clicking through every page and feature you want covered.
4. Autorize intercepts each request **after** it's sent by the high-privilege browser, and fires a second, modified copy of it using the low-privilege cookie configured in step 2.

### 2.3 Reading the Results

Autorize categorizes each replayed pair into a color-coded verdict:

- **Bypassed (red)** — the low-privilege replay returned a response substantially similar to the original high-privilege response. This is the actual finding: the endpoint did not differentiate between the two privilege levels, meaning **no authorization check is enforced** on it.
- **Enforced (green)** — the low-privilege replay returned a meaningfully different response (e.g. a `403`, a redirect to login, an empty/error body). Authorization is working correctly here.
- **Is enforced?? (yellow / needs manual review)** — Autorize's similarity comparison (by default, response length and a content-similarity heuristic) couldn't confidently classify the pair. This bucket needs **human eyes** — automated similarity scoring can't tell the difference between "same data, correctly blocked" pages that happen to share boilerplate structure (e.g. both a denial page and a real result page using the same site template/header/footer).

### 2.4 Why the "Yellow" Bucket Is the Most Important One to Understand

This is the single most common practical mistake when using Autorize: trusting the red/green buckets completely and ignoring yellow. In real applications, a denial page and a legitimate response frequently share enough HTML structure (navigation bars, footers, CSS includes) that a naive content-length or fuzzy-match comparison can misclassify either direction — flagging a real vulnerability as "enforced" because the deny page happened to be a similar size, or flagging a correctly-protected endpoint as "bypassed" because of shared boilerplate. **Always manually inspect at least the yellow-bucketed results, and spot-check a sample of green results on any endpoint that returns data you'd consider sensitive** — Autorize accelerates testing across hundreds of endpoints; it doesn't replace judgment on any individual one.

### 2.5 Real-World Workflow

In an actual engagement, the typical Autorize workflow is: log in as the highest-privilege test account the client has provisioned, click through the *entire* application surface area once with Autorize running (every CRUD operation, every admin function, every report/export), then export Autorize's findings and manually verify each red and yellow result with a manual Repeater request before including it in the report. This turns what would be days of manual endpoint-by-endpoint testing into a single guided pass.

## 3. AuthMatrix — Structured, Role-Matrix Testing

### 3.1 What It Does Differently

Where Autorize works passively and compares exactly two privilege levels (the high-priv session you're browsing with, and the low-priv session you configured), **AuthMatrix** is built for testing **more than two roles at once**, in a structured grid: you define a list of users/roles (e.g. `unauthenticated`, `standard user`, `manager`, `admin`), a list of requests (pulled directly from Burp's history or Repeater), and AuthMatrix replays **every request under every role**, producing a matrix of pass/fail results — much closer to a formal role-based access control (RBAC) test matrix that a professional report would actually document.

### 3.2 Setup, Piece-by-Piece

1. **Define users.** In the AuthMatrix "Users" tab, add an entry per role you want to test, each with its own authentication mechanism — typically the `Cookie` header value for that role's session, but it also supports custom headers (useful for token-based/JWT auth where the credential isn't a cookie at all).
2. **Add requests.** Send the requests you want tested (one per distinct endpoint/action) to AuthMatrix from Burp's proxy history or Repeater — these become the matrix's rows.
3. **Tag expected results.** For each request/role combination, mark in the grid whether that role is *supposed* to succeed (✓) or *supposed* to be denied (✗) according to the application's intended design. This step is what elevates AuthMatrix above simple replay-and-diff — you're encoding the actual authorization policy you expect, not just looking for "different responses."
4. **Run the matrix.** AuthMatrix substitutes each configured user's credential into each configured request in turn and checks the actual response against your tagged expectation.

### 3.3 Reading the Results

- A cell where the **actual result matches the expected tag** is shown as a pass (the access control is working as designed for that role/endpoint pair).
- A cell where the actual result **contradicts the expected tag** — most critically, a role marked "should be denied" that actually **succeeded** — is the finding. This is functionally the same underlying signal as Autorize's "Bypassed," but presented per-role across an arbitrary number of roles rather than just one low-priv vs. one high-priv comparison.
- AuthMatrix uses configurable **response matchers** (status code, a regex against the body, response length) to determine success/failure programmatically per cell, so getting these matchers right for the specific application is essential — the same false-positive/false-negative caution from the Autorize section applies here, just configured explicitly instead of inferred heuristically.

### 3.4 When to Use Which Tool

| Situation | Better fit |
|---|---|
| Quick sweep of an entire app with just two privilege levels (e.g. "user" vs "admin") | **Autorize** — passive, near zero setup beyond one cookie |
| Formal RBAC test matrix needed for a client deliverable, 3+ distinct roles | **AuthMatrix** — explicit, structured, exportable as a real matrix |
| Token-based auth (JWT in an `Authorization` header rather than a cookie) | **AuthMatrix** — first-class support for arbitrary auth headers per user |
| You're browsing the app live and want continuous background checking as you go | **Autorize** |
| You already have a fixed set of specific requests you want re-verified after a fix | **AuthMatrix** — re-run the same matrix to confirm remediation |

## 4. Limitations of Both Tools (Apply Judgment, Not Just Automation)

- Neither tool understands **business logic context** — they detect "did this role get a similar/successful response," not "is this response actually the correct data for this user." A response that returns *different but still sensitive* data (e.g. a different victim's record instead of the original one) can be missed if it doesn't trigger the similarity/match heuristic.
- Neither tool tests **multi-step process abuse** (file 6) automatically unless you specifically capture and add the final, action-performing request of that flow as one of the tested requests — they replay exactly what you give them, nothing more.
- Both depend entirely on the quality of the credentials you configure — an expired or wrong session for any role silently produces misleading "enforced" results for that role across the board.
- Neither replaces manually reading the actual response bodies for high-impact endpoints before reporting a finding as confirmed.

## 5. Real-World Notes

- These extensions are why access control testing has shifted, in modern penetration testing practice, from "manually try changing one ID at a time" to "browse once as an admin, let the tool cross-test every captured request against every other role automatically." This is the standard methodology expected at the BSCP/OSWE level and in any professional web-app engagement with a defined RBAC model to verify.
- Both tools are free and install directly from Burp's BApp Store (`Extensions` tab → `BApp Store` → search "Autorize" / "AuthMatrix") — no separate download or license needed beyond Burp itself.
