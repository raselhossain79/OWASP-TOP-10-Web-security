# Engagement Identification Checklist — A09: Security Logging and Monitoring Failures

## 1. Honest PortSwigger Web Security Academy Lab Coverage Note

**There is no dedicated "Logging and Monitoring" or "Log Injection" topic or lab category on PortSwigger Web Security Academy.** This was verified directly against the Academy's official topic index, which lists every category (SQL injection, XSS, CSRF, Clickjacking, CORS, XXE, SSRF, Request smuggling, Command injection, SSTI, Insecure deserialization, Path traversal, Access control, Authentication, OAuth, Business logic vulnerabilities, WebSockets, DOM-based, Web cache poisoning, HTTP Host header attacks, Information disclosure, File upload, JWT, Prototype pollution, GraphQL, API testing, Race conditions, NoSQL injection, Web cache deception, Web LLM attacks) — A09 is not among them, and no lab anywhere in the catalog is framed around log injection or logging/monitoring gaps as the learning objective.

This is consistent with the nature of the category: PortSwigger's labs are built around a single, demonstrable client-server vulnerability with a clear "lab solved" success condition. A09 doesn't fit that model because its core failure (logs not being reviewed, alerts not firing, SOC not responding) **isn't something a static lab environment can simulate** — there's no backend SOC to fail to notice you.

**Practical implication for your practice:** don't go looking for a "logging" lab category — it doesn't exist. Instead, two adjacent areas of the Academy are useful for building intuition relevant to this category:

- **Authentication** topic labs (particularly brute-force-related ones) are good practice for the *behavioral inference* technique described in Section 3 below — noticing whether an application implements (or fails to implement) lockouts, rate-limiting, or detectable anti-automation responses is directly transferable to spotting A09 gaps in a live engagement.
- **Information Disclosure** topic labs are useful for the inverse problem (CWE-532, sensitive data ending up somewhere it shouldn't, including potentially in logs) even though they're not framed as logging labs specifically.

If a future Academy update adds a dedicated category, re-verify before citing it elsewhere — this note reflects the catalog as it stands at the time of writing.

---

## 2. Pre-Engagement Scoping Questions (Ask Before Testing)

A09 findings are far stronger when scoping clarifies what visibility you'll actually have. Confirm with the client:

- [ ] Is this a black-box, grey-box, or assumed-breach engagement? (Black-box severely limits how much A09 testing you can directly evidence — most of it becomes inferential.)
- [ ] Will the client provide **any** visibility into their own logging/alerting during the test window (e.g. "did our SIEM page anyone during your test")? This is the single highest-value data point you can get for this category, and it's almost always more useful than anything you can observe from the outside.
- [ ] Is testing for log injection (file 02 techniques) in scope, given it can pollute the client's real log data?
- [ ] Are there any internal log-viewing dashboards in scope for direct testing (relevant to the log-viewer XSS technique)?

---

## 3. Active Testing Checklist (What You Can Actually Do, Black-Box or Grey-Box)

### 3.1 Behavioral / Inference Testing

- [ ] **Brute-force a login form for 20–50 attempts.** Does *anything* observable change — CAPTCHA appearing, account lockout, IP-based rate limiting, increasing response delay, a generic "too many attempts" message? No observable change after a sustained, obvious brute-force pattern is a strong signal that no detection/response mechanism exists on the authentication path.
- [ ] **Trigger an obvious access control violation** (e.g. attempt to access another user's resource by ID manipulation, or hit an admin-only endpoint as a low-privilege user) repeatedly. Does access get revoked, does the session get terminated, does anything change?
- [ ] **Send deliberately malformed/malicious input** (a basic SQLi probe like `'`, an XSS probe like `<script>`) across multiple endpoints in quick succession, simulating what an automated scanner's noise would look like, and see if the application's behavior changes (WAF block pages appearing, IP getting blocked, session getting killed).
- [ ] **Check for any client-visible indication of monitoring at all** — security headers like `Report-To`/`NEL` (Network Error Logging) that suggest some monitoring infrastructure exists, or error pages that reveal (intentionally or not) whether an incident was flagged.

### 3.2 Direct Evidence Testing (If Logs/Dashboards Are In-Scope)

- [ ] If you have any access to log output (e.g. assumed-breach engagement with internal access, or client provides log samples for review), check for:
  - Presence of authentication events (success **and** failure)
  - Presence of authorization/access-control failure events
  - Presence of source IP, timestamp, username/user ID, and outcome in each relevant entry
  - Whether high-value actions (password changes, privilege escalations, data exports) are logged at all
- [ ] Test the log injection techniques from file 02 against any endpoint whose input plausibly flows into a log (username fields, User-Agent, Referer, custom headers, search/query parameters) — **but confirm this is in scope first**, since it can pollute production log data.
- [ ] If a log viewer/dashboard is in scope, test the log-viewer XSS technique from file 02, section 4.

### 3.3 Sensitive Data in Logs (CWE-532, Inverse Check)

- [ ] If you get any log visibility, check the opposite failure mode too: are passwords, full credit card numbers, session tokens, or other sensitive fields appearing in plaintext in logs? This is technically a different CWE (532) but is commonly grouped with A09 findings in client-facing reports since it's also a "logging hygiene" issue.

### 3.4 Interview-Based Evidence (Grey-Box / Client Conversations)

- [ ] Ask directly: "Do you have a SIEM or centralized log aggregation in place?"
- [ ] Ask: "Was anyone on your security team alerted during our testing window?" (Compare against your own activity log/timeline — a complete lack of any alert against a sustained, noisy testing period is itself reportable evidence.)
- [ ] Ask about log retention policy — many compliance frameworks (PCI DSS specifically) mandate minimum retention periods (90 days hot, 1 year total is a common PCI baseline), and short or absent retention is a documented, citable gap.

---

## 4. How This Gets Evidenced in the Final Report

Since you usually can't show a single "exploit" screenshot for this category, structure the finding differently from a typical vulnerability writeup:

**Recommended report structure for an A09 finding:**

1. **Finding title**: Be specific about *which* failure mode, not just "A09 — Logging Failures." E.g. "Insufficient Authentication Event Logging and Alerting" or "Log Injection via Unsanitized User-Agent Header."
2. **Evidence**: Document your actual testing activity and timestamp it precisely (e.g. "Between 14:02 and 14:19 UTC, 47 failed login attempts were submitted against `/login` from a single source IP with no rate-limiting, lockout, or CAPTCHA observed"). The absence is the evidence — make the timeline explicit so it's falsifiable/verifiable by the client.
3. **Correlate with other findings**: Explicitly cross-reference other vulnerabilities found during the same engagement and state plainly how the logging gap amplifies their real-world risk — e.g. "The SQL Injection finding (Section X) combined with this logging gap means a real attacker exploiting that vulnerability would likely go undetected for an extended period."
4. **CWE reference**: Cite the specific CWE (778 for insufficient logging, 117 for log injection, 532 for sensitive data exposure in logs) rather than only the umbrella OWASP category.
5. **Compliance framing where relevant**: If the client is subject to PCI DSS, HIPAA, or SOC 2, note the specific control they're likely failing (e.g. "PCI DSS Requirement 10.2 mandates logging of all individual user access to cardholder data; this was not observed/confirmed during testing").
6. **Remediation**: Be concrete and avoid vague "improve your logging" language. Practical, industry-standard recommendations include:
   - Centralize logs to a SIEM (not just local files on the application server)
   - Log authentication success/failure, access control failures, and high-value transactions, each with timestamp, source IP, user identity, and outcome
   - Use structured logging (proper JSON serialization, not string concatenation — see file 02, section 3) to prevent injection
   - Define and test actual alert thresholds and response playbooks, not just log collection — collection without alerting doesn't close the gap
   - Set retention periods aligned to applicable compliance requirements

**Sample finding summary language (adapt, don't copy verbatim into a real report without client-specific detail):**

> During testing, 47 consecutive failed authentication attempts were submitted against the login endpoint over a 17-minute window with no observable rate-limiting, account lockout, or CAPTCHA challenge. The client confirmed no internal alert was triggered during this activity. This indicates an absence of effective authentication monitoring, meaning a real-world credential-stuffing or brute-force attack against this endpoint would likely go undetected. This finding directly amplifies the risk of any authentication-related vulnerability identified elsewhere in this report (see Section X).

---

## 5. Severity Framing Guidance

A09 findings are rarely "Critical" on their own (there's no direct compromise), but resist the temptation to default to "Low" either. Industry-standard practice (consistent with how CVSS-based and qualitative risk matrices are usually applied to this category) is to rate based on:

- **How severe the undetected scenario would be** — a logging gap on an admin authentication path is more severe than one on a low-value public endpoint.
- **Compliance exposure** — a confirmed gap against a mandatory control (e.g. PCI DSS 10.2) often justifies a higher severity than the technical impact alone would suggest, because it carries direct regulatory/business consequence.
- **Compounding effect on other findings** — as in the sample language above, explicitly note when this finding raises the real-world severity of other findings in the same report.

Most A09 findings land in the **Medium** range on their own, escalating to **High** when tied to a compliance-mandated control or when paired explicitly with another high-severity technical finding it would have hidden.
