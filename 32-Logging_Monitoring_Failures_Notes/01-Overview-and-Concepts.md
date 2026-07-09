# A09:2021 — Security Logging and Monitoring Failures

## 1. What This Category Actually Is

A09 is different from almost every other category in the OWASP Top 10. SQL Injection, XSS, SSRF, and Insecure Deserialization are all about a vulnerability that lets you **do** something — extract data, execute code, forge requests. A09 is not that. A09 is about an organization's inability to **detect, record, and respond** to the fact that any of those other categories were exploited in the first place.

This makes A09 a **meta-category**. It does not describe a single flaw in a single endpoint. It describes a systemic gap in the application and infrastructure's defensive posture: if an attacker did everything else on this list, would anyone know? Could anyone reconstruct what happened?

OWASP's official description ties A09 to three failure modes:

- **Auditable events are not logged** (logins, failed logins, high-value transactions, access control failures).
- **Logs are stored only locally**, are not monitored, or warnings/errors produce no actionable alert.
- **Logs and alerts are not integrated** with active monitoring (SIEM, IDS/IPS) so detection and response times effectively become infinite.

## 2. Why It's in the Top 10 at All

This category exists in the Top 10 because of a recurring pattern in real breach timelines, not because of a clever exploit technique. The pattern industry incident response reports keep surfacing is: initial compromise happens fast (minutes to hours), but **detection** of that compromise takes days, weeks, or months — and in a large share of cases the organization didn't find out from their own monitoring stack at all. They found out from a third party: a customer noticing fraudulent charges, a security researcher, a ransomware note, or law enforcement.

Verizon's annual Data Breach Investigations Report and Mandiant's M-Trends report have tracked this "detection deficit" for years. The numbers shift year to year, but the structural finding is stable: **time-to-detect is consistently and dramatically longer than time-to-compromise.** That gap is exactly what A09 is naming.

From a pentester's perspective, this matters because:

- A weak logging/monitoring posture **multiplies the real-world impact** of every other finding in your report. A SQLi finding rated "High" in a well-monitored environment might realistically be contained in minutes. The same SQLi in an environment with no monitoring could mean unlimited dwell time for a real attacker. You should be explicitly stating this relationship in your reports (see file 03).
- Clients increasingly ask for it directly because of **compliance pressure** — PCI DSS Requirement 10, HIPAA's audit control requirements, SOC 2 CC7.2, and ISO 27001 Annex A.8.15/8.16 all mandate logging and monitoring controls. A pentest that ignores A09 leaves an obvious compliance gap unflagged.

## 3. Why A09 Is (Almost) Never "Exploitable"

You cannot send a payload that "exploits" a missing log entry. There is no request that turns "logging is insufficient" into remote code execution. This is the single most important mental shift for testing this category:

> **A09 findings are evidenced through absence, inference, and correlation — not through a single proof-of-concept request.**

Concretely, this means:

- You don't prove A09 with one HTTP request and one response. You prove it by **doing things that should generate a log entry or an alert, and then showing that nothing was recorded, nothing alerted, or — if you have visibility into logs as part of the engagement scope — that the entry is missing critical fields** (who, what, when, source IP, outcome).
- The "techniques" in file 02 of this series (log injection) are a **related but distinct** sub-problem: they're about attacking the integrity of logs that *do* exist, by injecting malicious content into them. They are not how you prove logging is *absent*.
- Most A09 findings in real pentest reports come from a combination of: black-box behavioral testing (does the app behave differently after suspicious activity, e.g. account lockouts, IP blocking, CAPTCHA triggers — none of these things happening is itself a signal), direct questions to the client/blue team during a grey-box or assumed-breach engagement, and architecture/config review (if you get any infrastructure access or documentation).

## 4. Related CWEs

A09:2021 maps to a cluster of related CWEs rather than one single weakness:

- **CWE-778**: Insufficient Logging
- **CWE-117**: Improper Output Neutralization for Logs (this is the CWE behind log injection — file 02)
- **CWE-223**: Omission of Security-relevant Information
- **CWE-532**: Insertion of Sensitive Information into Log File (a closely related but inverse problem — logging *too much*, e.g. passwords or tokens in plaintext logs)

Knowing these CWE numbers matters for reporting — clients and compliance auditors often want CWE references next to each finding, and citing CWE-778 for "no logging" versus CWE-117 for "log injection" versus CWE-532 for "sensitive data in logs" makes clear you're not just bundling everything under one vague label.

## 5. Real-World Industry Notes

- **SIEM coverage gaps are the norm, not the exception.** In real engagements, you'll frequently find that an organization has a SIEM (Splunk, Sentinel, Elastic, QRadar) but the *application layer* isn't actually feeding it anything useful — only infrastructure/OS logs are ingested. The web application's own authentication and authorization events never make it into the pipeline. This is one of the most common A09 findings in practice.
- **Alert fatigue is a documented secondary failure.** Even when logging and alerting exist, SOC teams drowning in low-fidelity alerts will miss the real one. If you can establish during an engagement (e.g. via client interview) that alert volume is extremely high and triage is inconsistent, that's a legitimate A09-adjacent observation worth noting, even though it's organizational rather than technical.
- **Cloud-native environments add a specific failure mode**: logging defaults that are *opt-in* rather than *opt-out*. AWS CloudTrail, Azure Activity Log, and GCP Cloud Audit Logs are often left at default retention/scope, missing data-plane events (e.g. S3 object-level access) unless explicitly enabled. This is a frequent finding in cloud-focused pentests and is directly relevant to A09 when application logs are stored in or alongside cloud infrastructure.
- **Log4Shell (CVE-2021-44228, December 2021)** is the most cited real-world incident tying logging directly to catastrophic impact — but note carefully what it actually was: a **JNDI lookup vulnerability in the Log4j library's message-parsing logic**, not a generic "logging is insufficient" issue. It belongs more precisely under A06 (Vulnerable and Outdated Components) than A09, though it's frequently (and loosely) cited in A09 discussions because the entry point was an attacker-controlled string flowing into a logging call. We mention it here for completeness and will reference it again briefly in file 02 with the correct framing — don't misattribute it as a pure A09 case in a report.

## 6. What Comes Next in This Series

- **File 02 — Log Injection Techniques**: CRLF/log forging, terminal escape sequence injection, structured-log (JSON) breakout, and log-viewer XSS. These attack the *integrity* of logs that exist.
- **File 03 — Engagement Identification Checklist**: the practical, step-by-step methodology for evidencing A09 as a finding during a pentest, including the honest PortSwigger Academy lab-coverage note and sample reporting language.
