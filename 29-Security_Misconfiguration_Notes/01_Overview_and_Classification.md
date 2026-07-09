# 01 — Overview and Classification: Security Misconfiguration (OWASP A05:2021)

## What is Security Misconfiguration?

Security Misconfiguration occurs when a system, application, framework, server, or cloud
service is deployed with settings that are insecure, incomplete, default, or simply wrong —
not because of a coding flaw in the traditional sense (like a missing input sanitizer), but
because of a **configuration decision, or the absence of one**.

This is what separates A05:2021 from categories like Injection (A03) or Broken Access Control
(A01): a misconfiguration is rarely a single line of vulnerable code. It is usually a setting
left at its insecure factory default, a feature that was never turned off after testing, or a
control that was simply never turned on.

OWASP's official definition groups several distinct failure modes under this single category.
Because the category is broad, this series breaks it into **seven concrete, testable
sub-categories** (with XXE deliberately excluded — see the README scope note):

1. Default credentials
2. Unnecessary features, services, and components enabled
3. Verbose error messages and stack traces
4. Missing or misconfigured security headers
5. Directory listing exposure
6. Cloud storage and infrastructure misconfiguration (S3 buckets, IAM, etc.)
7. CORS misconfiguration

## Why Security Misconfiguration ranks where it does

OWASP's 2021 data showed Security Misconfiguration present in **90% of applications tested**,
with an average incidence rate around 4%, and over 208,000 occurrences of related CWEs across
the dataset used to build the Top 10. The category moved from position 6 (2017) to position 5
(2021), reflecting the shift toward highly configurable cloud infrastructure, containerized
deployments, and microservices — every one of which multiplies the number of settings that can
be left insecure.

### Why it's so common in practice

- **Configuration sprawl.** A modern web stack involves a reverse proxy, an application server,
  a framework, a database, a cache layer, a cloud storage bucket, an orchestration layer
  (Kubernetes/Docker), and a CDN — each with its own settings surface.
- **Default-insecure by design.** Many technologies ship with verbose debugging enabled, sample
  applications installed, or permissive CORS/headers, because the vendor optimizes the default
  experience for "it works out of the box during development," not "it is secure in production."
- **Configuration drift.** Settings that were correct at deployment time degrade over months as
  patches, plugins, and quick fixes are applied without re-auditing the security baseline.
- **No single owner.** Headers might be a DevOps concern, IAM might be a cloud team concern, and
  error verbosity might be a developer concern — misconfiguration often exists in the gaps between
  teams.

## Classification Taxonomy (for engagement triage)

When you encounter a misconfiguration finding during a pentest or bug bounty hunt, classify it
along these dimensions before deciding how to report it — this is the same triage logic
professional pentest reports use:

| Dimension | Questions to ask |
|---|---|
| **Exposure surface** | Is this externally reachable, or only visible from an internal network/VPN? |
| **Authentication requirement** | Does exploiting it require valid credentials, or is it pre-auth? |
| **Direct vs. enabling impact** | Does the misconfiguration directly expose sensitive data (e.g., an open S3 bucket with PII), or does it merely *enable* a further attack (e.g., a verbose stack trace revealing a vulnerable framework version)? |
| **Chainability** | Can this be combined with another low-severity finding to produce a high-severity outcome? (This is the most common real-world pattern — see "Chaining" below.) |
| **Persistence** | Is this a one-off oversight, or does it indicate a systemic process failure (e.g., no header policy, no IaC review)? |

### Chaining — the most important real-world pattern

Individually, many misconfiguration findings look "informational" or low severity:

- A verbose error reveals the backend framework is Express 4.16.x.
- A misconfigured CORS policy reflects an arbitrary `Origin` header.
- An S3 bucket is publicly listable but contains only "old" log files.

In isolation, each of these might earn a low CVSS score. In combination, they routinely produce
critical findings:

> Verbose error discloses framework + version → public CVE database search finds a known RCE for
> that version → exploited because the same misconfigured server also has directory listing
> enabled, letting the attacker confirm the exact deployed file structure before firing the
> exploit.

This is why every file in this series includes real-world chaining notes, not just isolated
lab-style descriptions.

## Real-world case studies (industry framing)

- **Capital One (2019).** A misconfigured Web Application Firewall on AWS, combined with
  over-permissioned IAM credentials, allowed an attacker to query the EC2 metadata service via
  SSRF and retrieve temporary credentials with access to S3 buckets containing over 100 million
  customer records. This is a textbook example of *cloud infrastructure misconfiguration*
  chaining with *unnecessary services* (the metadata endpoint reachable from a request-driven
  WAF context).
- **Equifax (2017).** While the initial entry point was an unpatched Apache Struts vulnerability
  (technically a patching/vulnerable-components issue, A06:2021), the breach was made dramatically
  worse by internal network segmentation failures and the discovery of plaintext credentials in
  internal config files and scripts — both classic misconfiguration patterns.
- **Numerous bug bounty reports.** A large share of HackerOne and Bugcrowd public disclosures for
  "CORS misconfiguration" and "exposed S3 bucket" findings demonstrate that these categories are
  not academic — they are routinely paid out at meaningful bounty levels because of the sensitive
  data exposure they enable.

## How this maps to PortSwigger Web Security Academy

PortSwigger does not have a single topic literally named "Security Misconfiguration." Instead,
the relevant labs are distributed across PortSwigger's own topic structure:

- **CORS** topic → maps directly to file `05_CORS_Misconfiguration.md`
- **Information disclosure** topic → maps to files `03_Verbose_Errors_and_Debug_Exposure.md` and
  `06_Directory_Listing_Exposure.md` (directory listing, backup files, debug pages, and the
  TRACE-method insecure-configuration lab all live under this PortSwigger topic)
- There is no dedicated PortSwigger topic for default credentials, unnecessary feature exposure,
  or cloud storage misconfiguration — these are industry-standard pentest categories that
  PortSwigger does not gamify as labs, so files `02` and `07` are built from real-world technique
  and tooling rather than Academy labs. This is called out explicitly in those files and in the
  final lab-mapping file `09`.

## What's next

Continue to `02_Default_Credentials_and_Unnecessary_Features.md` for the first concrete
sub-category.
