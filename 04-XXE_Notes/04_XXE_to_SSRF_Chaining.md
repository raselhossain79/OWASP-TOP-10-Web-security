# 04 — XXE-to-SSRF Chaining

## Real-World Framing

Every XXE vulnerability is, by construction, also a partial SSRF primitive: the moment
a parser will dereference a `SYSTEM` URI, you control what server-side request it makes
— you're just usually using `file://` instead of `http://`. Treating XXE as an SSRF
vector is one of the highest-value reframes a tester can make, because it opens up
targets that have nothing to do with "files" at all: internal admin panels, cloud
instance metadata services, internal microservice APIs that trust requests originating
from inside the network, and internal port scanning. This is also why XXE findings are
frequently rated as critical in bug bounty programs even when no file is ever directly
read — the cloud credential theft path below is one of the most common high-payout XXE
chains reported publicly.

## Technique 1: Basic SSRF via External Entity

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

- `SYSTEM "http://internal.vulnerable-website.com/"` — the only change from a classic
  file-read payload is the URI scheme and host. The parser doesn't distinguish between
  "read a file" and "make an HTTP request" conceptually — both are just URI
  dereferencing to it. This means the server itself — which may sit inside a private
  network, VPC, or behind a firewall that blocks your direct access — becomes the one
  making the request, reaching destinations you could never hit directly from the
  internet.
- If the entity's resolved value ends up reflected in the response (same in-band
  mechanic as file 2), you get full two-way interaction: you see the internal service's
  actual response body. If not, you still achieve **blind SSRF**, which can be just as
  damaging depending on the target (e.g. triggering a state-changing internal API call
  doesn't require seeing a response).

## Technique 2: Cloud Metadata Endpoint Abuse (the high-value target)

Cloud providers expose an instance metadata service reachable only from inside the
instance itself, traditionally at a link-local address. For AWS EC2 specifically:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
```

### Piece-by-Piece Breakdown and Exploitation Flow

- `169.254.169.254` — the link-local IPv4 address AWS (and several other cloud
  providers, with provider-specific path structures) uses for the Instance Metadata
  Service (IMDS). It is only reachable from within the instance — which is exactly why
  XXE/SSRF is the only way an external attacker reaches it: the vulnerable application
  server becomes the "internal" requester on the attacker's behalf.
- `/latest/meta-data/iam/security-credentials/` — listing this path (with the trailing
  slash) returns the *name* of an IAM role attached to the instance, if one exists, as
  plain text in the response body.
- Once you have the role name, you repeat the request with the role name appended to
  the path (`/latest/meta-data/iam/security-credentials/<role-name>`), which returns a
  JSON blob containing temporary `AccessKeyId`, `SecretAccessKey`, and `SessionToken`
  values for that IAM role.
- With these in hand, you can configure the AWS CLI / SDK with the stolen temporary
  credentials and interact with whatever AWS services that IAM role has permissions
  for — S3 buckets, EC2 instances, Lambda functions, sometimes far broader access than
  the role's name would suggest, depending on how permissively it was configured.

### Real-World Note

This exact chain (XXE → SSRF → IMDS → IAM credential theft) is one of the most
frequently disclosed high-severity findings across public bug bounty writeups for any
SSRF-capable bug, not just XXE specifically. Many organizations have since migrated to
**IMDSv2**, which requires a session token obtained via a `PUT` request with a custom
header before metadata can be read — this specifically blocks simple GET-only SSRF
primitives (including most XXE-based SSRF, since you typically can't set custom headers
or use `PUT` through an `ENTITY SYSTEM` URI) and is worth checking for during
engagements, since its presence significantly reduces this chain's viability.

## Technique 3: Internal Port Scanning / Service Discovery via Response Timing or Errors

When two-way interaction isn't available, XXE-driven SSRF can still be used for blind
internal reconnaissance by observing differences in response time or error behavior
across many requests, each targeting a different internal host:port combination:

```xml
<!ENTITY xxe SYSTEM "http://10.0.0.5:8080/">
```

- Iterating the IP/port in this entity across a plausible internal range and noting
  which requests cause a fast connection (port open, something responded) versus a
  timeout (likely closed/filtered) or an immediate connection-refused-style error
  (closed but reachable) lets you map internal network topology blind, the same way
  classic blind SSRF timing techniques work — XXE is just the delivery mechanism here.

## Why This Matters for Reporting and Prioritization

When writing up an XXE finding professionally, always state both halves of the impact
clearly: the file-disclosure capability *and* the SSRF capability, even if you only
demonstrated one in your proof-of-concept, because remediation guidance differs
slightly between them (disabling external entities fixes both; network-level egress
controls only mitigate the SSRF half) and because a reviewer scoring severity needs to
know the full blast radius, not just whichever path you happened to prove first.

## What's Next

File 5 covers what to do when a WAF or signature-based XML filter sits in front of the
target and blocks the straightforward payloads shown in files 2–4 — encoding
variations, parameter entity obfuscation, and other ways to evade detection without
changing the underlying entity mechanics. File 6 then covers XXEinjector, the closest
tool ecosystem has to a dedicated XXE automation framework.
