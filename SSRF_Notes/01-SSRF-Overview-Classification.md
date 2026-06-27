# 01 — SSRF Overview & Classification

## 1. What SSRF Actually Is

Server-Side Request Forgery is not "the server makes a request" — every web
server does that constantly (fetching upstream APIs, webhooks, images). SSRF is
specifically when **an attacker controls, fully or partially, the destination
of a request that the server makes**, and that destination was never meant to
be attacker-controlled.

The vulnerable pattern always has three ingredients:

1. A server-side feature that fetches a URL (or connects to a host) on behalf
   of the application — stock checkers, PDF generators, webhook senders, image
   proxies, URL preview/unfurl features, SSO metadata fetchers, "import from
   URL" buttons.
2. User input that influences some part of that destination — the full URL, a
   hostname, a path, or even just a header value (like `Referer`) that a
   backend analytics tool later fetches.
3. A **trust boundary** the server crosses when it makes that request — usually
   network position. Requests that originate *from* the server (not from the
   public internet) are frequently treated as implicitly trusted by internal
   systems, admin panels, and cloud control planes.

That third point is the entire reason SSRF is dangerous. It's not really an
"injection" the way SQLi or XSS are — it's an abuse of **identity by network
origin**. The attacker isn't injecting code; they're borrowing the server's
network position to reach things the server can reach but the attacker can't.

## 2. The Two Core Attack Categories

### 2.1 SSRF Against the Server Itself

The attacker points the vulnerable parameter back at the server's own loopback
interface — `127.0.0.1`, `localhost`, `0.0.0.0`, or the IPv6 equivalent `::1`.

Why this works: many applications have admin functionality, debug endpoints, or
diagnostic interfaces that are either unauthenticated or only access-controlled
at a layer in front of the app (e.g., a reverse proxy that blocks `/admin` from
the public internet but doesn't apply the same rule to requests the app server
makes to itself). A request that *appears* to originate from `localhost` skips
that front-door check entirely.

### 2.2 SSRF Against Other Back-End Systems

The attacker points the vulnerable parameter at other hosts inside the
organization's private network — RFC 1918 ranges like `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, or cloud-internal ranges. These back-end
systems are usually unauthenticated internally because the network boundary
itself was assumed to be the security control — a classic "trusted internal
network" design flaw. Internal admin panels, message queues (Redis, RabbitMQ),
internal REST APIs, monitoring dashboards, and CI/CD systems are common targets
here.

A third category, covered in depth in file 04, deserves its own mental bucket
even though technically it's a special case of 2.2: **cloud metadata services**.
`169.254.169.254` is not a normal internal host — it's a control-plane endpoint
that can hand over IAM credentials, making it the single highest-value SSRF
target in modern cloud-hosted applications.

## 3. Visible vs. Blind SSRF

This distinction matters because it changes your entire exploitation
methodology, not just the payload.

- **Visible (basic) SSRF** — the response from the back-end request is reflected
  back to you in the application's front-end response. You can directly read
  the admin panel's HTML, the internal API's JSON, etc. This is the easiest
  category to confirm and exploit because you get immediate feedback.
- **Blind SSRF** — the server issues the back-end request, but you never see the
  response. You only know the request happened (or didn't) through indirect
  signals: timing differences, out-of-band network callbacks (DNS lookups, HTTP
  hits on a listener you control), or downstream side effects. Blind SSRF is
  harder to confirm and harder to exploit for data exfiltration, but it can
  still escalate to remote code execution if you can chain it into a
  vulnerable back-end service (covered with the Shellshock example in file 02,
  and with Gopher-based protocol smuggling in file 06).

## 4. Real-World Industry Context

SSRF is not a theoretical lab category — it has caused some of the highest-profile
cloud breaches of the last decade, almost always via the same mechanism: a
web-facing application with an SSRF flaw, chained into the cloud metadata
service, to steal temporary IAM credentials with permissions far broader than
the vulnerable app should have had.

Patterns seen repeatedly in real incidents and bug bounty reports:

- **WAF/reverse-proxy SSRF leading to credential theft.** Misconfigured edge
  infrastructure that itself made outbound requests based on attacker-supplied
  headers, chained into the instance metadata service, leading to large-scale
  data exposure. This is the textbook example cited industry-wide for why
  IMDSv2 (session-token-based metadata access) exists.
- **URL preview / "import from link" features.** Chat apps, document editors,
  and CMS platforms that fetch a URL to generate a preview card are one of the
  most commonly reported SSRF surfaces in bug bounty programs, because the
  feature is *designed* to fetch arbitrary attacker-supplied URLs — the only
  question is whether internal/private-range destinations are filtered.
- **PDF generators and "export to PDF/image" features.** Server-side HTML-to-PDF
  renderers (wkhtmltopdf, headless Chrome/Puppeteer) that process attacker
  HTML/CSS will fetch any `<img src>`, `@import`, or `<iframe>` URL embedded in
  that input — a very common and frequently underestimated SSRF + local file
  read vector.
- **Webhook and integration features.** Anything that lets a user register a
  callback URL ("notify me at this URL when X happens") is SSRF-by-design from
  the platform's perspective; the security question is entirely about what
  destinations are disallowed.

The consistent lesson across these: SSRF is rarely the *final* impact. Its real
danger is as a **pivot** — a way to reach something else (an internal API, a
metadata endpoint, an unauthenticated internal service) that has its own,
usually more severe, impact. When scoping a pentest or bug bounty report, the
SSRF itself is almost never the headline; what you can reach through it is.

## 5. Mitigations (for context — reference when writing reports)

- Network-level egress filtering / firewalling outbound requests from
  application servers (deny-by-default to internal ranges).
- Disabling unused URL schemes (`file://`, `gopher://`, `dict://`) in any HTTP
  client library used server-side.
- Strict allow-listing of destination hosts, enforced *after* DNS resolution
  (not just on the input string) and re-validated if redirects are followed.
- For cloud metadata specifically: enforcing IMDSv2 (AWS), disabling legacy
  metadata access, or blocking egress to `169.254.169.254` from the app tier
  entirely where the app doesn't need it.

These are referenced again, more specifically, in the relevant technique files.
