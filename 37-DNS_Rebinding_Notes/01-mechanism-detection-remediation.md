# DNS Rebinding — Mechanism, Detection, Remediation

## 1. Mechanism

### Why test it
Browsers enforce Same-Origin Policy based on hostname, not IP address. DNS
rebinding abuses this gap: an attacker controls a DNS record for a domain
the victim's browser is tricked into visiting, and switches that domain's
resolved IP *after* the initial page load — from an attacker-controlled
public IP to an internal/private IP (e.g., `127.0.0.1`, `192.168.x.x`, a
cloud metadata endpoint). Because the hostname hasn't changed, the browser
still considers follow-up requests same-origin, letting attacker-controlled
JavaScript running in the victim's browser make requests to internal
services that should never be reachable from the public internet.

### Classification
High — can lead to internal network reconnaissance, access to unauthenticated
internal admin interfaces, or cloud metadata credential theft, but requires
a specific set of conditions (victim must load attacker page, target
internal service must lack its own auth, low DNS TTL exploitation window)
to be practically exploitable — hence not scored Critical by default.

## 2. Attack Flow

1. Attacker sets up a domain with a very short DNS TTL.
2. Victim visits the attacker's page; browser resolves the domain to
   attacker's public server and loads the initial page/JS.
3. Attacker's DNS server then changes the record to resolve to an internal
   IP (e.g., `127.0.0.1`, `169.254.169.254` for cloud metadata, or an
   internal admin panel's IP).
4. The page's JavaScript (already loaded, same "origin" per hostname)
   re-requests the domain — now resolving internally — and can read
   responses from the internal service due to same-origin being satisfied
   at the hostname level.

## 3. Detection & Interpretation

- Identify any application feature that accepts a user-supplied hostname
  and then makes a server-side or client-side follow-up request to it
  (webhooks, URL preview/unfurl features, SSRF-adjacent functionality) —
  rebinding is often chained with or mistaken for SSRF; the distinguishing
  factor is that classic SSRF is a single server-side request, while
  rebinding specifically relies on the *browser* re-resolving DNS mid-session.
- For a suspected vulnerable internal service: confirm whether it performs
  any hostname/`Host`-header validation, or whether it trusts any request
  arriving on its listening interface regardless of origin.
- Tools: `singularity` (rebinding-focused framework) and Burp Collaborator
  (or a self-hosted authoritative DNS server you control) to demonstrate
  the TTL-based re-resolution against your own lab service.

## 4. Remediation

- Internal services should require their own authentication regardless of
  source IP/network position — never rely on "it's only reachable
  internally" as the sole control.
- Validate the `Host` header server-side against an allow-list on any
  service that should only be reachable via a specific known hostname.
- Applications that make follow-up requests to a previously-resolved
  hostname should pin the DNS resolution for the lifetime of that
  request/session ("DNS pinning") rather than re-resolving on each request.
- For browser-facing internal tools specifically, consider requiring a
  custom header or token that a cross-origin/rebound request cannot supply.

## PortSwigger Lab Mapping — Gap Disclosure

PortSwigger Web Security Academy does not have a dedicated DNS rebinding lab
category at the time of writing — its SSRF labs cover the adjacent server-
side request forgery pattern, but not the browser DNS re-resolution
mechanism specifically. Stated plainly rather than stretching an SSRF lab to
look like coverage it doesn't provide.
