# Scope and Authorization

## 1. Purpose
Confirm, in writing, what you are and are not allowed to test before running a single
tool against a target. This is not bureaucracy — testing out-of-scope infrastructure
can be a legal issue even when your intent is good-faith research.

## 2. When to Use
Before step 1 of any engagement, and again any time scope changes (new assets added
to a bug bounty program, a new engagement letter, a target that redirects to a domain
you haven't checked).

## 3. Prerequisites
- The program's published scope (bug bounty platform page) or the signed engagement
  letter/SOW (for contracted pentests).
- Any rules-of-engagement document specifying rate limits, excluded test types
  (e.g. "no automated scanning", "no DoS testing"), and allowed testing windows.

## 4. Methodology

### a) Read the scope definition literally
Bug bounty scope pages typically list:
- **In-scope**: specific domains, subdomain wildcards (`*.target.com`), mobile apps,
  specific IP ranges.
- **Out-of-scope**: explicitly excluded subdomains (often third-party services,
  status pages, marketing sites hosted elsewhere), excluded vulnerability classes
  (e.g. "no clickjacking reports", "no SPF/DMARC reports"), and excluded testing
  types (e.g. "no automated/bulk scanning without prior approval").

### b) Map discovered assets against scope before testing them
Every asset you find in later recon stages (subdomains, IPs, APIs) must be checked
against the scope definition before you send it a single crafted payload. A
wildcard like `*.target.com` does **not** automatically include every IP that
resolves for that domain if the domain is proxied through third-party infrastructure
not owned by the target (common with SaaS platforms, CDNs, support ticketing tools
on a subdomain).

### c) Build a simple scope-check habit
Before testing any newly discovered host, ask:
1. Is this domain/IP explicitly listed as in-scope?
2. If it's a subdomain matching a wildcard, is it actually operated by the target
   (not a third-party SaaS tenant)?
3. Does the program exclude this vulnerability class or testing method?
4. Am I within any stated rate limit or testing window?

If any answer is "no" or "unclear," do not test — ask the program (via their
disclosed contact channel) or skip it.

### d) Origin IP and direct-to-infrastructure testing — a specific, common mistake
Finding a target's real origin IP (see `03-Origin-Infrastructure/origin-ip-discovery.md`)
does **not** automatically authorize sending traffic directly to it. Many programs
explicitly prohibit bypassing their CDN/WAF, because:
- Rate limiting and WAF rules are themselves in-scope protective controls — testing
  that deliberately routes around them may violate the rules of engagement even if
  the origin IP itself is "in scope" by domain ownership.
- Direct-to-origin traffic can affect infrastructure shared with other
  tenants/services not covered by the authorization.

**Always check explicitly** whether the scope permits direct origin testing before
using a discovered origin IP for anything beyond passive confirmation.

## 5. Safe Testing Practices (apply across every later module)
- **Rate limits**: default to slow, single-threaded requests unless the program
  states otherwise. Tools like `ffuf`/`sqlmap` support `-p`/`--delay` flags
  specifically to throttle request rate — use them by default, not as an afterthought.
- **No destructive testing**: never run payloads that modify, delete, or mass-export
  data unless a program explicitly permits it and you're using a designated test
  account/test data.
- **Use test accounts**: register your own account where possible rather than testing
  against real user accounts or data, especially for IDOR/BAC testing.
- **Avoid unnecessary exposure to sensitive data**: if a vulnerability you're
  validating would expose other users' real personal data, stop at the minimum
  evidence needed to prove the issue (e.g. confirm you can see *a* record you
  shouldn't, don't enumerate or download the full dataset).
- **Stopping conditions**: stop testing a specific finding once you have enough
  evidence to report it clearly. Continuing to "see how far it goes" past that point
  is the most common way authorized testing turns into something a program will
  flag as a policy violation.

## 6. Documentation
- Save the scope page/engagement letter itself (screenshot or PDF, dated) — scope
  changes over time and you want a record of what was in scope when you tested.
- Log every asset you decided was in-scope vs. excluded, with your reasoning, before
  you start testing it.

## Output
A written scope boundary you can refer back to for the rest of the engagement, plus
the rate-limit/safety defaults that every later module assumes you're already
following.
