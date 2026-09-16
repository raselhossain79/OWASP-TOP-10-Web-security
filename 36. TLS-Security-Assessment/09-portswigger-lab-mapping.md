# 09 — PortSwigger Lab Mapping (Honest Gap Disclosure)

Consistent with this library's convention, this section states plainly where
PortSwigger's Web Security Academy does and does not cover TLS-specific
testing — no attempt to stretch loosely-related labs into false coverage.

## 9.1 What PortSwigger Does NOT Cover (Direct Gap)

PortSwigger Web Security Academy runs its labs behind a managed, uniform
HTTPS termination layer that is intentionally out of scope for learners to
modify or attack. As a direct consequence, **the following topics from this
library have no corresponding PortSwigger lab at all**:

- Protocol/version downgrade (01) — no lab exposes a choice of TLS versions
- Cipher suite weaknesses (02) — no lab exposes cipher configuration
- Certificate assessment (03) — lab certificates are fixed and valid
- TLS configuration/session handling (04) — HSTS, OCSP stapling, session
  tickets, etc. are not variable across labs
- Named CVE-class TLS vulnerabilities (05) — Heartbleed, POODLE, FREAK,
  Logjam, DROWN, ROBOT, Sweet32, Lucky13 have zero PortSwigger lab coverage

This is the single largest gap in the GitHub library's existing convention
of PortSwigger lab mapping — it's being stated explicitly here rather than
listing tenuous "related" labs to appear more complete than the coverage
actually is.

## 9.2 What PortSwigger DOES Cover (Adjacent, Not Equivalent)

A small number of labs touch topics *adjacent* to TLS from file 06 —
these are genuinely relevant but test application-layer behavior around
HTTPS, not the TLS layer itself:

| Topic | PortSwigger Coverage | Overlap with this library |
|---|---|---|
| HSTS bypass / cookie security | Labs under "HTTP Host header attacks" and cookie-security-adjacent labs touch on secure cookie flags and, indirectly, transport security assumptions | Partial overlap with 04.2/06.1 — application-layer consequence of missing transport security, not the HSTS header check itself |
| Mixed content / CSP | Some "Content Security Policy" labs cover CSP bypass techniques where mixed-content-style resource loading is part of the bypass chain | Partial overlap with 06.2 — CSP mechanics, not TLS mixed-content scanning |
| Request smuggling | The dedicated "HTTP request smuggling" lab category occasionally involves front-end/back-end protocol mismatches at a TLS-terminating proxy | Loosely adjacent to 04.6's proxy-boundary note, not a TLS test itself |

None of these labs should be presented as "practicing TLS assessment" —
they're included here only so the honest boundary is clear: useful adjacent
skill-building, not a substitute for sections 01–05.

## 9.3 Recommended Substitute for Lab-Style Practice

Since PortSwigger doesn't fill this gap, file 08 (Practice Platforms) is the
actual substitute for "lab practice" in this specific area of the library —
badssl.com for recognition-level practice (Category A), and a self-built lab
for the full test-fix-retest cycle (Category B). Treat file 08 as this
library's equivalent of a lab index for TLS topics specifically.
