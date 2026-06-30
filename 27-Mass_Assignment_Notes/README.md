# Mass Assignment Vulnerabilities — Note Series

A structured, GitHub-ready reference on Mass Assignment (also known as Auto-Binding)
vulnerabilities in API-backed and ORM-driven applications. Built for hands-on
penetration testing, bug bounty recon, and secure code review work.

## Scope

Mass assignment occurs when a web framework automatically binds incoming request
data (JSON body, form fields, query parameters) directly onto an internal object —
typically a database model or DTO — without an explicit whitelist of which fields
are allowed to be set by the client. If that internal object has properties that
were never meant to be client-controlled (`isAdmin`, `role`, `accountBalance`,
`verified`), an attacker who knows or guesses the property name can inject it into
the request and have the backend write it directly into persistent storage.

This is fundamentally a **trust boundary failure between the wire format (JSON/form
data) and the internal object model**, and it is one of the most common root causes
behind privilege escalation in REST APIs built on ORMs.

## File Index

| File | Contents |
|---|---|
| `01-overview-and-classification.md` | Definition, root cause mechanics, CWE/OWASP mapping, where it appears in real systems |
| `02-detection-methodology.md` | Methodology for finding hidden/bindable fields: response diffing, Param Miner, Intruder, API docs/Swagger, Autorize |
| `03-exploitation-privilege-escalation.md` | Piece-by-piece exploitation walkthroughs: privilege escalation, IDOR-via-mass-assignment, nested/array binding |
| `04-framework-specific-notes.md` | Mechanism-level breakdown per framework: Ruby on Rails, Django REST Framework, Spring Boot, Laravel |
| `05-cheatsheet.md` | Quick-reference field wordlist, request templates, detection/remediation checklists, lab map |

## How This Series Is Organized

Every file in this series follows the same conventions used across the rest of this
notes library:

- **Mechanism-first explanations** — every technique is explained in terms of *why*
  the backend behaves the way it does, not just *what* payload to send.
- **Piece-by-piece request breakdowns** — every example HTTP request is annotated
  field by field: which value is attacker-controlled, why the backend binds it,
  and what the resulting impact is.
- **PortSwigger Web Security Academy lab mapping** — labs are referenced where they
  exist, in the Academy's own difficulty order. Coverage gaps are disclosed
  honestly rather than stretched to fit.
- **Real-world industry framing** — every file includes a section connecting the
  technique to real disclosed incidents, bug bounty patterns, or industry guidance
  (OWASP API Security Top 10).

## PortSwigger Coverage Note

As of this series' research date, PortSwigger Web Security Academy has **one
dedicated lab** for this vulnerability class:

- **Lab: Exploiting a mass assignment vulnerability** (API Testing topic,
  Practitioner difficulty) — `portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability`

There is no dedicated "Mass Assignment" top-level Academy topic — it is taught as a
subsection of the **API Testing** topic, alongside hidden parameter discovery and
server-side parameter pollution. This series treats those as related-but-distinct
techniques and cross-references them only where the detection workflow genuinely
overlaps (see `02-detection-methodology.md`). This gap is disclosed explicitly
rather than padded out with loosely related labs.

## Prerequisites

This series assumes familiarity with:
- Intercepting and replaying HTTP requests in Burp Suite (Proxy/Repeater)
- Basic REST API conventions (verbs, JSON bodies, status codes)
- Reading this notes library's `Web Fundamentals` and `Broken Access Control / A01`
  series, since mass assignment is a sub-class of broken access control
