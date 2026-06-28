# HTTP Request Smuggling — Burp Suite "HTTP Request Smuggler" Extension

This is the closest thing this category has to a sqlmap/commix-style dedicated
automation tool. Manually hand-crafting CL.TE/TE.CL probes and then fuzzing every
known `Transfer-Encoding` obfuscation variant by hand does not scale across a real
engagement's worth of endpoints — this extension exists precisely to automate that.

## 1. What it is

**HTTP Request Smuggler** is a Burp Suite extension written by James Kettle,
PortSwigger's Director of Research — the same researcher who re-popularized this
entire vulnerability class with the 2019 "HTTP Desync Attacks" Black Hat/DEF CON
talk. The extension automatically detects and exploits HTTP request smuggling vulnerabilities using advanced desynchronization techniques developed by Kettle, and supports comprehensive scanning for HTTP/1.1 and HTTP/2-downgrade desync vulnerabilities, client-side desyncs, and connection state attacks.

As of version 3.0, released in 2025, it added parser discrepancy detection, a
significantly more robust approach focused on finding raw parsing disagreements
between front-end and back-end rather than only checking known obfuscation
signatures — meaning it stays effective even against infrastructure that has been
patched against the well-known classic payloads. It's compatible with Burp Suite DAST, Professional, and Community editions.

It depends on **Turbo Intruder** (also by Kettle) under the hood for sending the
malformed, deliberately-non-RFC-compliant raw requests this category requires —
standard Burp Repeater/Intruder will auto-correct things like `Content-Length`
unless you're careful, which is exactly the kind of interference this tooling exists
to avoid.

## 2. Installation

1. In Burp Suite: **Extensions → BApp Store** (older versions: **Extender → BApp
   Store**).
2. Search for "HTTP Request Smuggler".
3. Click **Install**. Burp will automatically pull in the Turbo Intruder dependency
   if it isn't already installed — if it isn't auto-resolved on Community Edition,
   install Turbo Intruder from the BApp Store separately first, then install HTTP
   Request Smuggler.
4. Confirm it loaded: **Extensions → Installed**, and check the **Output** tab for
   the extension to confirm no load errors.

## 3. Core workflow 1 — "Launch Smuggle probe" (detection)

This is the primary detection workflow and maps directly to the timing-based
detection technique covered in `02-detection-techniques.md`, just automated across
every obfuscation/header-handling variant the extension knows about instead of one
manual probe at a time.

Steps:
1. Capture or send a request to the target endpoint so it appears in Burp's history,
   site map, or Repeater.
2. Right-click the request → **Extensions → HTTP Request Smuggler → Launch Smuggle
   probe** (in older versions this may appear directly as **Launch Smuggle probe**
   in the right-click menu without the submenu).
3. A configuration dialog appears, most importantly a **timeout** setting (commonly
   set to 3–5 seconds) — this is the threshold above which a delayed response is
   flagged as a potential desync, directly implementing the timing-delay logic
   explained in the detection file.
4. Confirm, and the extension fires a battery of probe requests at the target —
   CL.TE probes, TE.CL probes, and the full library of `Transfer-Encoding`
   obfuscation variants from `01-concept-and-root-cause.md` Section 6 — far faster
   and more exhaustively than testing each variant by hand in Repeater.
5. Watch results in **Extensions → Installed → HTTP Request Smuggler** output pane.
   On **Burp Suite Professional**, any positive finding is also automatically
   surfaced as a normal scan issue in the **Issues**/**Dashboard** view, with
   severity and a description of which variant (CL.TE/TE.CL/TE.TE/H2.CL/H2.TE) was
   detected.

### Why this matters for an engagement
A single hand-tested obfuscation header takes a few minutes to verify properly
(craft, send, observe timing, repeat). A real target might have dozens of in-scope
endpoints behind different front-end configurations. The probe workflow turns what
would be hours of manual fuzzing into a single right-click action per endpoint, which
is the difference between covering a handful of endpoints in an engagement window
versus covering the entire in-scope surface.

## 4. Core workflow 2 — "Launch Smuggle attack" (exploitation)

Once a probe confirms a desync exists, the next step is building a working
exploitation payload — which is its own non-trivial task, since offsets, chunk-size
hex values, and trailing padding all have to be recalculated for every change you
make to the smuggled fragment (exactly the kind of manual byte-counting shown
throughout `03-exploitation-outcomes.md`).

Steps:
1. Right-click a request that you've confirmed uses, or can be made to use, chunked
   encoding (i.e. one you've already proven is part of a CL.TE or TE.CL desync).
2. Select **Extensions → HTTP Request Smuggler → Launch Smuggle attack**.
3. This opens a **Turbo Intruder** window pre-populated with a Python-based attack
   script. The key thing you edit is the `prefix` variable — this is exactly the
   smuggled fragment discussed throughout `03-exploitation-outcomes.md` (the
   `GET /admin HTTP/1.1...` block, the XSS payload request, the malicious-`Host`
   redirect request, etc.).
4. The extension automates certain critical adjustments, such as calculating the offsets required for TE.CL attacks — meaning you don't have to manually recompute hex chunk-size values every time you tweak the smuggled payload's length, which is one of the most error-prone parts of doing this by hand (get the hex byte count wrong by even one character and the whole attack silently fails to desync).
5. Run the Turbo Intruder attack and observe the responses for the differential
   signal (unexpected 404, reflected payload, captured session data, etc.) described
   in the relevant section of `03-exploitation-outcomes.md`.

## 5. Practical tips from real-world usage

- **Always uncheck "Update Content-Length" in the Repeater menu** before manually
  testing or tweaking any smuggling payload directly in Repeater (outside the
  extension's automated flow) — Burp's default auto-correction will silently
  "fix" the deliberately wrong length header your attack depends on, and the
  attack will appear not to work for reasons that have nothing to do with the
  target.
- The extension's automated probe will fire a meaningful volume of malformed traffic
  at the target connection. It is not recommended to use it on production systems, since it could cause downtime if the probes are successful — treat this exactly like any other active scanning tool: confirm written authorization and scope before running it, and prefer running it against staging/lab environments first.
- If you're testing a target that uses HTTP/2 at the edge, remember from
  `01-concept-and-root-cause.md` Section 7 that you may need to manually force
  Burp/Repeater to use HTTP/1.1 (or, conversely, manually switch to HTTP/2 in the
  Inspector's Request Attributes panel) to correctly exercise the downgrade path —
  the extension's HTTP/2-downgrade-specific checks rely on you testing the right
  protocol version against the right layer.
- Pair it with the companion extension **HTTP Hacker** (also by PortSwigger/Kettle)
  when you need visibility into connection reuse and pipelining behavior across the
  proxy chain — useful for understanding *why* a probe succeeded or failed rather
  than just *that* it did.
- For environments that look "hardened" against the classic named obfuscation
  payloads, rely on the v3.0+ **parser discrepancy detection** mode rather than
  assuming the target is clean — established detection techniques often miss vulnerabilities due to superficial defences that simply block known request smuggling patterns, while the newer parser-discrepancy approach focuses on the underlying parsing primitives instead, meaning it can surface novel desyncs that signature-based defenses were never designed to catch.

## 6. Honest scope note on alternatives

For non-Burp workflows (e.g. scripted/CI scanning, or simply not having Burp Pro
available), **Smuggler.py** is a standalone Python scanner that automates the same
three core technique categories. It automates the search for the three main types of request smuggling — CL.TE, TE.CL, and TE.TE variants that exploit Transfer-Encoding parsing errors — and can add mutations to refine tests, particularly for TE.TE attacks, though it is no longer actively maintained. It remains a reasonable choice for broad, scripted scanning across a large host list outside of Burp, but the Burp extension is the more current, actively developed, and more capable tool for hands-on engagement work, particularly given its v3.0 parser-discrepancy detection that Smuggler.py does not implement.
