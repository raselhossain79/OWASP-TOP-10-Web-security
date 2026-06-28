# 06 — Cheatsheet and PortSwigger Lab Mapping

A condensed, quick-reference version of Files 01–05, plus the full PortSwigger Web
Security Academy "File upload vulnerabilities" lab list in exact difficulty
progression order. Use this file during active testing; use Files 01–05 to actually
understand the mechanisms when something doesn't work as expected.

---

## PortSwigger Web Security Academy — full lab list, in order

The "File upload vulnerabilities" topic on the Academy contains **7 labs total**,
progressing from Apprentice through Practitioner to Expert difficulty:

| # | Lab title | Difficulty | Technique tested | Covered in |
|---|---|---|---|---|
| 1 | Remote code execution via web shell upload | Apprentice | No validation at all — baseline webshell upload and trigger | File 02 (validation absence), File 05 (trigger/chain) |
| 2 | Web shell upload via Content-Type restriction bypass | Apprentice | Spoofing the per-part `Content-Type` header | File 03, Technique 1 |
| 3 | Web shell upload via path traversal | Apprentice | Path traversal sequences in the `filename` field | File 03, Technique 2; File 05 (escaping non-executable directories) |
| 4 | Web shell upload via extension blacklist bypass | Practitioner | Alternate executable extensions / overriding server config via uploaded `.htaccess` | File 03, Technique 3 |
| 5 | Web shell upload via obfuscated file extension | Practitioner | Case manipulation, double extensions, trailing characters, encoding tricks, null bytes | File 03, Technique 4 (all sub-techniques) |
| 6 | Remote code execution via polyglot web shell upload | Practitioner | JPEG + EXIF polyglot construction (exiftool) defeating magic-byte/content checks | File 04, Technique 2 |
| 7 | Web shell upload via race condition | Expert | Exploiting the upload-then-validate-then-delete timing window | File 05, Race conditions section |

### Honest disclosure on lab coverage

This mapping is built from the Academy's published lab list and corroborated against
multiple independent solved-lab writeups, since the Academy's lab catalog page itself is
rendered client-side and doesn't expose plain-text lab titles to a simple fetch. The
**order and titles above match the standard, consistently-reported sequence** across
every independent source checked. If PortSwigger adds or reorders labs in this topic in
the future, treat the *technique-to-file mapping* (right-hand columns) as the durable
part of this table — that mapping is determined by the underlying mechanism, not by
whatever number the Academy currently assigns a given lab.

There is **no dedicated automation tool** comparable to `sqlmap` or `commix` for this
category — file upload bypass is inherently manual/semi-manual work (Burp Repeater,
Intruder, Turbo Intruder, plus general-purpose tools like `exiftool`), which is why this
series doesn't include a dedicated automation-tool file the way the SQL Injection series
does.

---

## Quick-reference: technique → what it defeats → where to find it

| Technique | Defeats | File |
|---|---|---|
| Disable/bypass client-side JS check via Burp Repeater | Client-side filename/type checks | 02 |
| Spoof per-part `Content-Type` header | Server-side MIME-type check that trusts the header | 03 |
| Path traversal in `filename` | Unsanitized path construction during save | 03, 05 |
| Alternate executable extension (`.php5`, `.phtml`, `.pht`, `.phar`) | Incomplete extension blacklist | 03 |
| Upload `.htaccess` / `web.config` to remap an arbitrary extension | Blacklist of *known* dangerous extensions (you define a new one) | 03 |
| Case manipulation (`.pHp`) | Case-sensitive blacklist + case-insensitive execution mapping | 03 |
| Double extension (`.php.jpg`) | Validators reading only the final extension segment | 03 |
| Trailing dot/whitespace (`.php.`) | Strict string-match blacklist vs. filesystem-level stripping | 03 |
| URL / double-URL encoding (`%2E`, `%252E`) | Validation running before a later decode step | 03 |
| Null byte (`%00`) / semicolon (`;`) injection | High-level vs. low-level filename parsing disagreement | 03 |
| Overlong UTF-8 encoding | Decoders that "helpfully" normalize invalid sequences | 03 |
| Non-recursive strip bypass (`shell.p.phphp`) | Single-pass substring removal instead of recursive | 03 |
| GIF + PHP polyglot | Pure magic-byte (first-N-bytes) signature checks | 04 |
| JPEG + EXIF polyglot (exiftool) | Magic-byte checks **and** structural/dimension checks (`getimagesize()`) | 04 |
| File overwrite via predictable filenames | Missing filename randomization | 05 |
| Race condition (parallel upload + trigger requests) | Upload-then-validate-then-delete window | 05 |
| `PUT` method direct write | Application-level upload validation entirely (bypasses the form) | 05 |

---

## Practical testing checklist (mapped to WSTG-BUSL-08 / WSTG-BUSL-09)

Use this as a structured pass over any upload feature you encounter:

1. **Baseline:** does the application accept an obviously dangerous file
   (`shell.php`) with no modification at all? If yes, stop here — no further bypass
   needed (Lab 1 equivalent).
2. **Identify every validation layer present:** client-side JS, server-side
   extension check, server-side Content-Type check, server-side content/magic-byte
   check. Test each independently where possible by isolating which check actually
   triggers a rejection.
3. **Test Content-Type spoofing** (File 03, Technique 1) by changing only the
   per-part header, leaving the filename and content untouched, to confirm whether
   that header alone is trusted.
4. **Test filename-based path traversal** (File 03, Technique 2) to see whether the
   save location can be influenced or escaped.
5. **Enumerate alternate executable extensions** for the identified server stack
   (Apache: `.php3/.php4/.php5/.phtml/.pht/.phar`; check IIS/Tomcat/Node equivalents as
   relevant) before assuming a `.php` block is a complete fix.
6. **Test obfuscation variants systematically** rather than guessing one at random —
   case manipulation, double extension, trailing dot, single and double URL encoding,
   null byte — since real blacklists often catch some but not all of these.
7. **If a content check exists** (the file is rejected when it doesn't look like a
   real image), build a polyglot (File 04) rather than continuing to fight the
   extension layer alone.
8. **Once any file uploads successfully, confirm where it lands and whether that
   location executes the relevant extension** before assuming you have RCE — a
   successful upload is necessary but not sufficient.
9. **Check for filename collision/overwrite behavior** by re-uploading a file with a
   name you've already used or suspect already exists.
10. **If the application supports importing a file via URL**, treat it as a separate
    upload path with its own potential race condition, not just an alternate UI for the
    same validated pipeline.
11. **Send an `OPTIONS` request** to the upload endpoint and any nearby static paths to
    check for unexpectedly enabled `PUT` support.

---

## Tooling notes

- **Burp Repeater** — the primary tool for every technique in Files 02–03; manually
  editing the `filename`, `Content-Type`, and body of a captured multipart request.
- **Burp Intruder / Turbo Intruder** — for systematically trying extension wordlists
  (Technique 4 variants) across many requests, and for the precise parallel-request
  timing race conditions in File 05 require.
- **exiftool** — for constructing the JPEG/EXIF polyglot in File 04.
- **FuzzDB / SecLists** "web-shells" and "fuzzing/file-upload" wordlists — useful
  starting points for alternate-extension and obfuscation wordlist fuzzing rather than
  manually trying each variant from File 03 one at a time.

## OWASP prevention guidance (for the report-writing side of testing)

When documenting findings in this category, the standard remediation guidance to cite
is consistent across both PortSwigger and WSTG-BUSL-08/09:

- Validate against a **whitelist** of permitted extensions, not a blacklist.
- Reject filenames containing path traversal sequences (`../`) outright rather than
  attempting to sanitize them.
- **Rename** every uploaded file to a randomized name on save, eliminating both
  filename-based attacks and overwrite collisions.
- Never write uploads directly to their final, permanent location until full
  validation has completed — eliminating the race condition class entirely.
- Where possible, **re-encode** uploaded images through a fresh encoder rather than
  storing the original bytes, which strips embedded polyglot payloads as a side effect.
- Prefer an established framework's built-in upload handling over custom,
  hand-rolled implementations wherever feasible.
