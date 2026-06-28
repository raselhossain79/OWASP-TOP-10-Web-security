# 01 — Overview and Classification of File Upload Vulnerabilities

## What a file upload vulnerability actually is

A file upload vulnerability exists when a web server accepts a user-supplied file
without sufficiently validating one or more of: its **name**, its **type**, its
**contents**, or its **size** — and that insufficient validation lets an attacker get a
file onto the server (or onto a client's browser) in a form that causes harm.

The phrase "insufficiently validating" is doing a lot of work in that sentence, and the
rest of this series is essentially unpacking it. It is genuinely rare in 2026 to find a
production application with **zero** validation. Developers are aware uploads are
dangerous. What you find instead is validation that is logically reasonable but
technically incomplete — a blacklist that misses an extension, a Content-Type check that
trusts a client-controlled header, a magic-byte check that only looks at the first few
bytes. Every technique in this series exploits one of these specific, narrow gaps.

## The four things a server *could* validate

| What's checked | Example mechanism | How robust is it alone |
|---|---|---|
| **Filename / extension** | String match against a blacklist/whitelist, e.g. reject `.php` | Weak — extensions are just text in a field the attacker fully controls |
| **Declared MIME type** | The `Content-Type` header inside the multipart part | Weak — this is also client-supplied text, not a server-side fact about the file |
| **File contents** | Magic byte / signature check, dimension check (`getimagesize()`), full content scan | Moderate to strong, depending on depth of inspection |
| **File size** | Byte-length check against a max | Only prevents DoS-style abuse, irrelevant to RCE |

A server that checks only the first two columns is checking attacker-controlled
*metadata about the file*, not the file itself. This is the single most important idea
in this entire series: **filename and Content-Type are input fields, not facts.** They
arrive in the HTTP request exactly like a username or comment field would, and an
attacker can set them to anything.

## Classification axis 1: where the validation happens

- **Client-side** (JavaScript `accept` filters, file-extension checks before the form
  submits) — this is a UX convenience, not a security boundary. It runs in a browser the
  attacker fully controls, so it can always be skipped. Covered in File 02.
- **Server-side** — this is the actual trust boundary. Everything in Files 03–05 targets
  gaps in server-side checks specifically, because that's the only validation that
  matters for security.

Real applications almost always implement **both** — client-side for instant user
feedback, server-side (in theory) as the real gate. The danger is when a team treats the
client-side check as sufficient and either omits the server-side check entirely or
implements it with the same naive logic.

## Classification axis 2: what happens to the file after it lands

This determines the *ceiling* of the impact, independent of how the validation was
bypassed:

1. **Uploaded into a directory the web server will execute scripts from, and the
   extension maps to an executable handler** (e.g. `.php` in a PHP-enabled directory) →
   potential full RCE.
2. **Uploaded into a directory the server treats as static content, but served back to
   other users in their browser, and the file type allows active content** (e.g. an
   `.html` or `.svg` file containing `<script>`) → stored XSS, not RCE, but still
   dangerous in an authenticated app.
3. **Uploaded and later parsed/processed by a vulnerable library** (e.g. an XML-based
   `.docx`/`.xlsx` parsed by a vulnerable XML parser, or an image processed by a
   vulnerable image library) → vulnerability class shifts entirely, e.g. XXE or a
   memory-corruption bug in the parser.
4. **Uploaded with a filename the attacker fully controls, and no path sanitization** →
   directory traversal during the *write*, letting the attacker choose the destination
   path, or overwrite an existing file by name collision.
5. **Uploaded but never executed, never re-served as active content, never parsed by
   anything dangerous** → at most a storage/DoS concern (disk exhaustion from oversized
   or excessive uploads).

Tiers 1, 4, and 5 are the focus of Files 03–05. Tier 2 (client-side-only impact via
stored XSS through HTML/SVG upload) and tier 3 (XXE via uploaded Office documents) are
real and worth testing for, but they're separate vulnerability classes layered on top of
the upload feature — they belong conceptually with XSS and XXE testing rather than with
file-upload-specific bypass technique, so this series only touches them briefly where
relevant and doesn't duplicate the dedicated XSS/XXE material.

## Impact ranking, worst to least severe

1. **Remote code execution** via webshell upload — full server compromise (Files 03–05).
2. **Stored client-side script execution** (XSS via uploaded HTML/SVG, served from the
   same origin) — session hijacking, account takeover of *other* users.
3. **File overwrite** — corrupting or replacing application files, configuration files,
   or other users' uploaded content by filename collision (File 05).
4. **Server-side parsing vulnerabilities** triggered by uploaded file contents (e.g. XXE
   via a malicious `.xlsx`) — impact varies by what's reachable from that parser.
5. **Information disclosure** — misconfigured servers sometimes return source code as
   plaintext when they fail to execute an uploaded script, leaking application logic.
6. **Denial of service** — disk exhaustion via oversized or unlimited uploads.

## Why this is such a heavily reported bug bounty category

A few structural reasons file upload bugs are consistently profitable for bounty
hunters and consistently dangerous in the wild:

- **Every application with user-generated content has an upload feature somewhere** —
  avatars, attachments, CSV imports, resume uploads, KYC document uploads. The attack
  surface is everywhere, not confined to one obvious endpoint.
- **The validation logic is usually bespoke per-application**, unlike, say, an ORM that
  handles SQL parameterization consistently. Every team reinvents file upload validation,
  and reinvented security logic is reliably where bugs live.
- **Frameworks have gotten much better, but legacy and hand-rolled upload handlers are
  everywhere**, especially in older PHP codebases, internal admin tools, and CMS plugin
  ecosystems (WordPress plugin upload bugs are a near-permanent fixture of CVE feeds).
- **The fix is conceptually simple (whitelist + rename + non-executable storage) but
  easy to implement partially**, which is exactly the gap this series exploits.

## What's next

File 02 covers the client-side/server-side split in detail, including exactly what the
multipart/form-data request looks like and which parts of it are meaningfully
"server-side validated" versus purely cosmetic. That structural understanding is a
prerequisite for every bypass technique in Files 03–05.
