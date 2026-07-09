# Path Traversal as a Broken Access Control Issue

## 1. Why Path Traversal Belongs in This Series

PortSwigger lists Path Traversal as its own Academy topic, separate from Access Control — but conceptually, **path traversal is a file-system-level instance of the exact same IDOR pattern from file 2.** Instead of a database row ID, the "direct object reference" here is a filesystem path. The server takes user-supplied input, concatenates it into a path, and opens whatever that path resolves to — with no check that the resolved file is one the requester is actually authorized to read.

```
GET /loadImage?filename=218.png HTTP/1.1
```

This single line is the entire vulnerability surface: `filename` becomes part of a server-side path like `/var/www/images/218.png`, and the access control question — "should this specific session be allowed to read this specific file?" — is never asked. The only thing standing between this and reading `/etc/passwd` is whatever (if any) sanitization the application performs on `filename`. The six techniques below, in PortSwigger Academy's actual difficulty order, are six different levels of that sanitization and how each one fails.

## 2. Lab 1 — Simple Case (No Sanitization)

```
GET /image?filename=../../../etc/passwd HTTP/1.1
```

### Piece-by-piece breakdown

- The application's image-serving logic does something equivalent to `open(BASE_DIR + filename)`, where `BASE_DIR` is `/var/www/images/`.
- `../../../etc/passwd` — each `../` instructs the filesystem to move **up one directory level** from the current location before continuing to resolve the rest of the path. Three `../` sequences walk up from `/var/www/images/` to `/var/www/`, then `/var/`, then `/` (root) — enough levels to escape the intended image directory entirely.
- Once at root, `etc/passwd` is a normal, valid relative path to the well-known Unix credentials-format file (it doesn't contain actual hashed passwords on modern systems, but is the universal proof-of-concept target because its content is predictable and always world-readable).
- **Why this is an access-control failure, not "just" a path bug:** the server never verified that the *resolved* path stayed inside `/var/www/images/`. It trusted user input as the entire suffix of a sensitive operation (file read) with zero boundary check.

## 3. Lab 2 — Absolute Path Bypass (Traversal Sequences Blocked)

```
GET /image?filename=/etc/passwd HTTP/1.1
```

### Piece-by-piece breakdown

- This lab's defense specifically blocks input *containing* `../`. A naive filter checks for that literal substring and rejects the request if found.
- The bypass: most filesystem APIs, when given an **absolute path** (`/etc/passwd`, starting with a leading `/`) as the second argument to a path-join/concatenation function, will silently **discard the base directory entirely** and resolve straight from root. This is standard, documented behavior in many languages' path-joining functions (e.g. Python's `os.path.join('/var/www/images/', '/etc/passwd')` returns `/etc/passwd`, not a combined path).
- No `../` sequence appears anywhere in this payload, so the literal substring filter never triggers — yet the result is identical filesystem escape, because the *vulnerability* (trusting the filename argument unconditionally) was never actually about the `../` characters; the filter just assumed it was.

## 4. Lab 3 — Non-Recursive Stripping (Traversal Sequences Stripped Once)

```
GET /image?filename=....//....//....//etc/passwd HTTP/1.1
```

### Piece-by-piece breakdown

- This filter does remove `../` — but only as a **single, one-pass string replacement**, not recursively. It scans the input once, deletes every `../` it finds, and stops.
- `....//` — this is constructed so that when the filter strips the *inner* `../` substring out of `....//`, what's left behind is `../`. Walk through it: the string `....//` contains the substring `../` starting at position 2 (`..` + `.` + `/` + `/` reorganized — concretely, `....//`. removing the middle `../` leaves `../`. After the filter's single pass, `....//....//....//etc/passwd` becomes `../../../etc/passwd` — the exact payload from Lab 1, now reconstructed *after* the filter already ran.
- **Why one pass isn't enough:** the developer correctly identified the dangerous substring but implemented the fix as `input.replace("../", "")` instead of looping until no more replacements occur (or, better, resolving the absolute path and checking it starts with the intended base directory). A single non-recursive replace can always be defeated by pre-doubling the sequence so the *leftover* after stripping is the original malicious payload.

## 5. Lab 4 — Superfluous URL-Decode (Sequences Blocked, Then URL-Decoded)

```
GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/1.1
```

### Piece-by-piece breakdown

- This application's filter blocks raw `../` in the input **before** the web server/framework performs its own URL-decoding pass on the parameter. The filter runs first; decoding happens second — an ordering mistake.
- `%252f` is the **double URL-encoded** form of `/`. Breaking down the encoding layers: `/` → single-encode → `%2f` → encode again → `%25` (the encoded form of `%`) followed by `2f` → `%252f`.
- When the request arrives, the access-control filter inspects the raw query string, sees `..%252f` — which does **not** contain the literal substring `../` — and lets it pass.
- *After* the filter, the standard HTTP parameter-decoding layer URL-decodes the value **once**: `%25` becomes `%`, turning `..%252f` into `..%2f`. The filter has already run and already approved the request by this point.
- The application then uses this once-decoded value directly in the file path. Depending on the platform, the underlying filesystem/OS layer or a second internal decode step interprets `..%2f` — or in some implementations the framework performs a second decode pass on path segments, fully reconstructing `../`. The net effect verified in this lab is that the traversal sequence reassembles **after** the point where the filter already approved the input, completely bypassing it.
- **Lesson for testing in general:** any time a filter operates on a raw string before decoding occurs, double-encoding is a near-universal bypass technique — applicable far beyond path traversal (it works the same way against many other input filters, including some WAF rules).

## 6. Lab 5 — Validation of Start of Path

```
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/1.1
```

### Piece-by-piece breakdown

- This application transmits the **entire path** as the parameter (not just a filename) and validates that the supplied value **starts with** the expected base directory string, `/var/www/images`.
- `filename=/var/www/images/../../../etc/passwd` — the string genuinely does start with `/var/www/images`, so the validation check (`input.startsWith("/var/www/images")`) passes.
- The validation never re-checks what the path **resolves to** after the traversal sequences that follow are processed. `/var/www/images/../../../etc/passwd` still walks up three directories from `/var/www/images/` (through `/var/www/`, `/var/`, to `/`) and then descends into `etc/passwd` — landing at `/etc/passwd`, completely outside the directory whose name satisfied the validation check.
- **Why "starts with" checks are insufficient:** validating a *prefix* of a string tells you nothing about where the *fully resolved* path ends up once `../` sequences are applied. The only safe check is to resolve the path first (canonicalize it) and then verify the canonical result is still inside the allowed directory.

## 7. Lab 6 — Validation of File Extension with Null Byte Bypass

```
GET /image?filename=../../../etc/passwd%00.png HTTP/1.1
```

### Piece-by-piece breakdown

- This application validates that the supplied filename **ends with** an approved image extension (`.png`, `.jpg`, etc.) before opening it — a check meant to limit the file-read operation to image files only.
- `../../../etc/passwd` is the same directory-escape payload from Lab 1, doing the same job: walking up to root, then into `etc/passwd`.
- `%00` is the URL-encoded representation of the **null byte** (`\x00`), a control character historically used in C-family languages (and the lower-level OS/filesystem APIs many web frameworks ultimately call into) to mark the **end of a string**.
- `.png` is appended *after* the null byte purely to satisfy the string-suffix check performed at the **application/scripting layer** — that layer sees the full string `../../../etc/passwd%00.png`, decodes `%00`, and confirms it ends in `.png`. Validation passes.
- However, when that same string is handed down to a **lower-level system call** that opens the file, many such calls treat the null byte as a hard string terminator and stop reading right there — effectively truncating the path to `../../../etc/passwd` before the `.png` is ever considered. The file that actually gets opened is `/etc/passwd`, not a `.png` file.
- This is the classic "two layers of the stack disagree about where a string ends" bug — identical in spirit to the URL-matching discrepancies in file 4, just manifesting at the C-string level instead of the HTTP-routing level.
- **Modern caveat:** many current language runtimes (modern PHP, Java, etc.) now reject null bytes in strings outright specifically because of this historical class of bug — but it remains essential lab knowledge because legacy systems, certain native extensions, and some lower-level file APIs in older runtimes still exhibit it, and it's a textbook illustration of validation-layer mismatch.

## 8. Real-World Notes

- Path traversal is formally tracked as **CWE-22: Improper Limitation of a Pathname to a Restricted Directory**, and it routinely appears in CVEs for everything from CMS plugins to network appliance firmware web UIs.
- In real engagements, path traversal frequently escalates beyond read access: if the same parameter is used in a **file write/upload** path (not just read), the same techniques can let an attacker write a web shell outside the intended upload directory — turning an access-control bug into remote code execution.
- The only fully robust fix (per PortSwigger's own guidance) is to avoid passing user input into filesystem APIs at all where possible — e.g. map user-supplied identifiers to a fixed, server-controlled list of permitted filenames, rather than trying to sanitize an arbitrary path string. Every defense shown failing in this file (substring blocking, prefix validation, suffix validation) is a sanitization-based approach; sanitization of path strings is notoriously hard to get exhaustively right, which is exactly why so many distinct bypass variants exist.
