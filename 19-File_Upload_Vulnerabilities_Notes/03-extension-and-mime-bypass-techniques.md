# 03 — Extension and MIME Bypass Techniques

This file covers every technique for getting a malicious file past extension and
Content-Type checks specifically — i.e., checks that inspect the `filename` and
per-part `Content-Type` fields described in File 02, without (yet) inspecting the actual
file contents. File 04 covers the next layer up (content/magic-byte checks).

Every technique here follows the same underlying logic: **find a discrepancy between
what the validation code checks and what the execution environment actually does**, and
exploit the gap between them.

---

## Technique 1: Content-Type (MIME) spoofing

### The flaw

A server validates uploads by checking that the per-part `Content-Type` header inside
the multipart request equals an allowed value, e.g. `image/jpeg` or `image/png`. It does
**not** independently verify that the actual bytes match that declared type.

### The mechanism, piece by piece

Recall from File 02 that this header is just attacker-supplied text, sent inside the
`Content-Disposition` part of the multipart body:

```
------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg

<?php echo system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

What's happening:

- The **`filename="shell.php"`** tells the server-side handler the original name —
  potentially used to decide the saved extension.
- The **`Content-Type: image/jpeg`** is a deliberate lie. The actual content that
  follows is a PHP one-liner, not JPEG binary data.
- If the server's check is literally `if ($_FILES['avatar']['type'] !== 'image/jpeg') { reject(); }`,
  this check reads `image/jpeg` exactly as declared and passes — because PHP's
  `$_FILES[...]['type']` is populated directly from this client-supplied header, not
  from any inspection of the file's actual bytes. The check is validating a string the
  attacker wrote, against another string the attacker also controls indirectly.

### How to perform it

1. Upload any normal file once through the application UI to see the baseline request
   shape in Burp Proxy history.
2. Send that request to Repeater.
3. Change `filename="..."` to your payload's intended extension (e.g. `.php`).
4. Change the binary body content to your webshell payload.
5. **Leave (or set) `Content-Type: image/jpeg`** in the part header — this is the
   specific field this technique targets. Forward the request.
6. If accepted, request the uploaded file's URL directly to trigger execution (assuming
   the destination directory executes the relevant extension — see File 05 for the full
   chain).

### Real-world note

This is the *easiest* and most commonly found variant of file upload bypass in the wild,
because it requires the developer to have made exactly one mistake (trusting a header)
rather than several. It's an extremely common finding in bug bounty programs running
older or hand-rolled upload handlers, and is the PortSwigger Academy's apprentice-level
introduction to flawed validation for exactly this reason — see File 06 for the lab
mapping.

---

## Technique 2: Path traversal in the filename field

### The flaw

The server uses the attacker-controlled `filename` value, or a value derived from it,
directly when constructing the path to write the file to — without stripping directory
traversal sequences.

### The mechanism, piece by piece

```
Content-Disposition: form-data; name="avatar"; filename="../../../var/www/html/shell.php"
```

- Server-side code might do something conceptually like:
  `save_path = upload_dir + "/" + filename`
- If `filename` contains `../../../var/www/html/`, simple string concatenation
  resolves the traversal sequences when the OS interprets the path, walking **up and out
  of** the intended upload directory and back down into a directory the server is
  configured to execute scripts from.
- This matters because it can let an attacker **escape a deliberately
  non-executable upload directory** (one of the standard mitigations — see File 05) and
  land the payload in a directory where PHP execution is enabled.
- It can also be used more narrowly to control just the *destination directory*, without
  full traversal, if the application is vulnerable to less obvious filename injection
  (e.g. forward slashes creating unintended subdirectories).

### Real-world note

This combines two normally-separate bug classes — path/directory traversal and file
upload — into a single request. It's a good example of why this series treats file
upload as cutting across categories rather than being one isolated technique: the
underlying flaw here (unsanitized path construction from user input) is the same root
cause as classic directory traversal vulnerabilities, just reached via the `filename`
field of an upload instead of a URL parameter.

---

## Technique 3: Insufficient extension blacklisting

### The flaw

The server blocks a specific, known-dangerous extension (most commonly `.php`) but
doesn't account for the **full set** of extensions a given server is actually configured
to execute as code.

### The mechanism, piece by piece

Apache, in particular, can be configured (via `AddHandler` or `AddType` directives) to
execute a much wider range of extensions as PHP than developers typically remember to
blacklist:

```
.php, .php3, .php4, .php5, .phtml, .pht, .phar
```

A blacklist that only checks for `.php` lets `shell.php5` or `shell.phtml` straight
through, while the underlying Apache configuration still executes them as PHP because
the handler mapping was configured broadly (often by default, or by a hosting provider's
shared configuration) rather than narrowly.

### Sub-technique: overriding the server configuration directly

A more powerful version of this same root cause: if the upload directory doesn't block
uploading **configuration files themselves**, you don't need to guess which alternate
extension the server already executes — you can define a new one yourself.

For Apache, this means uploading a `.htaccess` file:

```apache
AddType application/x-httpd-php .whatever-extension-you-want
```

Breaking down why this works:

- Apache supports per-directory configuration overrides via a file literally named
  `.htaccess`, checked at request time for the directory the requested file lives in.
- If the upload feature doesn't restrict `.htaccess` as a filename (it has no
  extension in the traditional sense, so naive extension blacklists frequently miss it
  entirely), the attacker uploads this file into the target directory first.
- From that point on, Apache treats **any** file in that directory with the chosen
  extension as PHP — including an extension that wasn't on any blacklist because the
  attacker invented it for this purpose, then uploads `shell.whatever-extension-you-want`
  as a second request.
- The equivalent on IIS is a `web.config` file using `<handlers>` or `<staticContent>`
  directives to remap an extension to an executable handler.

### Real-world note

Blacklists are a fundamentally weak control because they require the defender to
enumerate every dangerous possibility in advance, while the attacker only needs to find
one the defender missed. This is precisely why OWASP's prevention guidance (see File 06)
recommends **whitelisting** allowed extensions instead of blacklisting denied ones — it's
far easier to correctly say "only allow `.jpg`, `.png`, `.pdf`" than to correctly say
"block every conceivable code-execution extension across every web server this
application might ever run on."

---

## Technique 4: Obfuscating the file extension to slip past a blacklist's string match

### The flaw

The blacklist/regex check is implemented with subtly different parsing logic than the
component that later determines the file's executable type — so a filename can satisfy
the check's pattern-matching while still being treated as the dangerous extension by the
server.

This is the densest technique cluster in file upload testing. Each variant below targets
a different specific parsing discrepancy.

### 4a. Case manipulation

```
shell.pHp
```

- **Mechanism:** if the blacklist check is a case-sensitive string comparison (e.g.
  `if (extension == ".php")`) but the subsequent extension-to-MIME-type mapping used by
  the web server to decide execution is case-*insensitive* (common on
  case-insensitive filesystems, and in many server configs), the check fails to match
  `.pHp` against `.php`, while the server still executes it as PHP afterward.

### 4b. Double extensions

```
shell.php.jpg
```

- **Mechanism:** depends entirely on how the parsing code extracts "the extension."
  - If validation logic looks only at the *last* segment after a dot (`.jpg`) — it
    passes the image check.
  - If the *web server* (for execution purposes) determines file type by checking
    whether the filename **contains** `.php` anywhere, rather than strictly the final
    segment, it still executes the file as PHP. Some legacy Apache `mod_mime`
    configurations using `AddHandler` apply the PHP handler based on **any** matching
    extension component in a multi-dotted filename, not just the last one — this is the
    exact discrepancy this technique targets.

### 4c. Trailing characters

```
shell.php.
shell.php%20
```

- **Mechanism:** some components (often filesystem-handling code, or specific OS/library
  behavior on Windows) silently strip trailing dots or whitespace when resolving a
  filename to disk, while the validation layer's string check (`endswith(".php")`, for
  instance) does **not** match `"shell.php."` because of the trailing dot. The
  validator says no match, the filesystem strips the dot and saves/executes
  `shell.php`.

### 4d. URL encoding / double URL encoding of dots and slashes

```
shell%2Ephp
shell%252Ephp
```

- **Mechanism:** `%2E` is the URL-encoded form of `.`. If the filename value is taken
  from a context where it isn't decoded *before* the extension blacklist check runs, but
  **is** decoded later, server-side, before the file is saved or served — the blacklist
  inspects the literal string `shell%2Ephp` (which obviously doesn't match `.php`), while
  the eventual decoded filename written to disk is `shell.php`. Double encoding
  (`%252E`, where `%25` is the encoded form of `%`) targets situations where a single
  decoding pass happens before validation but a second decoding pass happens afterward.

### 4e. Null byte and semicolon injection

```
shell.asp%00.jpg
shell.asp;.jpg
```

- **Mechanism:** this exploits a discrepancy between the language the validation logic
  is written in and the lower-level system call eventually used to handle the file.
  High-level languages like PHP and Java treat `%00` (a decoded null byte, `\x00`) as
  just another byte inside a string — so the validation check sees the full string
  `shell.asp\x00.jpg` and might decide the extension is `.jpg` (matching the last
  segment) and pass it. But the underlying C/C++ runtime, or certain legacy server/OS
  combinations, treats a null byte as a **string terminator** — so when that filename
  reaches a lower-level file-write or file-type-determination call, it sees the string as
  ending at `shell.asp`, truncating everything after the null byte. The semicolon variant
  targets specific legacy server stacks (historically some Java application servers)
  that treat `;` in a path as introducing a separate path parameter, again causing
  high-level and low-level parsing to disagree about where the "real" filename ends.
  Modern frameworks have mostly patched null byte truncation, but it remains worth
  testing against legacy or unusual stacks, and is a useful concept to understand even
  where it no longer directly works, because the *general pattern* (high-level vs
  low-level parsing disagreement) recurs constantly in this category.

### 4f. Multibyte Unicode overlong encoding

```
shell.phpxC0x2E   (illustrative — overlong encoding of '.')
```

- **Mechanism:** UTF-8 has a strict canonical encoding for each character, but malformed
  "overlong" encodings exist that represent the same character using more bytes than
  necessary (e.g. encoding `.` — normally a single byte `0x2E` — using a two-byte
  sequence like `0xC0 0xAE`). A correct UTF-8 decoder should reject overlong sequences as
  invalid, but some implementations normalize or "helpfully" decode them anyway,
  converting the overlong sequence back into the literal `.` (or null byte) *after* the
  validation step has already looked at the raw (still-encoded, still-look-harmless)
  bytes and decided they don't match a blocked pattern. This is the same parsing-order
  discrepancy as the URL-encoding technique above, just operating at the byte-encoding
  level instead of the percent-encoding level.

### 4g. Recursive-strip bypass (non-recursive sanitization)

```
shell.p.phphp
```

- **Mechanism:** if the server's mitigation is to **strip** the substring `.php`
  wherever it finds it (rather than reject the upload outright), and that stripping is
  applied only **once**, not recursively/repeatedly until no more matches exist, then a
  carefully doubled-up filename leaves a valid dangerous extension behind after a single
  strip pass: stripping `.php` from `shell.p.phphp` removes the middle `.php`+`hp`
  overlap... walking through it precisely — the string `shell.p.phphp` contains the
  substring `.php` starting right after `shell.p`. Removing that one occurrence of
  `.php` from `shell.p.phphp` leaves `shell.php`, a fully valid, dangerous extension that
  exists only *because* the stripping operation itself reassembled it from the
  surrounding characters. A non-recursive strip operation has no way to "notice" the new
  match it just created.

---

## Where this leaves you: extension/Content-Type bypass vs. content bypass

Every technique above defeats checks that look at **metadata about the file**
(`filename`, `Content-Type`) without inspecting the actual bytes. A server that goes
further — checking magic bytes, validating image dimensions via `getimagesize()`, or
fully parsing the file structure — closes off all of the above in one move, because none
of these techniques change what the actual file *contents* look like; a `shell.php`
saved with double-URL-encoded dots is still, at the byte level, a PHP script with no
JPEG structure whatsoever.

File 04 covers exactly that next layer: how to construct files that pass **content**
validation too, by building polyglots that are simultaneously valid as the expected
format and as executable/malicious code.
