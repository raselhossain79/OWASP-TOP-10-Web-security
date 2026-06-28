# 05 — Upload-to-RCE Escalation Chains

Files 03 and 04 covered individual bypass techniques in isolation. This file assembles
them into complete attack chains, and covers the remaining techniques that aren't really
"bypasses" of a check so much as exploitation of what happens *structurally* around the
upload feature: file overwrites, path traversal into execution-enabled directories, and
race conditions in the upload-then-validate process itself.

## The full webshell-to-RCE chain, step by step

Putting everything together, a complete real-world chain typically looks like this:

1. **Reconnaissance:** identify an upload feature, determine what server/stack is in use
   (response headers, error pages, default file extensions accepted elsewhere in the
   app), and probe what validation exists by trying an obvious malicious upload first
   (e.g. plain `shell.php` with no obfuscation) — this is effectively testing for the
   complete absence of validation, the baseline, worst-case scenario.
2. **Bypass whatever validation is present**, using the appropriate technique(s) from
   File 03 (extension/Content-Type) and/or File 04 (content/magic-byte), depending on
   what the server actually checks. Real applications often check more than one thing,
   so chains frequently combine techniques — e.g. a Content-Type spoof *and* a case-
   manipulated extension, because the app checks both fields.
3. **Confirm the file landed somewhere web-accessible.** The application's response to
   a successful upload (a returned URL, a "view profile" link, a predictable storage
   path pattern) usually reveals where the file lives. If it doesn't, common
   conventions to test: `/uploads/`, `/files/`, `/media/`, or a path mirroring the form
   field name.
4. **Confirm the destination directory actually executes the relevant extension.**
   This is a separate condition from "the file uploaded successfully" — some
   applications deliberately store uploads in a directory configured *not* to execute
   scripts (a standard, correct mitigation). If your `.php` file's bytes are returned
   verbatim as plaintext/source when requested, rather than executed, the directory is
   non-executable, and you need either a path-traversal write (below) or a different
   directory entirely.
5. **Trigger execution** by sending a normal `GET` request to the uploaded file's URL.
   At this point the server treats the request like any other request for that
   extension — assigning request parameters to variables and running the script.
6. **Use the webshell** — for a one-liner like `<?php system($_GET['cmd']); ?>`, simply
   append `?cmd=id` (or your actual command) to confirm code execution, then escalate to
   a more capable webshell or reverse shell as needed for the engagement.

The PHP one-liners themselves, broken down:

```php
<?php echo file_get_contents('/path/to/target/file'); ?>
```
- `file_get_contents()` reads an arbitrary file path **on the server's filesystem**,
  passed as a literal string here, but normally parameterized via a request value in a
  more flexible shell. `echo` sends that file's contents back in the HTTP response body.
  This single line gives arbitrary file *read*, useful for grabbing config files,
  source code, or credentials without yet achieving command execution.

```php
<?php echo system($_GET['command']); ?>
```
- `$_GET['command']` pulls a value directly from the URL query string the attacker
  controls (`?command=id`). `system()` passes that string to the OS shell and returns
  its output. This is full, arbitrary OS command execution — the realistic endpoint of
  a successful webshell upload.

---

## Path traversal in filenames, used to escape a non-executable upload directory

This is the practical payoff of File 03's path traversal technique, applied to the
specific problem in step 4 above: your file uploaded fine, lands in a directory that
*correctly* doesn't execute scripts — so instead of trying to find a content/extension
bypass for that directory's restrictions, you use the `filename` field itself to write
the file somewhere else entirely.

```
Content-Disposition: form-data; name="avatar"; filename="../../../var/www/html/uploads-executable/shell.php"
```

If the server-side save logic is naive string concatenation of `upload_dir + filename`
with no traversal sanitization, the resulting path resolves outside the intended,
locked-down upload directory and into a different, script-executing directory
elsewhere on the filesystem — assuming the web server process has write permissions
there, which it often does if multiple parts of the application share a webroot.

---

## File overwrite attacks

### The flaw

The server saves the uploaded file using the **attacker-supplied filename verbatim**,
with no randomization and no collision check, in a location where overwriting an
existing file has consequences beyond just losing a previous upload.

### Mechanism

If an attacker can determine or guess the filename of an existing, important file —
another user's avatar, a configuration file, or (most dangerously, combined with the
path traversal technique above) an application source file like `index.php` or a
`.htaccess`/`web.config` already present for legitimate reasons — uploading a new file
with that exact name silently replaces it. Depending on what's overwritten:

- Overwriting **another user's uploaded file** (e.g. avatar) by predictable naming —
  a low-severity but real defacement/IDOR-adjacent issue.
- Overwriting an **application file directly reachable via path traversal** — can range
  from defacement (replacing a page's content) up to RCE, if the overwritten file is
  itself a script that gets executed elsewhere in the application flow.
- Overwriting a **server configuration file** (`.htaccess`/`web.config`) that already
  exists for legitimate reasons — could downgrade or remove existing security
  directives the original file enforced.

### Why this is a separate concern from "filename validation" in File 03

File 03's techniques are about getting a *dangerous extension* past a check. File
overwrite is about the *absence of filename randomization/collision-handling*, which is
a distinct mitigation from extension whitelisting — an application can correctly
whitelist extensions and still be vulnerable to overwrite if it doesn't rename uploads
to something unpredictable (a UUID, a hash of the content, etc.) before saving.

---

## Race conditions in the upload-and-validate process

### Why this exists at all

Modern frameworks are generally hardened against the techniques above: they upload to a
temporary, sandboxed location first, perform validation there, and only move the file to
its final destination — and rename it to something unpredictable — once it's confirmed
safe. Teams that implement their own upload handling independently of a framework,
however, sometimes introduce a window where the file is briefly present, with its real
name, in a publicly-accessible location, *before* validation has finished and
potentially deleted it.

### Mechanism, step by step

1. Some hand-rolled implementations write the uploaded file **directly to its final,
   public destination first**, then run validation (e.g. an antivirus scan, or a content
   check) against that file *in place*, and delete it afterward if it fails.
2. Between the moment the file is written and the moment it's deleted (if it fails
   validation), the file is live and requestable on the server, with its actual name,
   for however many milliseconds that validation step takes.
3. An attacker who can request the file's predictable URL **during that window** can
   trigger its execution before the deletion happens — completely bypassing whatever the
   validation logic would have concluded, because execution already occurred before the
   verdict was reached.
4. **Exploitation in practice** requires sending the upload request and the
   triggering `GET` request to the file's known/guessable URL as close to simultaneously
   as possible, repeatedly, to land inside the narrow timing window — typically done with
   Burp Suite's Turbo Intruder extension running both request streams in parallel with
   minimal delay, rather than relying on manual timing.

### Race conditions in URL-based uploads specifically

Some upload features let the user supply a **URL** instead of a file directly (e.g.
"import an image from a link"), which the server then fetches itself. This introduces a
slightly different version of the same race:

- The server has to download the remote file into a local temporary location before it
  can validate anything — and because this fetch happens over the network rather than
  through a framework's built-in multipart upload handling, developers frequently
  implement their *own* temporary storage and validation logic for this path,
  independent of (and often less battle-tested than) the standard upload pipeline.
- If the temporary file is given a randomized name (e.g. via PHP's `uniqid()`) to
  prevent guessing, the strength of that protection depends entirely on how
  *unpredictable* the randomization actually is — `uniqid()` is based on the system
  clock at microsecond resolution and is, despite the name, brute-forceable within a
  practical range if you know roughly when the request was made.
- **Extending the timing window:** an attacker can deliberately upload a larger file,
  exploiting chunked processing, by placing the malicious payload at the very start of
  the file and padding the rest with arbitrary bytes — this extends how long the server
  spends processing/transferring the file, which extends the brute-force window for
  guessing the randomized temporary filename before validation completes and the file
  is removed or moved.

### Real-world note

Race condition bugs in file upload pipelines are subtle, often invisible during normal
black-box testing unless you specifically suspect a custom (non-framework) upload
implementation, and are correspondingly rarer in bug bounty reports than the more
straightforward techniques in Files 03–04 — but when found, they're highly credible,
high-severity findings precisely because they prove the *entire* validation pipeline
provides no real guarantee, regardless of how thorough the validation logic itself looks
on paper.

---

## Uploading via the PUT method, bypassing the upload form entirely

### Mechanism

Some web servers are configured to support the HTTP `PUT` method on certain paths,
intended for use cases like WebDAV or REST-style resource creation — independent of
whatever upload *form* the application exposes in its UI.

```
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

If this method is enabled and not separately access-controlled, it provides a way to
write a file directly to a chosen path on the server with **no application-level upload
form, and therefore no application-level validation logic at all** — because `PUT`
support is typically a web-server-level feature, sitting entirely outside whatever
validation the application's own upload-handling code performs. This means none of the
techniques in Files 03–04 are even necessary; the bypass *is* the existence of this
alternate write path.

### How to find it

Send an `OPTIONS` request to candidate endpoints/directories and inspect the `Allow`
header in the response — if it lists `PUT`, the server is advertising support for it on
that path, worth testing directly.

---

## Real-world chaining beyond the initial RCE

Getting a webshell is rarely the actual end goal in a real engagement or a serious bug
bounty submission — it's a foothold. Common next steps that build on this initial
access, worth being aware of even though they're outside this series' scope:

- **Internal network pivoting** — using the webshell as a proxy to reach internal
  services not directly exposed to the internet.
- **Cloud metadata SSRF** — if the compromised server runs in a cloud environment, the
  webshell can be used to query the instance metadata service (e.g.
  `http://169.254.169.254/`) for temporary cloud credentials, escalating from a single
  compromised host to broader cloud account access (see the dedicated SSRF material for
  the underlying mechanics).
- **CI/CD artifact upload abuse** — the same upload-to-RCE logic applies to build
  artifact ingestion pipelines, container registries, and package repositories, where a
  malicious "build output" or "package" upload can lead to supply-chain-level
  compromise rather than just one web server.

These are mentioned for context and chain-awareness, not covered in depth here, since
each is its own substantial topic with dedicated material elsewhere in this reference
library.
