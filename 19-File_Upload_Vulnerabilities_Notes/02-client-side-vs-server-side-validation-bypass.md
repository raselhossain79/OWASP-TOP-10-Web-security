# 02 — Client-Side vs Server-Side Validation Bypass

Real applications very rarely implement *only* server-side or *only* client-side
validation. They almost always layer both, for different reasons — and understanding why
each exists, and exactly what each one can and can't stop, is the foundation for every
bypass technique that follows.

## Why client-side validation exists at all

Client-side checks (a JavaScript handler on the `<input type="file">` change event, or
the HTML `accept` attribute) exist purely for **user experience**, not security:

- Instant feedback ("Please upload a .jpg or .png") without a round trip to the server.
- Reduced wasted bandwidth — no point uploading a 50MB file just to have the server
  reject it.
- A smoother form-completion flow, which matters for conversion-sensitive features like
  KYC document upload or resume submission.

None of these reasons are security reasons. This is the single fact you need to fully
internalize: **the browser running the JavaScript is the attacker's own computer.** The
attacker controls every line of code executing in that context. There is no version of
client-side validation that can be a security boundary, because the entity being asked
to enforce the rule is the same entity trying to break it.

## Mechanism: exactly why client-side checks are trivially bypassable

Consider a typical client-side check:

```html
<input type="file" id="upload" accept=".jpg,.jpeg,.png">
<script>
document.getElementById('upload').addEventListener('change', function(e) {
  const name = e.target.files[0].name;
  if (!name.match(/\.(jpe?g|png)$/i)) {
    alert('Only images are allowed');
    e.target.value = '';
  }
});
</script>
```

Walk through what this actually does:

1. The `accept` attribute only **filters which files the native file picker dialog
   shows** — it has zero effect once a file is selected, and several browsers let you
   override it by manually typing a filename or selecting "All Files" in the picker.
2. The `change` event handler runs *in the browser*, reading `e.target.files[0].name` —
   a property the attacker set by choosing the file. It performs a regex check and, if it
   fails, clears the input client-side.
3. **Critically: none of this logic constructs or sends the actual HTTP request.** The
   request is built by the browser's form-submission machinery (or by your own
   JavaScript `fetch`/`XHR` call) afterward. If you intercept and modify the request at
   that later stage — or skip the browser UI path entirely — this validation code never
   even executes, because nothing forces the HTTP request to match what the file picker
   showed.

### How to actually bypass it (mechanically, step by step)

The standard bypass workflow, and what's happening at each step:

1. **Intercept the request with Burp Suite (Proxy or Repeater).** This sits between your
   browser and the server. The JavaScript validation already ran (or you select a file
   that passes it, e.g. `shell.jpg`), the browser builds the multipart request, and Burp
   captures it *before* it reaches the server.
2. **Edit the captured request directly** — change the `filename="shell.jpg"` field to
   `filename="shell.php"`, and/or replace the body content with your payload. You're
   editing raw bytes of the HTTP request, completely independent of any browser-side
   logic. The JavaScript that ran earlier has no further influence — it already did its
   job and stopped.
3. **Forward the modified request with Repeater/Resend.** The server receives a request
   it has no way of knowing went through any client-side filtering at all — from the
   server's point of view, this looks identical to a request from a custom script that
   never touched a browser.
4. Equivalently, you can skip the browser entirely and craft the multipart request from
   scratch with `curl`, `requests` (Python), or a simple HTML form with `accept`/JS
   removed, pointed at the same upload endpoint.

The point isn't "use Burp" specifically — it's that **the validation logic and the
request-sending logic are decoupled**, and an attacker who controls the client (which is
always true) can drive the second without ever triggering the first.

## Server-side validation: the real trust boundary

Everything from here on targets server-side checks, because that's the only validation
that actually runs in an environment the attacker doesn't control. To understand the
bypasses in Files 03–05, you need to understand the exact structure of what the server
receives.

### Anatomy of a multipart/form-data upload request

Browsers send file uploads using `Content-Type: multipart/form-data`, not the more
familiar `application/x-www-form-urlencoded` used for simple text fields. This is
because urlencoding is unsuitable for large binary data — multipart instead splits the
body into separate, boundary-delimited parts, one per form field:

```
POST /images HTTP/1.1
Host: vulnerable-website.com
Content-Length: 12345
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="avatar"; filename="profile.jpg"
Content-Type: image/jpeg

[...binary bytes of profile.jpg...]
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="username"

wiener
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

Breaking down exactly what's attacker-controlled here, piece by piece:

- **`boundary=----WebKitFormBoundary...`** in the outer `Content-Type` header — a
  delimiter string the client chooses, marking where one form field ends and the next
  begins. Attacker-controlled, but rarely security-relevant on its own.
- **`Content-Disposition: form-data; name="avatar"; filename="profile.jpg"`** — the
  `name` attribute identifies which form field this part corresponds to server-side
  (e.g. `$_FILES['avatar']` in PHP). The **`filename` attribute is the original filename
  the browser read off the attacker's local file** — fully attacker-controlled text,
  sent as-is. Many servers use this value, or a value derived from it, to decide the
  saved file's name *and sometimes its destination path*. This single field is the root
  cause of extension bypass (File 03) and path traversal in filenames (File 05).
- **The per-part `Content-Type: image/jpeg`** — this is the MIME type the *browser*
  guessed based on the file's extension, or whatever the attacker manually set it to in
  Burp. It is not derived from inspecting the actual bytes that follow — it's just
  another text field. A server that checks this header and stops there is checking
  attacker-supplied metadata, identical in trust level to checking the `filename` value.
- **The binary content itself** (`[...binary bytes...]`) — this is the only piece of the
  request that the attacker cannot simply *declare* their way around. To pass a check
  against this, the actual bytes have to satisfy whatever the server inspects (a magic
  byte sequence, valid image structure, etc.) — which is why content-based validation is
  meaningfully stronger than filename/Content-Type checks, and why bypassing it (Files
  03–04) requires constructing real, parseable file structures rather than just editing
  a text field.

### Why this dual nature (text fields vs. binary payload) matters

The core asymmetry that drives the rest of this series: **`filename` and the per-part
`Content-Type` are strings the server has to trust or independently verify — there is no
third option.** A secure implementation treats them as hints at best (perhaps useful for
choosing a default display name) and never as the basis for a security decision. An
insecure implementation uses them directly to decide what extension to save the file
with, what MIME type to serve it back as, or — worse — to determine where on disk it
gets written.

Every bypass technique in Files 03 through 05 is really just exploiting one specific
instance of "the server trusted a value it shouldn't have," or "the server's content
check looked at the wrong thing, or not enough of it." Keep this multipart structure in
mind — when each file says "modify the filename field" or "modify the Content-Type
header," it's referring to these exact fields inside this exact request structure, sent
via Repeater after client-side checks have already been bypassed by the method described
above.

## Real-world note: WAFs and CDNs add a third layer, but it's the same category

In production environments, you'll often find a third validation layer in front of the
application server itself — a WAF or CDN rule blocking requests where the `filename`
matches a denylist pattern, or restricting allowed `Content-Type` values at the edge.
Mechanically these are no different from the application-level checks described above:
they're still inspecting the same attacker-controlled `filename` and `Content-Type`
fields, just earlier in the request path. The obfuscation techniques in File 03
(case manipulation, encoding tricks, alternate extensions) work against WAF-layer
filename checks for exactly the same reason they work against application-layer ones —
parsing discrepancies between the layer doing the check and the layer doing the
execution.
