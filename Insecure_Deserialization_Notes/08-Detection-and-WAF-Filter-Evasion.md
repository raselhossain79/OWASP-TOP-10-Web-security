# 08 — Detection and WAF/Filter Evasion

This file collects evasion and obfuscation techniques across all four languages. Unlike
injection-style topics (SQLi, XSS), deserialization "WAF bypass" is less about escaping quote
characters and more about **defeating signature/pattern matching on the serialized structure
itself**, and about getting a malicious payload past content-type or file-extension
restrictions. Treat this file as the companion to whichever per-language file (03–07) you're
actively working from.

## 1. Why Deserialization Payloads Are Often Hard to Signature-Match (In Your Favor)

A WAF that wants to block, say, a Commons Collections gadget chain has to pattern-match against
*Base64-decoded* serialized bytes — it can't just look for plaintext keywords the way it can
with `<script>` or `UNION SELECT`. This already makes naive WAF rules weak against this bug
class, but real-world WAFs (and custom application-level filters) still commonly try, using
techniques like:

- Blacklisting known-dangerous class names as substrings (`InvokerTransformer`,
  `ObjectDataProvider`, `os.system`, `__reduce__`) either in raw or Base64-encoded form.
- Blocking known magic-byte prefixes (`rO0` for Java, `O:` for PHP, `\x80` for pickle).
- Rejecting overly large request bodies/cookies (gadget chains can be large).
- Generic deny-lists on file upload extensions (relevant to the PHAR technique in File 03).

## 2. PHP-Specific Evasion

### 2.1 Case and whitespace tolerance in the format itself

PHP's serialization format is strict about its length-prefix syntax but the *class names* and
*string contents* inside it are exactly what you put there — there's no extra obfuscation layer
built into the format itself. Evasion at this layer is mostly about **avoiding the literal class
name appearing in plaintext** if a filter blacklists specific class names:

- If multiple classes in the target's autoloaded codebase can serve the same gadget role
  (common in larger frameworks with several near-identical utility classes), switching to an
  alternate class with the same dangerous method achieves the same effect while not matching a
  blacklist built around one specific class name.

### 2.2 PHAR extension bypass (ties directly to File 03 Section 5)

Since the PHAR technique relies on getting an arbitrary-content file uploaded under **any**
filename, the relevant evasion isn't about the serialized payload at all — it's standard file
upload validation bypass: renaming `.phar` to an allowed extension (`.jpg`, `.gif`), since the
later `phar://` stream-wrapper trigger doesn't care about the file's actual extension, only its
internal Phar-format structure. If the upload validator checks **magic bytes/content**, not just
the extension, you instead need to find a way to make the file *also* pass as a valid image
(e.g. prepending a valid GIF header before the Phar archive structure — Phar parsing tolerates
extra leading bytes before its own format markers in many implementations, though this varies
and should be tested against the specific target).

### 2.3 Hackvertor for safe iterative testing

Mentioned in File 03 — Hackvertor's main *evasion-relevant* value is that it lets you keep all
your edits in a clean, decoded, human-readable form and have it recompute length prefixes and
final encoding automatically, which matters when you're rapidly trying several different class
names/payloads against a filter and can't afford to manually break the byte-length math on every
attempt.

## 3. Java-Specific Evasion

### 3.1 Choosing among multiple equivalent gadget chains

ysoserial (File 05) ships many payload names precisely because different applications have
different libraries on their classpath — but this multiplicity is also your primary evasion
tool against a filter blacklisting specific class names. If `CommonsCollections6`'s payload gets
blocked because a filter denies requests containing the string `InvokerTransformer` (even
Base64-decoded, if the filter decodes before matching), try a different `CommonsCollections{N}`
variant, or a chain through an entirely different library (`Spring1`, `Groovy1`, `Hibernate1`)
that achieves the same RCE outcome through different class names.

### 3.2 Compression

Some deserialization-accepting endpoints support Gzip-compressed input transparently (common
where the application also accepts compressed uploads/requests generally). Gzip-compressing
the serialized payload before delivery defeats any filter that only pattern-matches the
plaintext/Base64 form, since the compressed bytes look nothing like the signatures the filter
was built around — but this only works if the *target itself* decompresses before
deserializing, which you need to confirm rather than assume.

### 3.3 Custom chain construction as the ultimate evasion

If every known public chain for the libraries present is specifically blacklisted, falling back
to the **custom gadget chain** approach from File 02 Section 4.2 / File 04 Section 7 sidesteps
the entire problem, since a hand-built chain through the application's own classes won't match
any signature built around well-known public tool output.

## 4. Python-Specific Evasion

### 4.1 Avoiding obviously-dangerous callables in plain sight

A naive filter might block any pickle containing the literal bytes for `os` or `system` as a
module/function name. Since `__reduce__` accepts **any** callable, you have wide latitude to
choose a less-obviously-named but equally dangerous one:

```python
class Exploit:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))
```

- `eval` as the callable, with a string argument that performs the import and call dynamically
  at execution time rather than naming `os.system` directly inside the pickle's opcode stream —
  this changes what literal text/bytes appear in the serialized payload, which is exactly what
  a substring-based filter is checking.

### 4.2 Manually crafting opcodes instead of using `pickle.dumps`

Because `pickletools` lets you both **disassemble** and the underlying opcode language lets you
**hand-write** a pickle byte stream directly (rather than always going through
`pickle.dumps(SomeClass())`), advanced evasion involves emitting pickle opcodes that achieve the
same `GLOBAL` + `REDUCE` effect through differently-shaped (but still valid) opcode sequences —
useful if a filter is matching on the *typical* byte pattern `pickle.dumps()` produces rather
than on the semantic content. This is a deeper technique generally reserved for cases where
straightforward `__reduce__`-based payloads are reliably being caught.

## 5. .NET-Specific Evasion

### 5.1 Switching gadgets, not just payloads

Exactly as with Java (Section 3.1), ysoserial.net (File 07) exposes many `-g` gadget options for
the same `-p ObjectDataProvider` payload type — if a filter blocks requests containing the
string `ObjectDataProvider` or a specific gadget class name like
`TextFormattingRunProperties`, trying an alternate gadget (`WindowsIdentity`,
`PSObject`, etc., depending on what your ysoserial.net build offers) targeting the same
underlying serializer often slips past a narrowly-scoped blacklist.

### 5.2 ViewState-specific evasion considerations

Since ViewState is normally MAC-protected, the relevant "evasion" isn't really about a WAF —
it's about whether you can forge a validly-signed payload at all (Section 3 of File 07). Once
you have a valid MachineKey (leaked, default, or recovered via a padding-oracle-class
vulnerability), the resulting payload is, by definition, indistinguishable from a legitimate
ViewState value to any filter, since it carries a correct, server-verifiable signature.

## 6. General Cross-Language Principles

- **Always test with an out-of-band, non-destructive command first** (covered in File 05
  Section 6, applies identically to every language) — this tells you whether a failure is due
  to the chain being wrong versus the payload being filtered/blocked, which determines whether
  you need a different gadget chain or a different evasion technique.
- **Read every error message carefully.** A `403 Forbidden` from a WAF looks very different from
  a `ClassNotFoundException`/`TypeError`/PHP fatal error from the application itself —
  conflating "filtered" with "wrong chain" wastes significant engagement time.
- **Don't over-invest in evasion before confirming the chain works on an unfiltered path.** If
  the engagement has any internal/staging endpoint without the WAF in front of it, confirm
  exploitability there first, then treat WAF bypass as a separate, secondary finding worth its
  own line in the report (a real vulnerability that's "just" partially mitigated by a WAF is
  still a critical finding from a defense-in-depth perspective).

## 7. What's Next

File 09 is the master cheatsheet and the full PortSwigger Web Security Academy lab mapping, in
the platform's actual Apprentice → Practitioner → Expert order — your single quick-reference
file for active lab work.

---
*Sensitive topic note: none — this file is purely technical/educational security content.*
