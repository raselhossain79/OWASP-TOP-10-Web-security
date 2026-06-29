# Open Redirect — Blocklist Bypass Techniques

## 0. The Mismatch Every Technique in This File Exploits

Almost no real-world open redirect protection is "no protection at all" — that's the Academy lab covered in file 1, and it's rare in production. What you actually find in real assessments is a developer's home-grown filter that *looks* like it blocks external redirects but was written by testing against `http://evil.com` and a handful of obvious variants, without replicating how the browser's own URL parser actually decides what the host of a URL is.

Every technique below targets exactly that gap: a value that a literal-string or naive-substring filter does not recognize as dangerous, but that a spec-compliant browser still resolves to an attacker-controlled host. To make that gap concrete, every payload is broken down into (a) what filter logic it defeats, (b) the exact URL-parsing behavior responsible, and (c) what the browser actually does with it.

A quick grammar reminder used throughout this file: an absolute URL's authority component is `scheme://[userinfo@]host[:port]`. The **host** — not whatever substring a filter happens to find first — is what the browser actually connects to.

## 1. Protocol-Relative URLs

**Payload:** `//evil.com`

**Filter defeated:** a keyword/substring blocklist that checks for the literal substring `http` (case-insensitively) anywhere in the value, on the assumption that anything *without* that substring must be a safe, app-relative path.

**Why it works, piece by piece:**

- The payload contains no scheme at all — just two slashes followed by a host.
- When a browser resolves a URL starting with exactly `//` against the current page (say `https://trusted.com/page`), it performs **scheme-relative resolution**: it keeps the current page's scheme (`https`) and treats everything after the `//` as a brand-new authority component.
- Result: the browser navigates to `https://evil.com` — a full cross-origin redirect — even though the string `http` never appears anywhere in the payload.

A filter written as `if (value.toLowerCase().includes("http")) reject();` will let this straight through, because there is genuinely nothing to match. The fix has to explicitly also reject any value starting with `//`.

## 2. Double / Malformed Slash Sequences (Scheme Present)

**Payloads:** `https:////evil.com`, `https:///evil.com`, `https:evil.com` (zero slashes)

**Filter defeated:** any check that does exact-offset matching for the literal three-character sequence `://` immediately after the scheme name, or a sanitizer that performs a single, non-global `replace("//", "")` under the assumption that stripping one occurrence of double-slash neutralizes the payload.

**Why it works, piece by piece — this is the least-known mechanic in this category:**

- The WHATWG URL Standard defines `http`, `https`, `ws`, `wss`, `ftp`, and `file` as **"special" schemes**.
- When the parser encounters a special scheme followed by a colon, it enters a slash-skipping state that consumes **any number of `/` characters it finds — including zero** — before it starts reading the authority (host).
- That means `https:evil.com`, `https:/evil.com`, `https://evil.com`, and `https:////evil.com` all parse to the **exact same host: `evil.com`**. The number of slashes is cosmetic to the parser for these schemes.

So a sanitizer that does a single `.replace("//", "")` on `https:////evil.com` removes one pair of slashes and is left with `https://evil.com` — which still resolves to `evil.com` — while a sanitizer requiring the literal three-character sequence `://` to appear at a fixed character offset (e.g. exactly at index 5 for an `https` scheme) will reject `https:evil.com` outright as "malformed," not realizing the browser doesn't care and will redirect there anyway.

## 3. The `@` Symbol (Userinfo) Trick

**Payload:** `https://trusted.com@evil.com`

**Filter defeated:** a substring check (`value.includes("trusted.com")`) or a prefix check (`value.startsWith("https://trusted.com")`) used as an *allowlist*, intended to permit only URLs pointing at the trusted domain.

**Why it works, piece by piece:**

- Authority grammar: `scheme://[userinfo@]host[:port]`.
- `https://` — scheme and start of authority.
- `trusted.com` — everything up to the first unescaped `@` is parsed as **userinfo** (conventionally a username, optionally `username:password`), not as the host. The browser treats this as authentication credentials offered for the connection, and silently discards it since http(s) doesn't actually prompt for it in this context.
- `@` — the userinfo/host delimiter.
- `evil.com` — the actual host, because it's everything after the `@` up to the next `/`, `?`, or `#`.
- The literal string `"trusted.com"` genuinely is present in the value, immediately after the scheme — so both the substring check and the prefix check pass — but neither check models URL authority grammar, so neither one realizes that text is decorative userinfo rather than the host the browser will actually connect to.

**Stealth variant:** `https://trusted.com:s3cr3t@evil.com/path` — adding a fake password after a colon further disguises the payload from a casual human code reviewer or a regex specifically looking for a bare `@evil.com` tail with nothing in front of it.

## 4. Backslash Conversion

**Payloads:** `https:/\evil.com`, `https:\/evil.com`, `https:\\evil.com`

**Filter defeated:** any check doing exact-string matching for the literal forward-slash sequence `://`, on the assumption that a "real" absolute URL can only be written with forward slashes.

**Why it works, piece by piece:**

- This reuses the same slash-skipping parser state from technique 2 — except that state explicitly treats `\` (backslash) as interchangeable with `/` (forward slash). This is a deliberate compatibility holdover in the URL Standard, inherited from how older IE-derived parsers handled Windows-style path separators.
- For `https:\\evil.com`: scheme `https:` is recognized as special → parser enters the slash-skipping state → it encounters two backslashes → treats them identically to two forward slashes → begins authority parsing → host = `evil.com`.
- A filter looking only for the literal three-byte sequence `://` will not match `:\\`, `:/\`, or `:\/` — by that filter's logic, the value doesn't even look like an absolute URL — yet the browser parses and redirects exactly as if forward slashes had been used.

## 5. Whitespace, Control-Character, and Null-Byte Tricks

### 5.1 Leading whitespace / tab / newline

**Payloads:** `" https://evil.com"`, `"\thttps://evil.com"`, `"\nhttps://evil.com"`

**Mechanism:** the URL Standard's parser strips leading and trailing ASCII whitespace and C0 control characters from the input as one of its very first processing steps, before any scheme or authority parsing begins.

**Why it works:** `value.startsWith("http")` evaluates to **false** on the raw string, because the first character is a space, tab, or newline — so a filter assuming "doesn't start with http → must be a safe relative path" lets it through. The browser, however, trims that leading character first and is then left looking at a perfectly clean `https://evil.com`.

### 5.2 Embedded tab/newline inside the scheme keyword itself

**Payloads:** `ht\ntp://evil.com`, `h\ttp://evil.com`

**Mechanism:** a separate, more specific step in the same spec explicitly instructs the parser to remove **all** ASCII tab and newline characters from the input — not just leading/trailing ones — anywhere they occur, before tokenizing.

**Why it works, piece by piece:** a blocklist doing a literal substring search for `"http"` will never find it in the raw bytes `h-t-NEWLINE-t-p`, because the substring genuinely isn't contiguous in the input the filter sees. The browser's mandatory tab/newline-stripping pass deletes that embedded character first, the bytes collapse back into a clean `http`, and parsing proceeds to `http://evil.com`. This is the exact same browser behavior that lets `java\tscript:alert(1)` slip past naive `"javascript:"` substring filters in XSS contexts — it isn't a coincidence; it's the same mandatory parser step being abused against a different keyword.

### 5.3 Null byte

**Payload:** `https://trusted.com/page?url=https://evil.com%00.trusted.com`

**Mechanism (legacy):** in C-style, null-terminated string handling, a decoded `\0` truncates the string for functions like `strlen`/`strstr`. A suffix-style validator checking "does this host end with `.trusted.com`" implemented on top of such string handling may only ever evaluate the portion up to the null byte.

**Honest caveat:** treat this one as a legacy technique, not a reliable modern bypass. Current major browsers and most modern web/application frameworks (Node.js, current PHP, Java, Go) either reject a literal NUL inside a URL outright or percent-encode it rather than truncate on it. It's still worth a quick test pass because some legacy backend validators, embedded-device web UIs, and custom WAF rule engines written in C/C++ retain null-truncation behavior — but don't expect it to land against a modern stack, and say so plainly in a report rather than overclaiming impact.

## 6. Combining Techniques — A Real-Audit-Style Chained Payload

Real validation logic in production is frequently a patchwork of several of the checks above stacked together, which means a single technique often isn't enough and you have to combine them. Worked example:

**Payload:** `\thttps:/\trusted.com@evil.com`

Breaking it down left to right:

- `\t` — a leading tab character. Defeats a `value.startsWith("http")` gate exactly as in technique 5.1: the raw string doesn't start with `http`, so the gate's "this must be relative" assumption is satisfied and the value passes through that first check.
- `https:` — once the browser strips the leading tab (per the URL Standard's mandatory trimming step), this is recognized as a special scheme.
- `/\` — one forward slash and one backslash. Per technique 4, the special-scheme slash-skipping state treats both characters identically and consumes them as the authority-start marker.
- `trusted.com` — parsed as userinfo per technique 3, because of the `@` that follows. A naive allowlist doing `value.includes("trusted.com")` finds this substring and is satisfied.
- `@` — userinfo/host delimiter.
- `evil.com` — the actual host the browser connects to.

Net result: a single payload survives a "must not start with `http`" gate (via the leading tab), a "must contain `trusted.com`" allowlist (via the userinfo trick), and a "must contain `://`" scheme check (via backslash substitution) — all at once — while still resolving to `evil.com`. This is the level of stacked reasoning to expect once you're past the first naive filter implementation in a real target.

## 7. PortSwigger Lab Mapping for This File

**Honest gap disclosure first:** the Web Security Academy does **not** have a dedicated lab for practicing blocklist bypass on a standalone open redirect. The one Academy-native open redirect lab (`DOM-based open redirection`, covered in file 1) has no filter at all to defeat — it's a pure detection-and-exploitation exercise on an unfiltered sink.

| Lab | Topic area | Difficulty | Relevance to this file |
|---|---|---|---|
| SSRF with filter bypass via open redirection vulnerability | SSRF | Practitioner | Closest Academy lab to this file's content — but it uses an *already-present, unfiltered* open redirect purely as a chain ingredient to defeat a separate SSRF allowlist (the SSRF filter only permits internal-looking requests, and the redirect is what gets a second internal request to fire). It does not require you to bypass any filtering on the open redirect itself. |

**Where to actually drill these specific bypasses:** since the Academy doesn't build out a dedicated target for it, the most efficient practice is to stand up a tiny local test harness yourself — five minutes per filter. Write four or five minimal Express/Flask redirect handlers, give each one exactly one of the naive checks described in sections 1–5 above, and confirm you can defeat each with the matching technique before moving on. This mirrors real audits far better than a single Academy lab would anyway, because real targets rarely use only one filter strategy.
