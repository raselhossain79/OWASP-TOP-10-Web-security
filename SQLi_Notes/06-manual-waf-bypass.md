# Manual WAF / Filter Bypass Techniques

## 1. Principle

A WAF (or app-layer filter) almost always works via **pattern/signature matching** — regexes
looking for known SQL keywords, specific character sequences, or suspicious combinations. It
does not understand SQL semantics the way the database does. The bypass strategy is always the
same: produce a payload that the *database* parses identically to the blocked one, but that
the *WAF's pattern matcher* does not recognize as matching its signatures.

Always test bypasses incrementally — change one evasion technique at a time so you know
exactly which one defeated which rule, and document that mapping for the report.

## 2. Case Manipulation

```sql
' UnIoN SeLeCt NULL,NULL--
```

Breakdown:
- SQL keywords are case-insensitive to the database parser — `UNION`, `union`, and `UnIoN` all
  execute identically.
- Many naive WAF regexes are written case-sensitively (e.g., matching only `UNION\s+SELECT`
  in uppercase) or only normalize partially — randomizing case can slip past these without
  changing the query's actual behavior at all.

## 3. Inline Comment Injection (Whitespace Substitution)

```sql
'/**/UNION/**/SELECT/**/NULL,NULL--
```

Breakdown:
- `/**/` — a valid, empty SQL comment. The database parser treats it as whitespace/no-op,
  identical in effect to a literal space character.
- WAFs frequently key on the *exact sequence* `UNION SELECT` (with a literal space). Replacing
  the space with `/**/` keeps the query semantically identical while breaking that literal
  string match.
- MySQL-specific variant — versioned comments, which only execute as SQL on matching MySQL
  versions and are otherwise also treated as a no-op-looking comment by many filters:

```sql
'/*!50000UNION*/ /*!50000SELECT*/ NULL,NULL--
```

Breakdown:
- `/*!50000 ... */` — MySQL's "executable comment" syntax: anything inside executes as SQL
  *only* on MySQL version ≥ 5.00.00, but looks like an inert comment to non-MySQL-aware
  parsers and many generic WAF signatures, since it's wrapped in comment delimiters.

## 4. Whitespace Alternatives

```sql
'%0aUNION%0aSELECT%0aNULL,NULL--
```

Breakdown:
- `%0a` — URL-encoded newline character. Most databases treat newlines as valid whitespace
  between SQL tokens, just like a space.
- Useful against filters that specifically strip or block literal space characters (`%20`)
  but don't account for other whitespace-equivalent bytes (tab `%09`, newline `%0a`, vertical
  tab `%0b`, form feed `%0c`).

```sql
'+UNION+SELECT+NULL,NULL--
```

Breakdown:
- In a URL query string, `+` is decoded by the web server as a space (an artifact of
  `application/x-www-form-urlencoded` encoding rules) — this substitution happens at the HTTP
  layer, before the WAF or app even inspects the "space" itself, so a filter scanning the raw
  encoded request body never sees a literal space character at all.

## 5. Encoding Tricks

### 5.1 URL Double-Encoding

```
%2527%2520OR%25201%253D1
```

Breakdown:
- `%25` is the URL-encoding of the `%` character itself. So `%2527` decodes once to `%27`,
  which only decodes a *second* time into `'`.
- Some WAFs decode the request URL exactly once before pattern-matching, then pass the
  *still partially-encoded* value to the application, which performs its own (second) decode
  layer before reaching the database — the WAF inspected a string that never contained the
  literal dangerous characters, while the app's final decoded value does.

### 5.2 Hex Encoding (avoiding quote characters entirely)

```sql
' UNION SELECT username,password FROM users WHERE username=0x61646d696e--
```

Breakdown:
- `0x61646d696e` — the hex representation of the ASCII string `admin`. MySQL natively
  interprets hex literals as strings in numeric/string contexts.
- Using this instead of `'admin'` avoids quote characters entirely in that portion of the
  payload — useful against filters that specifically strip or block single/double quotes.

### 5.3 Unicode/Alternate Encoding (filter-specific, test per target)

```
admin%u0027--
```

Breakdown:
- `%u0027` is a (non-standard, legacy IIS/ASP-specific) Unicode escape for `'`. Some
  legacy filters that only normalize standard `%27`-style encoding miss this format, while
  certain older app stacks still decode it correctly before passing to the database.
- This is highly stack-dependent — verify the target platform handles this encoding before
  relying on it; modern frameworks generally do not.

## 6. Comment-Based Evasion Combined With Keyword Splitting

```sql
'UN/**/ION SEL/**/ECT NULL,NULL--
```

Breakdown:
- Inserting an inert comment *inside* a keyword (`UN/**/ION` → still parses as `UNION` once
  the comment is stripped by the SQL parser) defeats filters that block on the literal
  contiguous keyword string `UNION`, since the raw bytes the WAF inspects never contain that
  unbroken substring.
- This relies on the database's comment-stripping happening *before* keyword tokenization,
  which is true for MySQL's `/**/` comment style — verify per-DBMS, as not all databases
  support comment injection mid-keyword.

## 7. HTTP Parameter Pollution (HPP)

```
GET /product?id=1&id=1' UNION SELECT username,password FROM users--
```

Breakdown:
- Sending the **same parameter name twice** (`id` appears twice in the query string).
- Different layers of a multi-tier stack (load balancer, WAF, app server, app framework)
  frequently disagree on *which* duplicate value to use — some take the first occurrence,
  some take the last, some concatenate them with a comma.
- If the WAF inspects only the *first* `id` value (the benign `1`) while the application
  itself uses the *last* (the malicious payload), the attack payload sails through inspection
  entirely undetected, purely due to this parsing inconsistency.

## 8. Combining Techniques (Real-World Bypass Chains)

A real bypass against a competent WAF is rarely one trick alone — it's a stacked combination:

```sql
'/**/UnIoN%0a/**/SeLeCt/**/0x61646d696e,NULL--
```

Breakdown (combining everything above):
- `/**/` before `UnIoN` — breaks the literal `' UNION` adjacency signature.
- `UnIoN` — randomized case, defeating case-sensitive regex matching.
- `%0a` — newline instead of space, defeating space-stripping/space-detection rules.
- `/**/` before `SeLeCt` — same keyword-adjacency break as above, applied to `SELECT`.
- `0x61646d696e` — hex-encoded string literal, avoiding quote-character signatures entirely.
- Each individual technique targets a *different* assumption a signature-based WAF rule makes;
  stacking them means defeating one rule doesn't help the WAF if three others are also broken
  simultaneously by the same payload.

## 9. Real-World Notes

- **Common mistake:** Throwing the most "exotic" encoding trick first instead of testing
  incrementally. Without isolating *which* change defeated *which* rule, you can't write a
  clear, reproducible finding — and you waste time re-deriving working payloads later.
- **Engagement reality:** Modern commercial WAFs (Cloudflare, Akamai, AWS WAF, Imperva) use
  far more sophisticated detection than simple regex — including request normalization,
  behavioral/ML scoring, and virtual-patching rule sets that update frequently. Manual
  encoding tricks alone increasingly fail against these; always pair manual probing with
  sqlmap's `--tamper` automation (file 07) and `--identify-waf`, and budget realistic time —
  WAF bypass on a hardened target can be the majority of an engagement's effort, or may simply
  not be the highest-value use of limited testing time versus reporting the underlying SQLi
  with a clear "WAF currently mitigates trivial payloads; bypass achievable with effort" note.
- **Report-writing tip:** Always report the *underlying vulnerability* as the primary finding,
  with WAF bypass documented as a secondary "defense-in-depth gap" note — a fixed WAF rule
  without a fixed root-cause query is not a remediation, and the report should make that
  distinction explicit for the client.

## Next File
→ `07-sqlmap-complete.md` — Full sqlmap reference, including the dedicated WAF bypass section.
