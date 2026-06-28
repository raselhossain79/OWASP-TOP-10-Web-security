# XPath Injection — Filter and WAF Bypass

This file assumes a basic filter or WAF is blocking the straightforward payloads from file 2.
Every bypass technique below explains the underlying mechanism — why the original filter catches
the naive payload, and exactly what property of XPath syntax the bypass exploits to slip past it.

## 1. Quote-Character Filtering

**Common filter behavior:** the application strips or blocks `'` and `"` characters, since most
naive XPath injection payloads rely on closing a string literal.

### 1.1 Switching quote style

If the developer's code wraps the literal in double quotes (`"`) rather than single quotes (`'`),
a filter tuned only for `'` will let `"` straight through.

**Payload:**
```
" or "1"="1
```

**Mechanism:** Identical logic to the single-quote tautology bypass in file 2, just using the
other quote character XPath supports for string literals. Always test both quote styles before
concluding a parameter is filtered against injection entirely — testing only one is the most
common reason testers wrongly write off a vulnerable field.

### 1.2 Avoiding quotes entirely with `concat()`

Some filters block both `'` and `"` outright. XPath 1.0's `concat()` function lets you build
string comparisons without ever using a literal quoted string in your payload body if the
surrounding application code is the one supplying the quote characters and you only control what
goes *between* them — but more usefully, `concat()` lets you reconstruct a target string from
pieces in contexts where a single quote character is blocked mid-payload but not at the very
boundary the application itself provides.

**Payload (when only internal quotes inside your injected value are blocked, not the boundary
ones the app adds):**

```
' or username/text()=concat('ad','min') or '1'='1
```

**Mechanism:**
- `concat(string1, string2, ...)` — an XPath function taking any number of string arguments and
  returning them joined together. `concat('ad','min')` evaluates to the string `admin`.
- This matters specifically when a filter is doing substring matching against known bad literal
  values (i.e., blocking the literal text `admin` from appearing in input) rather than against
  XPath syntax itself — splitting the target string across multiple `concat()` arguments defeats
  any filter doing literal substring detection on your raw input, since the string `admin` never
  appears intact anywhere in your submitted payload.

## 2. Keyword Filtering (`and` / `or` Blocked)

**Common filter behavior:** input validation blocks the literal substrings `and` and `or`
(case-insensitively), since they're the most recognizable XPath/SQL-style injection keywords.

### 2.1 Using the union operator instead of a boolean tautology

Recall from file 2 that `|` (union) doesn't require any boolean keyword at all — it's a pure
node-set combination operator.

**Payload:**
```
x'] | //user[1]/*[name()!='x
```

**Mechanism:**
- This payload contains no `and`/`or` substring anywhere, so any filter keying purely on those
  keywords passes it through untouched.
- `!=` is a standalone inequality operator that doesn't require a boolean connective keyword to
  function inside a predicate on its own.
- The overall effect (pulling in an unrelated node-set via union) mirrors section 3.2 of file 2,
  achieved here specifically to route around keyword-based filtering rather than for its original
  data-extraction purpose.

### 2.2 Case variation and encoding for naive keyword filters

If the filter does a case-sensitive literal match for `or`/`and` (rare, but seen in poorly written
custom WAF rules rather than mainstream WAF products):

**Payload:**
```
' Or '1'='1
```

**Mechanism:** XPath keywords are case-sensitive in the standard, and `Or` (capitalized) is not a
valid XPath keyword — so this specific bypass **only works if the filter itself is naive and the
backend XPath engine is simultaneously lenient/non-standard**, which is uncommon. This is included
here as a known historical bypass technique referenced in OWASP/PayloadsAllTheThings material, but
it should not be relied on against modern XPath engines, which strictly require lowercase `and`/
`or` — flagging this honestly rather than presenting it as universally effective.

## 3. Bracket and Special-Character Filtering

**Common filter behavior:** stripping `[`, `]`, `(`, `)`, or `*` because they're recognizable as
XPath-specific metacharacters distinct from typical form input.

### 3.1 Using the implicit wildcard without brackets

If `*` itself isn't blocked but bracket predicates are, you can still broaden a query using `*` as
a bare node-test wildcard rather than inside a predicate:

**Payload (replacing a known element name with a wildcard, no brackets needed):**

```
' or /*/*/*/text()='admin
```

**Mechanism:**
- `/*/*/*` walks three levels deep from the document root using only the wildcard node test at
  each step, with no predicate brackets at all — this is a blunt, low-precision way to reach
  arbitrary nodes when you can't filter by exact tag name due to bracket filtering, trading
  precision for the ability to bypass a bracket-based filter entirely.

### 3.2 URL/entity encoding for bracket characters

Encoding can sometimes slip past filters operating on the raw, pre-decoded request body, if the
filter runs before URL-decoding but the XPath-processing layer runs after it.

**Payload (URL-encoded brackets, sent as raw request body bytes):**
```
%27%20or%20%271%27%3D%271
```

**Mechanism:**
- `%27` decodes to `'`, `%20` to a space, `%3D` to `=` — standard percent-encoding.
- This only works as a bypass when there's a **decoding order mismatch** between the WAF/filter
  layer and the application layer — i.e., the filter inspects the raw encoded bytes and doesn't
  see anything resembling `'`, `or`, or `=`, but the web framework decodes the body *after* the
  filter has already approved it and *before* the value reaches the XPath query builder. This is
  a property of the specific stack's request-handling pipeline, not of XPath itself, and should be
  verified per-target rather than assumed to work universally — modern WAF products generally
  normalize/decode before inspection specifically to prevent this class of bypass.

## 4. Length-Based Filtering

**Common filter behavior:** rejecting input over some fixed character length, on the assumption
that legitimate usernames/search terms are short.

### 4.1 Minimizing payload length using short function names and removing unnecessary literals

```
'or 1=1 or'1
```

**Mechanism:**
- Removing the spaces immediately around `or` is syntactically valid in XPath as long as there's
  no ambiguity in tokenization at the boundary (XPath's parser tokenizes `'or` correctly since the
  quote character itself is an unambiguous token boundary) — this shaves a small number of
  characters off compared to the fully-spaced version, which can matter against a strict
  length cap on short fields like a username box capped at, say, 20 characters.
- This is a minor, situational technique — if the length cap is aggressive enough (under ~12
  characters), no XPath tautology payload will fit regardless of compression, and you should pivot
  to testing whether the length limit applies client-side only (and can be bypassed by sending the
  request directly via Burp Repeater rather than through the browser's form field) before assuming
  the endpoint is unexploitable.

## 5. Real-World Notes

- In practice, most production WAFs (Cloudflare, AWS WAF, Akamai) ship generic "SQL/XPath/LDAP
  injection" rule sets that pattern-match on the same small set of metacharacters (`'`, `"`,
  `()`, `[]`, `or`/`and`) across all three injection classes simultaneously — bypasses that work
  against custom in-house input filters (the techniques above) are far less reliable against a
  mature commercial WAF, where the more productive path is usually finding an unfiltered parameter
  entirely rather than trying to out-encode the rule set.
- Document every bypass attempt in client engagements precisely, including which exact filter
  behavior you confirmed (keyword-blocked vs character-blocked vs length-capped) — this is what
  turns a "we have a WAF, so we're covered" client assumption into an actionable remediation
  recommendation pointing at the actual root cause (string concatenation building the XPath query)
  rather than at the WAF rule set, which is a perimeter control, not a fix.
