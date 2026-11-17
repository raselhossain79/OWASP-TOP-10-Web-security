# Manual WAF / Filter Bypass Techniques

## 1. Principle

A Web Application Firewall (WAF) or application-layer input filter attempts to detect and block potentially malicious requests before they reach sensitive application components.

WAFs may use multiple detection mechanisms, including:

- Signature-based rules and pattern matching.
- Regular expressions.
- Request parsing and normalization.
- Character encoding and decoding.
- Protocol validation.
- Anomaly scoring and behavioral analysis.
- Machine-learning-assisted detection in some implementations.

Do not assume that every WAF relies only on simple regex matching.

The general objective of a bypass test is to determine whether different processing layers interpret the same request differently.

For example:

1. A client sends an encoded request.
2. A WAF inspects or normalizes the request.
3. A web server or application framework decodes the input.
4. The application processes the decoded value.
5. The database interprets the resulting SQL statement.

If these components disagree about how an input should be interpreted, a security gap may exist.

**Core principle:** Understand the complete request-processing and decoding sequence instead of blindly trying unusual payloads.

Always test bypass techniques incrementally. Change one transformation at a time so you can identify which behavior caused the difference.

---

## 2. Case Manipulation

Example:

```sql
' UnIoN SeLeCt NULL,NULL--
```

### Breakdown

- SQL keywords are generally case-insensitive in common SQL dialects.
- `UNION`, `union`, and `UnIoN` usually have the same meaning to the SQL parser.
- Some simplistic filters may look for exact uppercase or lowercase strings.
- Changing keyword capitalization may avoid a case-sensitive signature without changing the SQL statement's meaning.

### Important limitations

- Modern WAFs commonly perform case normalization.
- Case manipulation does not help if the WAF uses case-insensitive matching.
- Database identifiers, string values, and quoted content may have different case-sensitivity rules.

**Practical lesson:** Case manipulation is a simple test, not a reliable universal bypass.

---

## 3. Inline Comment Injection

SQL comments can sometimes act as separators between SQL tokens.

Example:

```sql
'/**/UNION/**/SELECT/**/NULL,NULL--
```

### Breakdown

- `/**/` represents an empty block comment in SQL dialects that support this syntax.
- In many SQL parsers, comments between tokens are treated similarly to whitespace.
- Some basic filters search for exact strings such as `UNION SELECT`.
- Replacing a literal space with a comment may change the request representation while preserving the SQL token sequence.

### MySQL executable comments

MySQL supports a special executable-comment syntax:

```sql
/*!50000 SELECT 1 */
```

- `/*! ... */` is MySQL-specific executable-comment syntax.
- The version number controls whether the enclosed statement is executed.
- `50000` represents MySQL version 5.0.0 or newer.
- This syntax is not equivalent to an ordinary inert comment.

### Important limitations

- Comment handling differs between DBMS products.
- Some WAFs normalize comments before inspection.
- Some application filters remove comments before the database receives the query.
- A comment separator does not guarantee a successful bypass.

**Practical lesson:** Understand whether comments are preserved, removed, or interpreted by each processing layer.

---

## 4. Whitespace Alternatives

SQL parsers commonly accept multiple whitespace characters between tokens.

Example:

```sql
'%0aUNION%0aSELECT%0aNULL,NULL--
```

### Breakdown

- `%0a` represents a URL-encoded line-feed character.
- Other whitespace characters include:
  - `%09` — horizontal tab.
  - `%0b` — vertical tab.
  - `%0c` — form feed.
  - `%0d` — carriage return.
- Depending on the DBMS and SQL context, these may act as whitespace separators.

### Plus sign as a space

Example:

```sql
'+UNION+SELECT+NULL,NULL--
```

In `application/x-www-form-urlencoded` query-string or form-body parsing:

- `+` is normally decoded as a space.
- `%20` is another common representation of a space.
- This decoding usually occurs during form-style parameter parsing.

### Important limitations

The interpretation of `+` depends on its location and request encoding:

- In form-encoded query parameters, `+` generally represents a space.
- In URL paths, `+` is generally a literal plus character.
- In JSON bodies, `+` is not automatically decoded into a space.
- A WAF may inspect either the raw or decoded representation.

**Practical lesson:** Always identify the request's content type and the decoding behavior of the application stack.

---

## 5. Encoding Techniques

Encoding changes how data is represented during transmission. It does not automatically make malicious input safe or change its meaning in every processing context.

### 5.1 URL Double-Encoding

Example:

```text
%2527%2520OR%25201%253D1
```

### Breakdown

- `%25` represents the percent character.
- `%2527` decodes once to `%27`.
- `%27` decodes again to a single quote (`'`).
- Therefore, double encoding requires multiple decoding stages to produce the final character.

### Possible processing sequence

1. The client sends double-encoded input.
2. One component decodes the input once.
3. Another component decodes it again.
4. A downstream component receives the fully decoded representation.

A decoding inconsistency can create a security gap if the WAF and application inspect different representations.

### Important limitations

- Multiple decoding stages are not guaranteed.
- Some applications reject malformed or repeatedly encoded input.
- Some WAFs normalize repeatedly encoded values.
- Double decoding can also cause unexpected application behavior.

**Practical lesson:** Identify exactly how many times and where the request is decoded.

### 5.2 Hexadecimal Encoding

Example:

```sql
0x61646d696e
```

### Breakdown

- `0x` introduces a hexadecimal literal in MySQL.
- `61646d696e` is the hexadecimal representation of the ASCII string `admin`.
- MySQL can interpret hexadecimal literals as binary strings in appropriate contexts.

This can be useful when testing whether a filter treats quoted strings and hexadecimal literals differently.

### Important limitations

- Hexadecimal literal syntax differs between DBMS products.
- Data types and implicit conversions affect interpretation.
- A WAF may recognize hexadecimal representations or normalize them.
- Hexadecimal encoding does not replace SQL parameterization.

### 5.3 Unicode and Alternate Encoding

Example:

```text
admin%u0027--
```

### Breakdown

- `%u0027` is a legacy, non-standard Unicode escape representation for the apostrophe character.
- Some older Microsoft IIS/ASP-related environments supported this type of decoding.
- Modern frameworks generally do not interpret it as a standard URL-encoded character.

### Important limitations

- `%uXXXX` is not standard URL percent encoding.
- Behavior is highly dependent on the application stack.
- Do not assume that modern servers or WAFs decode it.

**Practical lesson:** Encoding behavior must be verified against the actual target technology.

---

## 6. Comment-Based Keyword Separation

A common misconception is that inserting comments inside a SQL keyword always reconstructs the original keyword.

Example:

```sql
UN/**/ION
```

This should not be assumed to become:

```sql
UNION
```

### Why?

SQL parsers generally perform lexical analysis to identify tokens.

A comment between two parts of a keyword is normally treated as a separator, not as an instruction to concatenate the surrounding text.

Therefore, `UN/**/ION` is generally interpreted as two separate tokens rather than one `UNION` keyword.

### Correct distinction

There is an important difference between:

**Comment between SQL tokens:**

```sql
UNION/**/SELECT
```

Here the comment can act as a separator between two complete SQL keywords.

**Comment inside a SQL keyword:**

```sql
UN/**/ION
```

Here the comment generally splits the keyword and does not reconstruct it.

### DBMS considerations

- Comment syntax and parsing behavior vary between database products.
- MySQL has special executable comments.
- Do not assume that behavior observed in one DBMS applies to another.

**Practical lesson:** Comments can change token separation, but they are not a universal keyword-splitting mechanism.

---

## 7. HTTP Parameter Pollution (HPP)

Example:

```http
GET /product?id=1&id=2 HTTP/1.1
Host: example.com
```

### Breakdown

HTTP Parameter Pollution occurs when the same parameter name is supplied multiple times.

Different components may interpret duplicate parameters differently.

For example:

- A WAF may inspect the first occurrence.
- A web framework may use the last occurrence.
- Another framework may combine duplicate values into an array.
- Some components may concatenate values.

### Why this matters

If the WAF and backend disagree about which parameter value is effective, the security control may inspect a different value from the one the application processes.

### Important limitations

- Duplicate parameter handling is framework-dependent.
- Some WAFs detect duplicate parameters.
- Some applications reject duplicated parameters.
- Query-string and POST-body parameter handling may differ.
- Parameter precedence can change when both query and body contain the same name.

**Practical lesson:** When testing HPP, document how the WAF, server, and application each interpret duplicate values.

---

## 8. Combining Techniques

Multiple transformations can sometimes interact with different request-processing rules.

Example:

```sql
'/**/UnIoN%0a/**/SeLeCt/**/NULL,NULL--
```

This example combines:

- Comment separators.
- Mixed keyword capitalization.
- URL-encoded newline characters.
- Comment separators between SQL tokens.

### Why combine techniques?

A simple filter may detect one representation but fail to recognize another.

However, combining multiple techniques immediately makes it difficult to determine which transformation caused a change in behavior.

### Recommended testing methodology

1. Establish a normal baseline request.
2. Send a simple test input.
3. Record the response status, body, and length.
4. Change only one representation feature.
5. Compare the response with the baseline.
6. Confirm whether the backend behavior actually changed.
7. Combine techniques only after understanding their individual effects.

### Important limitations

- Multiple transformations may be normalized by the WAF.
- Incorrect encoding can break the request before it reaches the application.
- A different HTTP response does not automatically prove a successful bypass.
- A WAF bypass does not automatically prove SQL injection.

**Practical lesson:** Isolate individual transformations before testing combinations.

---

## 9. XML Encoding and Parser-Based Filter Bypass

XML supports character references that represent characters using numeric values.

Examples:

```xml
&#65;
```

Represents:

```text
A
```

Hexadecimal XML character reference:

```xml
&#x41;
```

Also represents:

```text
A
```

### How XML encoding can affect security testing

Consider an application that:

1. Receives XML input.
2. Applies a filter or validation rule.
3. Parses the XML document.
4. Uses extracted values in a database query.

If the filter and XML parser interpret the input differently, an input that appears encoded during inspection may become a different character after XML parsing.

This can create a filter bypass opportunity.

### Important distinction

XML character references are decoded by an XML parser in an appropriate XML context.

They are not automatically decoded by:

- Every HTTP server.
- Every web application framework.
- Every SQL database.
- Every WAF.

### Testing considerations

- Determine whether the endpoint actually accepts XML.
- Identify the component that parses the XML.
- Determine when XML decoding occurs.
- Check whether filtering happens before or after parsing.
- Verify whether the final parsed value reaches a vulnerable SQL query.

**Practical lesson:** XML encoding is context-dependent. It is not a universal SQL injection bypass.

---

## 10. Real-World Notes

### 10.1 Modern WAF behavior

Modern commercial WAF products such as Cloudflare, Akamai, AWS WAF, and Imperva may use:

- Request normalization.
- Signature and rule-based detection.
- Protocol-aware parsing.
- Anomaly scoring.
- Behavioral detection.
- Virtual patching.
- Continuously updated rule sets.

Simple case manipulation, comments, or alternate whitespace may be insufficient against properly configured modern WAFs.

### 10.2 SQLMap and WAF testing

SQLMap provides automation features that can help with WAF identification and request transformation.

Important options include:

- `--identify-waf` — attempts to identify a WAF.
- `--tamper` — applies selected tamper scripts to modify payload representation.

Important distinction:

- WAF identification is not WAF bypass.
- Tamper scripts do not guarantee successful bypass.
- A tamper script may be incompatible with a particular DBMS or injection context.
- Automated detection results require manual validation.

Always follow the target's authorization and automation restrictions.

### 10.3 WAF blocking versus SQL injection

A WAF blocking a basic SQLi payload does not prove that the underlying application is secure.

Likewise, successfully bypassing a WAF does not prove that the application has SQL injection.

These are separate questions:

1. Does the WAF detect or block the tested request?
2. Does the application construct unsafe SQL?
3. Can the database execute the injected SQL?
4. What is the security impact?

A proper assessment must establish the underlying vulnerability independently.

### 10.4 Engagement time and prioritization

WAF bypass can consume substantial testing time, particularly on hardened targets.

During a professional engagement:

- Prioritize vulnerabilities according to risk and scope.
- Do not spend unlimited time on low-value filter variations.
- Document the WAF's observed behavior.
- If SQL injection is confirmed, report the underlying SQL construction weakness.
- Explain WAF mitigation separately as a defense-in-depth observation.

### 10.5 Reporting guidance

The primary finding should describe the underlying vulnerability, not merely the fact that a WAF rule was bypassed.

A useful report should include:

- Affected endpoint and parameter.
- Injection context.
- Steps to reproduce.
- Evidence of SQL execution.
- Security impact.
- Relevant WAF behavior, if applicable.
- Recommended root-cause remediation.

**Remediation priority:** Use parameterized queries or prepared statements. WAF rules should be treated as an additional defensive layer, not as a replacement for fixing unsafe SQL construction.

---

## 11. Key Takeaways

| Technique | Main concept | Important dependency |
|---|---|---|
| Case manipulation | Change keyword capitalization | WAF normalization |
| Inline comments | Separate SQL tokens | DBMS comment syntax |
| Whitespace alternatives | Replace spaces with other separators | Parser and encoding behavior |
| Double encoding | Multiple decoding stages | Application processing order |
| Hex encoding | Represent values using hexadecimal literals | DBMS syntax and data types |
| Unicode encoding | Alternate character representation | Legacy/platform-specific decoding |
| HPP | Duplicate parameter interpretation | Framework and WAF parsing |
| XML encoding | XML parser decodes character references | XML parsing context |

### Final principles

1. Never assume a bypass technique works across all DBMS products.
2. Understand the entire request-processing chain.
3. Test one transformation at a time.
4. Compare the final backend behavior, not just HTTP status codes.
5. A WAF bypass is not automatically a SQL injection vulnerability.
6. Parameterized queries are the primary SQLi remediation.

---

## Next File

→ `07-sqlmap-complete.md` — SQLMap reference, automated SQL injection detection, DBMS fingerprinting, supported techniques, tamper scripts, and WAF-related testing.
