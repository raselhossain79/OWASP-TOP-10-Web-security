# XPath Injection — Overview and Classification

OWASP Top 10 2021 — **A03:2021 Injection**
CWE-91: XML Injection (aka Blind XPath Injection)

## 1. What XPath Injection Actually Is

XPath Injection happens when an application builds an XPath query by directly splicing in
attacker-controlled input — the same root cause as SQL injection, just against a different data
store. Instead of a relational database, the backend here is an XML document (or an in-memory XML
DOM), and the query language is **XPath** (XML Path Language) instead of SQL.

A typical vulnerable server-side construction looks like this:

```
//user[username/text()='" + username + "' and password/text()='" + password + "']
```

If `username` and `password` come straight from a login form with no sanitization, an attacker
can break out of the intended string literal and rewrite the logic of the query, exactly the way
they would with `' OR 1=1 --` in SQL injection.

### Why this still matters in 2026

XML-backed authentication and data stores are far less common than relational databases, but they
are not extinct. You will realistically encounter XPath injection in:

- **SOAP-based web services** — many enterprise SOAP/WS-* stacks still validate credentials or
  route requests against XML payloads using XPath internally.
- **Legacy CMS and intranet systems** — pre-2015 era Java/.NET enterprise apps frequently used
  XML files as lightweight "databases" for configuration, user lists, or content trees, queried
  via XPath rather than SQL.
- **SAML and XML-based SSO/config parsing layers** — XPath is used internally in many SAML
  processing libraries to pull attributes out of signed XML assertions; if any of that querying
  incorporates attacker-influenced values, injection is possible.
- **Mobile app backends and embedded devices** — XML config/data stores are common in router
  firmware admin panels and some IoT management backends, which are common bug bounty targets
  precisely because their codebases are old and rarely security-reviewed.
- **DOM-based client-side XPath injection** — modern web apps that use `document.evaluate()` to
  query parts of the page DOM based on URL parameters introduce a *client-side* version of this
  bug class, which is what PortSwigger's Academy actually has labs for (covered honestly in file
  5 of this series).

## 2. The XML/XPath Data Model, In Plain Terms

Before any payload makes sense, you need the mental model of what XPath is querying.

An XML document is a **tree of nodes** — not a table.

```xml
<users>
  <user>
    <username>admin</username>
    <password>S3cr3t!</password>
    <role>administrator</role>
  </user>
  <user>
    <username>alice</username>
    <password>alicepass</password>
    <role>user</role>
  </user>
</users>
```

There is no concept of "tables," "rows," "columns," or "schema" in the SQL sense. There is only:

- **Elements** — the tags themselves (`<user>`, `<username>`)
- **Attributes** — `<user id="1">` → `id` is an attribute of the `user` element
- **Text nodes** — the literal text content inside an element (`admin` inside `<username>`)
- **The document root** — the single top-level node everything hangs off of

XPath is the language used to *navigate and select* nodes in that tree. An XPath expression is
essentially a path description, similar in spirit to a filesystem path, but with the ability to
add conditional filters (predicates) at each step.

```
/users/user[username/text()='admin']/password/text()
```

Read left to right:
- `/users` → from the document root, go to the `users` element
- `/user` → then to its `user` children
- `[username/text()='admin']` → but only the `user` node(s) where the child `username`'s text
  equals `admin` — this square-bracket part is a **predicate**, the XPath equivalent of a SQL
  `WHERE` clause
- `/password/text()` → then return the text content of that matched node's `password` child

## 3. XPath Injection vs SQL Injection — The Core Differences

This is the part most people gloss over, and it is exactly why XPath injection trips people up
even when they already know SQL injection well. Same root cause, very different attack surface.

| Aspect | SQL Injection | XPath Injection |
|---|---|---|
| **Underlying data model** | Relational — tables, rows, columns, foreign keys, schema | Tree — nodes, elements, attributes, no schema enforcement at query time |
| **Schema discovery** | You enumerate table names, column names, database version via `information_schema`, `UNION SELECT`, error messages | There is no schema to enumerate in that sense — the "schema" is just whatever tag/attribute names exist in the tree, and you discover those by walking the tree itself (`name()`, `count()`, axis traversal) |
| **Access control model** | Permissions are usually enforced at the database engine level (GRANT/REVOKE, views, row-level security) — even with injection, you're bounded by what the DB user account can see | **There is no access control layer in XPath itself.** If the query engine can see the document, the attacker can usually reach the *entire* document via injection — there's no concept of "this part of the XML tree is restricted." This makes successful XPath injection often more severe in scope, even though XML datastores are smaller in size than relational DBs |
| **Time-based blind technique** | `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()` — native delay functions exist in virtually every SQL dialect | **XPath 1.0 has no native time-delay function.** There is nothing equivalent to `SLEEP(5)`. This is why time-based blind XPath injection is not practically usable as a primary technique — boolean-based blind is the dominant blind technique for this class, covered in depth in file 2 |
| **Out-of-band exfiltration** | DNS exfiltration, `xp_dirtree`, `UTL_HTTP`, linked servers | XPath 2.0+ engines that expose a `doc()` function can sometimes be coerced into making outbound requests, giving a rough OOB channel — but this is engine-dependent and far less reliable than SQL OOB techniques |
| **Multiple statements / stacked queries** | Often possible (`; DROP TABLE x;--`) depending on driver | Not applicable — XPath is a single expression language, there is no statement separator equivalent to `;` for stacking arbitrary additional operations |
| **Standard dialect fragmentation** | Many SQL dialects (MySQL, MSSQL, PostgreSQL, Oracle) with meaningfully different syntax for advanced techniques | XPath 1.0 is a W3C standard implemented near-identically across engines (libxml2, .NET `XPathNavigator`, Java's `javax.xml.xpath`, PHP's `SimpleXMLElement::xpath`) — payloads port across targets with very little adjustment, which is why automation tools like `xcat` work broadly |
| **Automation tooling maturity** | `sqlmap` — extremely mature, handles every dialect and technique | `xcat` — functional and effective for blind boolean extraction, but far less feature-complete than `sqlmap`; manual technique knowledge matters more here |

The single most important mental shift: **in SQL injection you are usually trying to escalate
from "this query" to "the whole database." In XPath injection, the moment you have any injection
point at all, you are already most of the way to "the whole document"** — because there is no
internal access-control boundary inside an XML document the way there is between database users
and tables/views in most RDBMS setups.

## 4. Where the Injection Point Usually Lives

Just like SQLi, the vulnerability is 100% about *how the query string is built*, not about XML or
XPath themselves being insecure. Three common vulnerable construction patterns:

**Pattern 1 — Authentication query (most common CTF/real-world pattern):**
```
//user[username/text()='" + username + "' and password/text()='" + password + "']
```

**Pattern 2 — Search/filter functionality:**
```
//book[category/text()='" + categoryInput + "']
```

**Pattern 3 — Direct lookup by attacker-supplied identifier:**
```
//item[@id='" + idParam + "']
```

In every case, the fix is the same as for SQLi: use parameterized XPath APIs (e.g.
`javax.xml.xpath.XPath.setXPathVariableResolver`, .NET's `XPathExpression` with bound variables)
instead of string concatenation, and apply strict allow-list input validation as defense in depth.

## 5. Severity and Real-World Impact

Because there is no internal access-control boundary in an XML document, a successful XPath
injection on an authentication query commonly leads directly to:

- **Authentication bypass** — log in as any user, including admin, without a valid password
- **Full data extraction** — recover every node's content in the document (often the *entire*
  user/credential store) via blind boolean techniques even when the application gives no direct
  output of query results
- **Application logic interference** — change which records get returned to a search/filter
  function, potentially leaking other users' private data
- **Local file disclosure (engine-dependent)** — some XPath engines expose a `doc()` function
  that can be abused to read additional XML files on the filesystem if the injection point allows
  function calls rather than just string literals

The next file in this series, `02-Exploitation-Techniques.md`, walks through each of these with
every payload broken down piece by piece.
