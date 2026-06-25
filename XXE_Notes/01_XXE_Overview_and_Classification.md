# 01 — XXE Overview and Classification

## Real-World Framing

XXE shows up constantly in real engagements wherever an application accepts XML —
SOAP APIs, SAML authentication flows, document upload pipelines (DOCX, XLSX, SVG all
contain XML internally), RSS/Atom feed processors, configuration import features, and
legacy B2B integrations that still speak XML instead of JSON. It is one of the highest
business-impact bugs a tester can find: file disclosure, SSRF into cloud metadata
services, and in some parser configurations, denial of service — all from a single
malformed XML body. Bug bounty programs and CVE databases are full of XXE findings in
unexpected places: PDF generators, image processing libraries (Apache Batik/SVG),
office-suite import features, and even password managers that import XML-based vaults.

## Why XXE Is Classified Under A05:2021

OWASP places XXE under **A05:2021 – Security Misconfiguration** because the root cause
is not a flaw in XML itself — it is a parser shipped with dangerous default behavior
(resolving external entities and DTDs) that the developer never explicitly disabled.
Prior to OWASP Top 10 2017, XXE had its own category. It was folded into Security
Misconfiguration because, structurally, the fix is identical to other misconfiguration
issues: change a setting before deployment (`disallow-doctype-decl`, disabling external
entity resolution, disabling XInclude) rather than rewrite application logic. This
series treats it separately from the broader Security Misconfiguration note set because
its exploitation techniques, payload mechanics, and tooling are specific enough to
deserve dedicated depth.

## XML Fundamentals You Need Before Any Payload Makes Sense

### The DOCTYPE and the DTD

Every XXE payload begins with a `DOCTYPE` declaration. A Document Type Definition (DTD)
is a block that can define the structure of an XML document, and — critically for
attackers — can also define **entities**: named placeholders that the parser substitutes
with other content before processing continues.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe "some value">
]>
<foo>&xxe;</foo>
```

Breaking this down token by token:

- `<?xml version="1.0" encoding="UTF-8"?>` — the XML prolog. Not part of the attack, but
  must remain valid or the parser rejects the document before reaching the DTD.
- `<!DOCTYPE foo [ ... ]>` — declares a DTD for the root element named `foo`. The square
  brackets open an **internal subset**, a block where entities can be declared inline,
  inside the document itself. `foo` here is just a label that should generally match (or
  be compatible with) the document's actual root element name — most parsers do not
  strictly enforce this, so it's common to see `<!DOCTYPE foo [...]>` even when the real
  root element has a different name.
- `<!ENTITY xxe "some value">` — defines a **general entity** named `xxe` whose value is
  the literal string `some value`. This is a normal (non-external) custom entity — the
  foundation the attacker abuses by replacing the literal string with a reference to a
  file or URL instead.
- `&xxe;` — an **entity reference**. Wherever this appears in the document body, the
  parser substitutes it with the entity's defined value before the application ever sees
  the "real" content.

### What Makes an Entity "External"

A normal custom entity's value is a literal string defined right there in the DTD. An
**external entity** instead tells the parser to fetch its value from outside the
document — from the local filesystem or over a network protocol:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

- `SYSTEM` — the keyword that marks this as an external entity and tells the parser the
  value should be loaded from the URI that follows, rather than treated as a literal
  string.
- `"file:///etc/passwd"` — the URI the parser will dereference. The triple slash is the
  `file://` scheme (empty host) followed by an absolute path `/etc/passwd`. The parser
  has no concept of "this is dangerous" — it is simply doing what URI resolution
  libraries do for any `SYSTEM` identifier, which is exactly the misconfiguration A05:2021
  is calling out: the capability exists and is enabled by default in many parsers, even
  though the application never intended to let user input dictate filesystem reads.
- There is also a `PUBLIC` variant (`<!ENTITY xxe PUBLIC "some-public-id" "http://...">`)
  used for referencing a formally registered external DTD by a public identifier, with a
  fallback system URI. It is rarer in attacker payloads but appears when repurposing
  known DTDs (covered in file 3).

### General Entities vs. Parameter Entities

This distinction matters enormously for blind XXE (file 3) and is worth understanding
now:

- **General entities** (`<!ENTITY name "value">`) are referenced with `&name;` and can
  only be used in the document's actual XML content (inside element bodies/attributes).
- **Parameter entities** (`<!ENTITY % name "value">`) are referenced with `%name;` and
  can only be used *within the DTD itself* — not in the document body. This matters
  because many blind XXE exploitation chains require building up the DTD dynamically
  using parameter entities to combine a local file's contents with an external URL, which
  general entities cannot do.

```xml
<!ENTITY % xxe "some DTD-only value">
```

The `%` immediately after `ENTITY` is what marks it as a parameter entity rather than a
general one — this single character changes both where the entity can be referenced
(`%xxe;` vs `&xxe;`) and where it is legal to use it.

## The Four Classes of XXE Attack

This series treats XXE as falling into four practical categories, which map directly to
the technique files that follow:

1. **Classic / in-band XXE** (file 2) — the application reflects the external entity's
   resolved value directly back in the HTTP response. You see the stolen file contents
   immediately. This is the easiest class to find and confirm.

2. **XXE-to-SSRF** (file 4) — instead of `file://`, the external entity uses `http://`
   or another network scheme, turning the XML parser into a proxy that makes outbound
   requests on the attacker's behalf. Useful even when no file is ever returned, because
   the request itself (and sometimes its response) has value — e.g. hitting cloud
   metadata endpoints.

3. **Blind XXE via out-of-band (OOB) exfiltration** (file 3) — the application never
   reflects anything related to XML processing, so confirmation and data exfiltration
   both depend on making the vulnerable server reach out to an attacker-controlled
   listener (DNS lookup or HTTP request), proving the entity was resolved server-side.

4. **Blind XXE via error-based exfiltration** (file 3) — when even OOB callbacks aren't
   possible (e.g. strict egress filtering), data can sometimes still be exfiltrated by
   intentionally causing the parser to throw a verbose error message that includes the
   sensitive data as part of the error text — for example, by trying to load a file as
   if it were the path to an external DTD, which fails and reports the file's contents
   in the parse error.

## How XXE Vulnerabilities Actually Arise (Root Cause)

Virtually every mainstream XML parsing library (libxml2, Java's `DocumentBuilderFactory`/
`SAXParserFactory`, .NET's `XmlDocument`, Python's `xml.etree`/`lxml`, PHP's
`simplexml`/`DOMDocument`) ships with external entity resolution **enabled by default**,
or did historically, because the XML specification requires conformant parsers to
support DTDs and entities. Developers writing XML-handling code rarely think about this
unless they are specifically aware of XXE — which is precisely the misconfiguration this
OWASP category targets. The fix is almost always a parser configuration change:
disabling DOCTYPE processing entirely, or disabling external entity/XInclude resolution
specifically — covered in more depth in file 6's cheatsheet.

## What's Next

File 2 walks through classic, in-band XXE — the technique to look for first on any
target, including the often-overlooked hidden attack surface (file uploads, XInclude,
content-type coercion) where XML parsing happens even when the application's "normal"
traffic doesn't look like XML at all.
