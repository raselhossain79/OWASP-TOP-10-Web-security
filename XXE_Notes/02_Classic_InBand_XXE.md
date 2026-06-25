# 02 — Classic / In-Band XXE

## Real-World Framing

In-band XXE is the variant testers find most often during manual testing because it's
self-confirming: you send a payload, the response contains the file you asked for. In
the wild this turns up most often in SOAP web services, XML-based API endpoints,
SAML assertions during SSO flows, and document-processing features (anything that
accepts an uploaded file and parses XML internally — SVG avatars, DOCX resumes, XLIFF
translation files). A single classic XXE finding on a SOAP endpoint commonly escalates
to full source code disclosure, SSH key theft (`~/.ssh/id_rsa`), or cloud credential
theft, because the technique reads arbitrary files the web server process has
permission to access — not just web-root files.

## Step 1: Recognizing the Attack Surface

Before injecting anything, identify where the application is parsing XML server-side:

- **Obvious surface**: requests with `Content-Type: application/xml` or
  `Content-Type: text/xml`, or a body that is visibly XML.
- **Hidden surface via content-type coercion**: some endpoints accept
  `application/x-www-form-urlencoded` by default but will *also* parse the body as XML
  if you change the `Content-Type` header to `text/xml` and supply a well-formed XML
  body with equivalent structure. Many frameworks are lenient about content negotiation,
  and this alone can expose attack surface the application "didn't mean" to expose.
- **Hidden surface via file upload**: SVG, DOCX, XLSX, PDF (in some toolchains), and
  other "rich" formats are XML-based or XML-containing under the hood. If an app
  processes uploaded images/documents server-side (resizing, thumbnailing, metadata
  extraction, virus-scanning previews), the parser touching that file may be vulnerable
  even though the upload endpoint never looks XML-related from the outside.
- **Hidden surface via XInclude**: when you only control a single data value that gets
  embedded into a larger, server-controlled XML document (e.g. your input is dropped
  into a back-end SOAP request), you cannot define your own `DOCTYPE` — but the
  document may still process `XInclude` directives if the parser supports it.

## Technique 1: Basic File Retrieval

### The Vulnerable Baseline Request

Suppose a stock-checking feature sends:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
```

### The Attack Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

### Piece-by-Piece Breakdown

- `<!DOCTYPE foo [ ... ]>` — injects a DTD with an internal subset. This is inserted
  between the XML prolog and the root element; it must come before the root element
  opens or the document is malformed.
- `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — defines a general external entity named
  `xxe`. `SYSTEM` tells the parser to dereference the URI rather than treat it as
  literal text. `file:///etc/passwd` uses the `file` URI scheme to point at an absolute
  filesystem path on the server the parser is running on — not the attacker's machine.
- `&xxe;` — placed where the original numeric `productId` value used to be. When the
  parser builds the DOM/SAX tree, it resolves this reference to the full contents of
  `/etc/passwd` *before* the application's business logic ever runs. The application
  thinks it received an unusually long, weird `productId` — which is exactly what gets
  reflected back when the app reports "Invalid product ID: ...".
- Why it works at all: the application's only "defense" was assuming `productId` would
  be numeric. It never validated that, and the parser was never told to refuse external
  entities. Both gaps have to exist for this to succeed.

### Real-World Note

In practice, never assume only one field is reflected. Systematically test every XML
data node in the document by replacing each one's value with `&xxe;` in turn and
watching which response changes — large real-world XML payloads (SOAP envelopes
especially) can have dozens of fields, and only one of them might end up echoed
anywhere in the response.

## Technique 2: Using Parameter Entities for In-Band Retrieval

If `SYSTEM` general entities don't resolve as expected (some parsers are stricter about
general external entities than parameter ones), parameter entities can sometimes still
be coerced into the document body indirectly by having one entity's value reference
another:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY xxe SYSTEM 'file:///etc/hostname'>">
  %eval;
]>
<foo>&xxe;</foo>
```

- `<!ENTITY % file SYSTEM "...">` — a parameter entity (note the `%`) holding the path
  to read. Used here mainly to illustrate the parameter-entity-as-builder pattern that
  becomes essential in blind XXE (file 3) — this pattern is more commonly needed for OOB
  chains than for simple in-band reads, but the mechanics are identical.
- `%eval;` on its own line inside the DTD — this is a parameter entity *reference* used
  at the DTD level, which causes the parser to expand it in place, effectively writing a
  brand-new `<!ENTITY xxe ...>` declaration into the DTD dynamically.
- `&xxe;` in the body then resolves normally, as in Technique 1.

This "entity that defines another entity" pattern is the core mechanic behind every
advanced XXE payload in this series — internalize it now because file 3 builds directly
on it.

## Technique 3: XInclude Attacks (When You Don't Control the Whole Document)

### When This Applies

Some applications take a piece of user-submitted data and splice it into a larger,
server-generated XML document before parsing — for example, embedding a user's comment
into a back-end SOAP call. You don't control the `DOCTYPE`, so general/parameter entity
tricks above don't apply. But if the parser supports `XInclude`, you can still reach
files by injecting an XInclude directive purely within the data value you do control.

### The Payload

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### Piece-by-Piece Breakdown

- `xmlns:xi="http://www.w3.org/2001/XInclude"` — declares the `xi` namespace prefix
  bound to the official XInclude specification URI. This is mandatory; without declaring
  the namespace, `<xi:include>` is just an unrecognized element and does nothing.
- `<xi:include ... />` — the actual directive. The parser, if XInclude processing is
  enabled, replaces this element with the content found at `href` before the document
  is handed to the application.
- `parse="text"` — tells the parser to treat the included file as raw text rather than
  trying to parse it as XML. This matters because `/etc/passwd` is not valid XML; without
  `parse="text"`, the parser would try to XML-parse `/etc/passwd`'s contents and fail.
  `parse="xml"` is the default if omitted, so for arbitrary OS files this attribute is
  required, not optional.
- `href="file:///etc/passwd"` — same `file://` URI mechanic as before.

### Real-World Note

XInclude attacks come up specifically in service-oriented architectures where front-end
input gets stitched into back-end XML/SOAP calls — a very common pattern in older
enterprise integration layers (ESBs, legacy banking/insurance back-ends) that are still
common in real assessments even though they look "old."

## Technique 4: XXE via File Upload (SVG Example)

### Why SVG

SVG is an XML-based image format. If an application accepts image uploads and uses a
library that also happens to process SVG (e.g. Apache Batik, ImageMagick with certain
delegates, librsvg), uploading a malicious SVG can trigger XXE even though the
upload feature has nothing to do with "XML" from the user's point of view.

### The Payload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### Piece-by-Piece Breakdown

- `standalone="yes"` — declares the document has no external dependencies as far as its
  *grammar* goes; this is just a normal XML prolog attribute and does not itself enable
  or disable entity resolution — that depends entirely on the parser's configuration.
- `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>` — identical mechanic
  to Technique 1, just embedded inside an SVG file instead of an API request body.
- `<svg ... xmlns="..." xmlns:xlink="...">` — standard SVG namespace boilerplate required
  for the file to be recognized and rendered as a valid SVG image by the processing
  library.
- `<text ...>&xxe;</text>` — places the resolved entity value into a visible text
  element, so that when the image is rendered/viewed, the stolen file contents appear
  printed inside the image itself.

### Real-World Note

Save this as a `.svg` file and upload it through the normal file-upload UI — there is
no need for Burp Suite to modify a request body, since the attack surface here is the
uploaded *file's* content, not the HTTP request structure. This is a useful technique to
remember when an app's API surface looks completely XXE-free but accepts images/avatars.

## Technique 5: Content-Type Coercion to Reach Hidden XML Endpoints

Many endpoints built around `application/x-www-form-urlencoded` bodies will still parse
the request as XML if you switch the `Content-Type` header, because the underlying
framework's content negotiation is more permissive than the developer realized:

```
POST /action HTTP/1.1
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

- Changing only the `Content-Type` header (from
  `application/x-www-form-urlencoded` to `text/xml`) and reformatting the body as
  well-formed XML is sometimes enough on its own to flip a "normal" form submission into
  parsed-XML attack surface — worth trying on any endpoint, even ones that look
  completely unrelated to XML.

## What's Next

File 3 covers what to do when none of this works because the application is blind —
it never reflects anything related to your injected entity. That's where out-of-band
exfiltration and error-based exfiltration come in, along with the parameter-entity
"DTD builder" pattern introduced briefly above, used in full.
