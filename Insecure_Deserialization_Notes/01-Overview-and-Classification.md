# 01 — Overview and Classification

## 1. What Serialization and Deserialization Actually Are

Serialization is the process of flattening an in-memory object (its class name, its fields, the
values of those fields) into a sequence of bytes or a string, so that it can be:

- Stored on disk or in a database
- Sent over a network or in an API call
- Cached
- Passed between processes that don't share memory

Deserialization is the reverse operation: take that byte stream and reconstruct it back into a
live object in memory, including restoring its internal state.

Different languages use different names for the same idea:

- **PHP / Java / generic** → "serialization" / "deserialization"
- **Python** → "pickling" / "unpickling"
- **Ruby** → "marshalling" / "unmarshalling"
- **.NET** → "serialization" / "deserialization" (multiple competing formats — BinaryFormatter,
  JSON.NET, XML, SOAP)

None of this is inherently dangerous. The danger appears the moment **untrusted, user-controllable
data is fed into a deserialization routine.**

## 2. Why This Is Its Own Vulnerability Class

Insecure deserialization is mapped under **OWASP A08:2021 — Software and Data Integrity
Failures** (it absorbed the old A8:2017 "Insecure Deserialization" category). It deserves its
own dedicated note set, separate from generic injection topics, for three reasons:

1. **It is not really "injection" in the SQLi/XSS sense.** You are not injecting a malicious
   string into a query or a page. You are handing the application a malicious *object graph*
   and letting the application's own legitimate code execute against it. The vulnerability is
   in the *trust boundary*, not in string handling.
2. **The exploitation primitive is reusable across unrelated applications.** A gadget chain
   discovered in a shared library (Apache Commons Collections, for example) can be reused
   against any application that happens to load that library on its classpath, regardless of
   what the application itself does. This is fundamentally different from SQLi, where the
   payload is tied to that specific query.
3. **It frequently escalates straight to Remote Code Execution (RCE)**, whereas many injection
   classes top out at data exfiltration unless chained further.

## 3. The Core Mental Model: Source → Gadget → Sink

Every deserialization exploit, regardless of language, follows the same three-part shape:

| Stage | Meaning |
|---|---|
| **Source** | The deserialization entry point — e.g. `unserialize()` in PHP, `ObjectInputStream.readObject()` in Java, `pickle.loads()` in Python, `BinaryFormatter.Deserialize()` in .NET. This is where attacker-controlled bytes enter the trust boundary. |
| **Gadget(s)** | Existing classes/methods already present in the application or its libraries, which get invoked automatically as a side effect of deserializing a crafted object (constructors, destructors, magic methods, `__reduce__`, `readObject`, property setters). |
| **Sink** | The dangerous final operation a gadget chain reaches — typically OS command execution, file read/write, or arbitrary code execution. |

You are never writing new code to run on the target. You are stitching together a path through
code that **already exists** on the target, using the deserialization mechanism as the trigger.
This is why the skill of building gadget chains is closer to "exploit chain construction" than
to traditional payload crafting.

## 4. Where This Shows Up in Real Engagements

This is not a theoretical lab-only bug class. Real-world patterns a pentester will hit:

- **Session/cookie state**: applications that serialize a user/session object and store it
  client-side (cookie, hidden field) instead of server-side. This is the single most common
  real-world finding pattern and is exactly what most PortSwigger labs simulate.
- **Caching layers**: Redis/Memcached values, or local disk caches, that get deserialized back
  into objects without validation.
- **Message queues / inter-service communication**: microservices that pass serialized Java
  objects or pickled Python objects between services (common in older Java EE/Spring stacks and
  in internal Python data pipelines).
- **.NET ViewState**: ASP.NET WebForms applications store serialized page state client-side by
  default; if the MachineKey is known/leaked/predictable, this becomes a direct RCE path.
- **Third-party library upgrades**: an application itself may have zero custom deserialization
  code, but still be exploitable purely because of what's sitting on the classpath/site-packages
  (Apache Commons Collections in old Java stacks is the textbook example — this is what made
  deserialization bugs famous starting around 2015 with the "Java deserialization apocalypse").

## 5. Detection Methodology

### Black-box (no source code)

- Look for parameters/cookies/hidden fields that are Base64-encoded blobs. Decode them — PHP
  serialized objects are recognizable by the `O:<len>:"<ClassName>":<count>:{...}` pattern; Java
  serialized objects start with the magic bytes `AC ED 00 05` (hex) which Base64-encodes to a
  recognizable `rO0` prefix; Python pickles often start with `\x80` (protocol marker, varies by
  protocol version); .NET BinaryFormatter blobs are also `AAEAAAD/////` style or magic-byte
  prefixed depending on format.
- Try editing simple fields in a decoded serialized object (a boolean `admin` flag, a numeric
  `role` field) and re-encoding, to confirm the server actually trusts and re-deserializes
  client-supplied state without integrity checks (no HMAC, no signature).
- Watch for stack traces in error responses — deserialization errors frequently leak the exact
  class name being deserialized, library versions, and sometimes full file paths. This is gold
  for gadget chain selection.

### White-box (source code available)

- Search for the dangerous sink functions directly: `unserialize(` (PHP), `readObject(` /
  `ObjectInputStream` (Java), `pickle.loads(` / `pickle.load(` (Python), `BinaryFormatter`,
  `NetDataContractSerializer`, `ObjectStateFormatter` (.NET).
- Trace backward from each sink to confirm whether the input is attacker-controlled (a cookie,
  a request parameter, an uploaded file) versus fully server-generated and never touched by the
  client.
- Enumerate what's on the classpath / installed packages, since a vulnerable sink with a known
  vulnerable gadget library present is an automatic high-severity finding even before you build
  a custom chain.

## 6. Severity and Real-World Impact

Per OWASP's own framing, it can be argued that there is no fully "safe" way to deserialize
untrusted input — the safest fix is almost always to stop deserializing untrusted data into
typed objects entirely (switch to data-only formats like plain JSON without type metadata, or
sign/encrypt the serialized blob server-side). When reporting findings, frame impact along this
escalation ladder, since not every deserialization bug reaches RCE:

1. **Object/data tampering** — change a boolean flag, numeric ID, or role inside the object
   (lowest severity, still often critical — e.g. privilege escalation).
2. **Type confusion / application-logic abuse** — supply an unexpected object type that the
   application's existing logic then operates on dangerously (e.g. a path-deletion routine
   reading an attacker-supplied file path from a deserialized field).
3. **Gadget chain RCE** — full remote code execution via a chain of existing classes, the
   highest-severity outcome and the one most reports focus on.

## 7. What's Next

File 02 covers gadget chain theory in detail — the concepts in this file (source/gadget/sink)
get expanded into the actual mechanics of *why* a chain of unrelated classes can produce code
execution, before the per-language files (03–07) apply that theory concretely.

---
*Sensitive topic note: none — this file is purely technical/educational security content.*
