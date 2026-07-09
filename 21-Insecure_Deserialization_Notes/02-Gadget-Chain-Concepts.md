# 02 — Gadget Chain Concepts

This file covers the theory that's identical across every language. Read this before any of
the per-language exploitation files (03–07) — they all assume you understand the vocabulary and
mechanics laid out here.

## 1. What a "Gadget" Actually Is

A **gadget** is any method that:

1. Already exists in the application's own code or in a library it loads, and
2. Gets executed automatically as a side effect of the deserialization process itself — not
   because the application explicitly called it, but because the *language runtime* calls it
   while reconstructing the object.

The key word is **automatically**. You never get to call arbitrary methods directly during
deserialization. What you get is a small, fixed set of "automatic call points" that every
language's serialization mechanism exposes, and your only lever is *which class* gets
deserialized into that call point — because the call point will then invoke whatever method
that class happens to define.

## 2. The Automatic Call Points, Per Language (Preview)

Every language gives you a different name for this, but the shape is identical: "if an object
of this type gets deserialized, this method on it runs without anyone explicitly calling it."

| Language | Automatic call point(s) | Covered in detail in |
|---|---|---|
| PHP | `__wakeup()`, `__destruct()`, `__toString()`, `__call()` (magic methods) | File 03 |
| Java | `readObject()` (if a class defines a custom one), plus methods invoked transitively from it | File 04 |
| Python | `__reduce__()`, `__setstate__()` (and `__reduce_ex__`) | File 06 |
| .NET | Constructors via `ISerializable`, property setters during JSON.NET type-resolved binding | File 07 |

## 3. Why a "Chain" Is Necessary

In the simplest case, a single magic method does something dangerous directly (e.g. a
`__destruct()` that deletes a file using an attacker-controlled path — this is the "using
application functionality" pattern, the easiest real lab scenario). But to get to something as
powerful as arbitrary OS command execution, the single automatic call point almost never does
anything dangerous by itself. Real applications don't ship a class whose destructor runs
`system($cmd)` with attacker input — that would just be a normal, obvious vulnerability.

Instead, you have to find a **sequence**:

```
Deserialization trigger (e.g. readObject)
  → calls Method A on Class 1 (because that's what readObject does for this class)
    → Method A's normal, legitimate logic happens to call Method B on some object stored in one
      of Class 1's fields
      → Method B's logic happens to call Method C on an object in one of *its* fields
        → ... eventually you reach a method that does something dangerous (e.g. invoke a
            command, instantiate a class by reflection, evaluate a script engine expression)
```

This is the **gadget chain**: a sequence of unrelated, individually harmless classes, linked
together purely by the fact that each one's normal field/method structure happens to call into
the next, until the chain bottoms out at a dangerous **sink**.

This is conceptually identical to **ROP (Return-Oriented Programming)** in binary exploitation:
you don't write new code, you stitch together existing code fragments ("gadgets") purely by
controlling what data flows into them. The same mental model transfers directly.

## 4. Two Ways to Get a Gadget Chain

### 4.1 Pre-built / known chains (most real-world cases)

Security researchers have already found and published chains for almost every widely-used
serialization-capable library: Apache Commons Collections, Spring, Hibernate, Groovy (Java);
various PHP frameworks; `__reduce__`-based one-liners for Python. Tools exist specifically to
generate the final malicious serialized blob from a known chain without you re-deriving it:

- **ysoserial** (Java) — covered in full in File 05.
- **ysoserial.net** (.NET) — covered in File 07.
- PHP gadget chains are usually framework-specific and published as PoC code (e.g. via
  `PHPGGC`, "PHP Generic Gadget Chains").

In black-box testing, this is almost always your first move: identify the library/framework
in use (from error messages, response headers, version disclosure), check whether a known
public gadget chain exists for it, and generate a payload with the matching tool.

### 4.2 Custom chains (source-code-dependent, the Expert-tier skill)

When no public chain fits — typically because the application's own classes are the chain,
not a third-party library — you need source-code access. The process, applicable in any
language:

1. **Identify the deserialization sink** (where untrusted bytes get deserialized).
2. **Identify the automatic call point** for that language (Section 2 above) on classes that
   are reachable/instantiable in the application's codebase.
3. **Work backward from a dangerous sink** (file write, command exec, reflective class
   instantiation) to find which existing method, if any, reaches that sink.
4. **Work forward from the automatic call point**, tracing through field types and method calls,
   until you find a path that connects to the sink found in step 3.
5. **Construct an object graph** (nested objects with fields pointing to other objects) that,
   when deserialized, walks exactly that path.
6. **Serialize that object graph by hand** (write code in the target language that builds the
   objects and calls the language's native serialize function — you cannot use the
   application's API for this, since you're crafting an attacker-side payload).

This is genuinely difficult and is what the **Expert**-tier PortSwigger labs test (see File 09).
It is also a realistic skill expectation for senior pentest/red-team roles, since CVE writeups
for major frameworks routinely involve exactly this process.

## 5. Why Shared Libraries Make This So Dangerous at Scale

If a gadget chain is found inside a popular library (not the target application's own code),
that chain works against **every application** that has that library on its classpath/installed
packages and a reachable deserialization sink — regardless of what the application itself does.
This is precisely why the 2015 disclosure of Apache Commons Collections gadget chains caused a
mass-RCE event across thousands of unrelated Java applications: the vulnerability was never in
any specific application's code, it was in a dependency almost everyone happened to be using.

When you find a deserialization sink during an engagement, always check **what's on the
classpath/installed**, not just what the application's own code does — the application may be
"clean" while still being fully exploitable through a dependency.

## 6. Format Quirk You Must Always Respect: Length-Prefixed Fields

Several serialization formats (most notably PHP's) embed explicit length counters inside the
serialized string itself — e.g. `s:5:"admin"` means "a string, 5 bytes long, value admin". If
you manually edit a field's value (changing `"admin"` to `"administrator"`) without also
updating that length prefix, the parser will misread the data boundary and either throw an
error or silently corrupt adjacent fields. This single detail is the most common reason a
manually-edited payload fails, and it's covered concretely with worked examples in File 03 and
again in the editing-tool guidance in File 08.

## 7. What's Next

File 03 applies all of this directly to PHP — the lowest-barrier-to-entry language for this
vulnerability class and the one most heavily represented in the PortSwigger Academy labs.

---
*Sensitive topic note: none — this file is purely technical/educational security content.*
