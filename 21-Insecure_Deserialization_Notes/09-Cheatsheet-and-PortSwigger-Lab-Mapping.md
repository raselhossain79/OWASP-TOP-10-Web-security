# 09 — Cheatsheet and PortSwigger Lab Mapping

Keep this file open in a second tab during active lab work. Section 1 is the quick-reference
cheatsheet; Section 2 is the full Academy lab list in the platform's real Apprentice →
Practitioner → Expert order (verified against the live Academy lab list, not grouped by theme).

## 1. Quick-Reference Cheatsheet

### 1.1 Recognizing serialized data on the wire

| Language | Tell-tale prefix (after Base64 decode unless noted) | Example start |
|---|---|---|
| PHP | `O:` (object), `a:` (array), `s:` (string) | `O:4:"User":2:{...}` |
| Java | Magic bytes `AC ED 00 05` → Base64 starts with `rO0` | `rO0ABXNyAB...` |
| Python pickle | `\x80` (protocol marker) → Base64 starts with `gA` | `gASVKgAAAA...` |
| .NET BinaryFormatter | Often starts `AAEAAAD/////` or similar header bytes | `AAEAAAD/////AQAA...` |
| .NET JSON.NET (TypeNameHandling) | Plain JSON containing a `$type` field — no decoding needed | `{"$type":"System...."}` |

### 1.2 First moves on any suspected sink

1. Decode the value (URL-decode, then Base64-decode if applicable).
2. Identify the format from Section 1.1.
3. Try a harmless field edit (boolean flip, numeric change) and re-submit — confirms the server
   actually trusts and re-deserializes client state with no integrity check.
4. If PHP: check for magic methods reachable from the class shown (`__wakeup`, `__destruct`).
5. If Java/.NET: fingerprint the framework/libraries in use, then try matching ysoserial /
   ysoserial.net payload names, starting with an out-of-band (Collaborator-style) command.
6. If Python: this is almost always source-code-driven (internal service, cache, ML pipeline)
   rather than a black-box web parameter — review code directly for `pickle.loads`/`pickle.load`.

### 1.3 PHP serialized-format syntax, at a glance

| Syntax | Type |
|---|---|
| `s:<len>:"<value>";` | string |
| `i:<value>;` | integer |
| `d:<value>;` | double/float |
| `b:0;` / `b:1;` | boolean false/true |
| `N;` | null |
| `a:<count>:{<key><value>...}` | array |
| `O:<len>:"<ClassName>":<propcount>:{...}` | object |

**Always recompute `<len>` after editing any string value by hand.**

### 1.4 Per-language "automatic call point" cheat table

| Language | Hook name | Triggered by |
|---|---|---|
| PHP | `__wakeup()` | Immediately after `unserialize()` |
| PHP | `__destruct()` | Object garbage collection / script end |
| Java | `readObject()` | `ObjectInputStream.readObject()` for that class |
| Python | `__reduce__()` | `pickle.loads()` / `pickle.load()` |
| .NET | `ISerializable` constructor | `BinaryFormatter.Deserialize()` |
| .NET | `$type`-resolved construction | JSON.NET with `TypeNameHandling != None` |

### 1.5 Tool command skeletons (see Files 05 and 07 for full flag breakdowns — never run these
blind)

```bash
# ysoserial (Java) — generate, then base64, then deliver via Burp Repeater
java -jar ysoserial-all.jar <PayloadName> "<command>" | base64 -w0

# ysoserial.net (.NET)
ysoserial.exe -p ObjectDataProvider -f Json.Net -g ObjectDataProvider -o raw -c "<command>"

# Python — disassemble a suspicious pickle WITHOUT executing it
python3 -c "import pickletools; pickletools.dis(open('suspect.pkl','rb').read())"
```

### 1.6 Severity framing for reports

| Outcome | Typical severity |
|---|---|
| Field tampering only (e.g. role/flag change) | High (often Critical if it's privilege escalation) |
| Application-logic abuse via a magic method (e.g. arbitrary file delete) | High–Critical |
| Confirmed gadget-chain RCE | Critical |

## 2. PortSwigger Web Security Academy — Insecure Deserialization Labs (Correct Order)

The Academy's Insecure Deserialization topic covers **PHP, Java, and Ruby** — 10 labs total,
listed below in the platform's actual difficulty sequence. **Python and .NET (Files 06 and 07
of this series) are not represented on the Academy** and are included here purely as real-world
extensions; practice them in your own lab environment.

### Apprentice

| # | Lab | Language | Maps to |
|---|---|---|---|
| 1 | Modifying serialized objects | PHP | File 03, Section 1–2 (basic field/type editing) |

### Practitioner

| # | Lab | Language | Maps to |
|---|---|---|---|
| 2 | Modifying serialized data types | PHP | File 03, Section 2 (type juggling) |
| 3 | Using application functionality to exploit insecure deserialization | PHP | File 03, Section 3 (magic-method-driven file delete) |
| 4 | Arbitrary object injection in PHP | PHP | File 03, Section 4 (POP chain construction) |
| 5 | Exploiting Java deserialization with Apache Commons | Java | File 04 (Commons Collections background) + File 05 (ysoserial usage, including the Java 16+ `--add-opens` flags) |
| 6 | Exploiting PHP deserialization with a pre-built gadget chain | PHP | File 03, Section 4 (using a published/PHPGGC-style chain rather than building one from scratch) |
| 7 | Exploiting Ruby deserialization using a documented gadget chain | Ruby | Not covered as a dedicated file in this series (series scope is PHP/Java/Python/.NET per your requirements) — the underlying gadget-chain *concept* in File 02 transfers directly; Ruby's own magic method is `marshal_load`, played identically to `__wakeup`/`readObject`/`__reduce__` |

### Expert

| # | Lab | Language | Maps to |
|---|---|---|---|
| 8 | Developing a custom gadget chain for Java deserialization | Java | File 02, Section 4.2 (custom chain methodology) + File 04, Section 7 |
| 9 | Developing a custom gadget chain for PHP deserialization | PHP | File 02, Section 4.2 + File 03, Section 4 |
| 10 | Using PHAR deserialization to deploy a custom gadget chain | PHP | File 03, Section 5 (PHAR mechanism in full) |

## 3. Suggested Practice Order

1. Lab 1 → confirm you can read/edit the PHP format by hand (File 03 §1).
2. Lab 2 → confirm you understand type juggling (File 03 §2).
3. Lab 3 → confirm you can identify a dangerous magic method from source (File 03 §3).
4. Lab 4 → first real POP chain (File 03 §4).
5. Lab 5 → first tool-assisted Java exploitation; this is also where you'll hit the Java 16+
   module flags in practice (File 05 §4) if running a modern JDK locally.
6. Lab 6 → PHP pre-built chain, contrast against Lab 4's from-scratch chain.
7. Lab 7 → Ruby, using the transferable gadget-chain theory from File 02.
8. Labs 8–10 (Expert) → custom chain construction; budget significantly more time here, this is
   genuinely advanced source-code-dependent work.
9. Once comfortable, move to your own local lab setup for Python (File 06) and .NET (File 07),
   since neither is testable on the Academy itself.

## 4. Closing Real-World Note

Across all four languages in this series, the single highest-leverage habit is the same one
emphasized in File 02: **always check what libraries/dependencies are present on the target**
before assuming you need to build anything from scratch. The majority of real-world
deserialization RCE findings — from the original Apache Commons Collections disclosures through
recent .NET `ObjectDataProvider` findings — were exploitable purely because of a known chain in
a shared dependency, not because of any custom application logic. Source-code-dependent custom
chain construction (the Expert-tier skill) is a genuinely valuable capability to have, but it is
the exception in real engagements, not the rule.

---
*Sensitive topic note: none — this file is purely technical/educational security content.*
