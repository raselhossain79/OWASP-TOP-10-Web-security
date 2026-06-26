# 07 — .NET Deserialization

**Scope note**: Like File 06, this is real-world/industry-standard content not currently
represented as a dedicated lab category on PortSwigger Web Security Academy. File 09 does not
map any Academy lab to this section for that reason — practice against a deliberately
vulnerable local ASP.NET app (several public vulnerable-by-design .NET repos exist for this
exact purpose) rather than expecting it on the Academy.

## 1. Why .NET Is More Fragmented Than the Other Three Languages

Unlike PHP (one `unserialize()`), Java (one `ObjectInputStream`), or Python (one `pickle`
module), .NET has historically shipped **multiple, competing serializers**, each with different
exploitation mechanics:

| Serializer | Typical use | Exploitability |
|---|---|---|
| `BinaryFormatter` | Legacy, very common in older WebForms/WCF apps | Directly exploitable by design — Microsoft itself now describes it as dangerous and unsafe for any untrusted input |
| `JSON.NET` (Newtonsoft.Json) | Extremely common in modern .NET web APIs | Exploitable **only** when the application explicitly opts into `TypeNameHandling` other than `None` |
| `DataContractSerializer` / `NetDataContractSerializer` | WCF services | `NetDataContractSerializer` (not the plain `DataContractSerializer`) carries full type info and is exploitable similarly to BinaryFormatter |
| `XmlSerializer` | Generally requires the *type* to be known/fixed ahead of time | Lower risk by default, but still relevant if attacker-controlled type info is involved |
| `LosFormatter` | Used internally by ASP.NET ViewState | Directly relevant via the ViewState attack path (Section 3) |

## 2. BinaryFormatter — The Core Mechanism

```csharp
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(untrustedStream); // <-- the sink
```

`BinaryFormatter.Deserialize()` reconstructs an object graph from the byte stream, including
restoring the **exact type** of every object in that graph from type metadata embedded directly
in the serialized bytes themselves. This embedded type metadata is the entire reason exploitation
is possible: you are not limited to types the application expects — you can specify **any type
available in any assembly loaded into the target process**, the same "use what's already
there" principle from File 02, just expressed through .NET's type system instead of magic
methods.

The automatic call point here is the **constructor pattern via `ISerializable`**: a class
implementing `ISerializable` defines a special constructor that .NET calls automatically during
deserialization:

```csharp
public MyClass(SerializationInfo info, StreamingContext context) {
    // runs automatically the instant an object of this type is deserialized
}
```

This plays the exact same structural role as PHP's `__wakeup()`, Java's `readObject()`, and
Python's `__reduce__` — an automatic call point you can aim at a class whose constructor logic,
directly or through a further chain, reaches a dangerous sink (commonly via `ObjectDataProvider`
gadget chains that ultimately invoke an arbitrary method via reflection, conceptually identical
to Java's `InvokerTransformer` from File 04).

## 3. ViewState — .NET's Highest-Real-World-Impact Deserialization Surface

ASP.NET WebForms applications, by default, serialize the entire page's UI state (`ViewState`)
into a hidden form field and send it to the **client**, then deserialize whatever comes back on
the next request using `LosFormatter` (which itself relies on `ObjectStateFormatter` internals).
This means ViewState is, by default, **client-supplied serialized data being deserialized
server-side on every postback** — a textbook deserialization sink built directly into the
framework's default behavior, not an application bug.

### Why ViewState is "protected" by default — and how that protection breaks

Out of the box, ASP.NET signs ViewState with a **MAC (Message Authentication Code)** keyed by
the server's `MachineKey`, specifically to prevent exactly the tampering described in this file.
In theory this should make ViewState safe. In practice, this protection fails in several
well-documented real-world scenarios:

- **The `MachineKey` is leaked or guessable.** A notable real-world category: a known,
  publicly-documented default/sample `MachineKey` shipped in some framework templates or
  outdated tutorials gets left unchanged in production. Tools exist (e.g.
  `ysoserial.net`'s companion `--generator=ViewState` mode, used together with a known
  MachineKey) specifically to forge a validly-MAC'd, malicious ViewState payload once the key is
  known.
- **`EnableViewStateMac` is explicitly disabled** (a legacy/misguided "performance" or
  compatibility setting) — this removes the integrity check entirely, making any submitted
  ViewState directly deserialized with zero validation.
- **Pre-auth deserialization via the `__VIEWSTATEGENERATOR`/encryption-oracle style attacks**
  (the historically significant **ysoserial.net "ViewState" / "MachineKey" related CVE
  research**, e.g. around ASP.NET's padding-oracle issues) allowed attackers to forge valid
  ViewState **without ever knowing the MachineKey directly**, by abusing how the framework
  reported decryption/validation errors — a class of vulnerability significant enough to have
  driven real Microsoft security patches.

## 4. JSON.NET `TypeNameHandling` — The Modern-API Equivalent

JSON.NET, by default, deserializes JSON purely as plain data (strings, numbers, generic
objects/dictionaries) — this default behavior is **safe**, because there is no embedded type
information for an attacker to abuse. The vulnerability appears **only** when the application
explicitly configures:

```csharp
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All // or .Auto / .Objects / .Arrays
};
JsonConvert.DeserializeObject<object>(untrustedJson, settings);
```

- `TypeNameHandling.All` (or any non-`None` value) tells JSON.NET to **read a `$type` field
  embedded in the JSON itself** and instantiate exactly that .NET type during deserialization —
  reintroducing the same "attacker chooses the type" primitive BinaryFormatter has by default,
  just gated behind an explicit opt-in setting most developers add for legitimate
  polymorphism-handling reasons without realizing the security implication.

Exploitation payload shape:

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList",
    "$values": ["cmd", "/c calc.exe"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```

- `"$type": "System.Windows.Data.ObjectDataProvider, ..."` — instructs JSON.NET to instantiate
  Microsoft's own `ObjectDataProvider` class, whose entire legitimate purpose (in WPF data
  binding) is to invoke a method on a target object by name — exactly the "reflection-based
  invoker" gadget role `InvokerTransformer` plays in Java (File 04).
- `"MethodName": "Start"` — the method to invoke; here, `Process.Start`.
- `"ObjectInstance": { "$type": "System.Diagnostics.Process, System" }` — the object to invoke
  that method *on*: a `Process` instance, again specified purely via embedded type metadata.
- `"MethodParameters"` — the arguments passed to `Start`, here `cmd /c calc.exe` as a
  proof-of-concept; in a real engagement this becomes whatever command achieves your verified,
  in-scope objective.

This exact gadget (`ObjectDataProvider` + `Process`) is one of ysoserial.net's most commonly
used built-in payload types specifically because it requires no special third-party library —
`PresentationFramework` and `System.Diagnostics.Process` are both part of the standard .NET
Framework, making this chain broadly available across nearly any .NET application.

## 5. ysoserial.net — Flag-by-Flag

ysoserial.net is a **separate tool** from Java's ysoserial (File 05), purpose-built for .NET's
serializers:

```bash
ysoserial.exe -p ObjectDataProvider -o base64 -g "TextFormattingRunProperties" -c "cmd /c calc.exe"
```

| Flag | Meaning |
|---|---|
| `-p ObjectDataProvider` | **Payload** — selects the gadget chain/technique to use; `ObjectDataProvider` is the chain shown conceptually in Section 4 above. |
| `-o base64` | **Output format** — encode the resulting bytes as Base64 text rather than raw binary, since the target almost always expects a text-safe value in a parameter/field. |
| `-g "TextFormattingRunProperties"` | **Gadget** — within the chosen payload technique, this selects the *specific* "trigger" class used to kick off the `ObjectDataProvider` invocation during deserialization (different gadgets are needed depending on which serializer — JSON.NET vs BinaryFormatter vs others — is actually doing the deserializing on the target, since different gadgets hook into different serializers' automatic call points). |
| `-c "cmd /c calc.exe"` | **Command** — the actual command string to execute on the target once the chain runs; `cmd /c` runs a single command via the Windows command interpreter and then exits, the Windows equivalent of `sh -c` on Linux. |

For BinaryFormatter targets specifically, you'd typically pair this with `-f BinaryFormatter`
(specifying the **formatter** the *target* uses, since ysoserial.net needs to wrap the gadget in
the exact byte format that formatter expects); for JSON.NET targets, `-f Json.Net` similarly
tells ysoserial.net to wrap the output as the `$type`-annotated JSON shown in Section 4 rather
than raw binary.

```bash
ysoserial.exe -p ObjectDataProvider -f Json.Net -o raw -g ObjectDataProvider -c "calc.exe"
```

- `-f Json.Net` — target formatter is JSON.NET, so output the JSON-with-`$type` structure shown
  in Section 4 rather than binary.
- `-o raw` — output the raw text/bytes with no additional encoding (appropriate here since
  JSON.NET payloads are already plain text, unlike BinaryFormatter's true binary output which
  usually needs `-o base64` for safe transport).

Run `ysoserial.exe --help` (or just `ysoserial.exe` with no arguments, depending on build) to
list every payload and gadget combination available in your specific build — this list grows as
new chains are researched, so always check your local copy rather than relying on a fixed list
from memory or an older writeup.

## 6. Real-World Notes

- ViewState exploitation (Section 3) has caused real, high-severity, pre-authentication RCE
  findings in production ASP.NET WebForms applications when a known/leaked MachineKey was in
  use — always check whether `EnableViewStateMac` is set to `false` or whether the application
  uses a publicly-documented sample key before ruling this out.
- `TypeNameHandling` misuse in JSON.NET is the most common modern .NET deserialization finding,
  precisely because it's such an easy, well-intentioned mistake (added for legitimate
  polymorphic deserialization needs) — check any .NET API's `JsonSerializerSettings`
  configuration directly if source is available.
- Always confirm execution via an out-of-band callback (the same Collaborator-style approach
  from File 05 Section 6) before committing to a destructive payload, exactly as with Java.

## 7. What's Next

File 08 covers detection and WAF/filter-evasion techniques that apply across all four languages
covered in this series — this is where you'll find what to do when your otherwise-correct
payload gets blocked by a signature-based filter or WAF rule.

---
*Sensitive topic note: none — this file is purely technical/educational security content.*
