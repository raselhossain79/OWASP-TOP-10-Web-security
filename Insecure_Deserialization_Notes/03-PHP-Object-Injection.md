# 03 — PHP Object Injection

## 1. The PHP Serialization Format

PHP's `serialize()` produces a compact, length-prefixed string format. You need to be able to
read and hand-edit this fluently — most real-world findings start with exactly this.

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

Breaking this down piece by piece:

| Fragment | Meaning |
|---|---|
| `O:4:"User":2:{...}` | `O` = this is an Object. `4` = the class name is 4 characters long. `"User"` = the class name. `2` = the object has 2 properties. Everything inside `{...}` is those 2 properties. |
| `s:8:"username";` | `s` = this value is a string. `8` = it is 8 bytes long. `"username"` = the property name (also a string, hence its own `s:8:"..."` framing — every property *name* is itself encoded the same way as a value). |
| `s:6:"wiener";` | The *value* for the `username` property: a string, 6 bytes, `"wiener"`. |
| `s:5:"admin";` | Property name #2: a string, 5 bytes, `"admin"`. |
| `b:0;` | The value for `admin`: a boolean, value `0` (false). `b:1;` would be true. |

Other type prefixes you'll encounter:

| Prefix | Type |
|---|---|
| `i:` | integer, e.g. `i:42;` |
| `d:` | double/float, e.g. `d:3.14;` |
| `s:` | string (always length-prefixed in bytes, not characters — important for multi-byte data) |
| `b:` | boolean (`0` or `1`) |
| `a:` | array, e.g. `a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}` — count of key/value *pairs*, then each key then value |
| `N;` | null |
| `O:` | object (class name + property count + properties, as shown above) |

### The #1 rule when hand-editing: fix the length prefixes

If you change `s:6:"wiener"` to `s:13:"administrator"`, you **must** update the `6` to `13`
(byte length of the new string), or PHP's parser will read exactly 6 bytes, get `"admini"`, then
choke on the leftover `strator"` it wasn't expecting and either error out or silently misparse
the rest of the object. This is the single most common reason a manual payload edit fails. The
**Hackvertor** Burp extension (BApp Store) automates this — it lets you edit the *value* as
plain text inside special tags, and it recalculates every length prefix and re-encodes the
whole structure (including outer Base64/URL-encoding) automatically. For learning purposes,
always do at least your first few edits by hand so you actually understand the format; switch
to Hackvertor once you're confident, purely for speed on an engagement.

## 2. Type Juggling (PHP's Comparison Quirks)

PHP's loose comparison (`==`) and certain string-to-type comparisons behave in
counter-intuitive ways that become directly exploitable once you can control a deserialized
field's *type*, not just its value:

```
"0" == 0          // true (string "0" loosely equals integer 0)
"abc" == 0        // true in older PHP behavior in some contexts
```

If an application compares a deserialized field against a secret (e.g. an access token) using
`==`, and you can supply that field as an **integer `0`** instead of a string (`i:0;` instead of
`s:32:"...";`), you may be able to force a match against values that loose-compare to zero
(empty strings, non-numeric strings in older PHP versions, etc.) without knowing the actual
secret. This is exactly the access-token-bypass pattern used in real session-forgery findings:
decode the cookie, find a string field holding a token, replace `s:32:"<token>"` with `i:0;`,
re-encode, and the comparison `$submitted_token == $real_token` may evaluate true purely from
type coercion — no knowledge of the real token required.

## 3. Magic Methods — The Automatic Call Points

PHP classes can define special methods that the engine calls **automatically** at specific
lifecycle moments, without anyone explicitly invoking them:

| Magic method | Called automatically when |
|---|---|
| `__wakeup()` | Immediately after `unserialize()` reconstructs the object — the most direct deserialization hook |
| `__destruct()` | When the object is garbage-collected (script end, or variable goes out of scope) |
| `__toString()` | Whenever the object is used in a string context (e.g. concatenated, echoed, passed to a function expecting a string) |
| `__call()` / `__callStatic()` | When code tries to call a method that doesn't exist on the object |
| `__get()` / `__set()` | When code reads/writes a property that doesn't exist or isn't accessible |

For exploitation, `__wakeup()` and `__destruct()` are the two you'll lean on most, because they
fire unconditionally as a direct consequence of deserialization — you don't need the
application to do anything else with the object afterward.

### Worked example: "using application functionality" pattern

This is the exact shape of PortSwigger's *Using application functionality to exploit insecure
deserialization* lab. Suppose decompiled/leaked source shows:

```php
class CustomTemplate {
    private $template_file_path;
    public function __destruct() {
        // Cleanup logic: delete the template file when the object is destroyed
        unlink($this->template_file_path);
    }
}
```

`unlink()` deletes the file at the given path — with **no validation** that the path is
actually a template file. Since `__destruct()` fires automatically once the object is garbage
collected, all you need to do is:

1. Build a serialized `CustomTemplate` object with `template_file_path` set to a target file
   (e.g. another user's file, or a file outside the intended directory).
2. Submit that serialized object wherever the application deserializes attacker input
   (typically a session cookie).
3. Let the request complete normally — PHP destroys the object at end of script execution,
   `__destruct()` fires, `unlink()` runs with your path.

The crafted payload, piece by piece:

```
O:14:"CustomTemplate":1:{s:18:"template_file_path";s:10:"/home/carlos/morale.txt";}
```

- `O:14:"CustomTemplate"` — object of class `CustomTemplate` (14 characters).
- `:1:{...}` — exactly 1 property follows.
- `s:18:"template_file_path"` — property name, 18 bytes long.
- `s:10:"/home/carlos/morale.txt"` *(note: in a real payload the length must exactly match the
  byte length of the path string you use — recalculate it for your actual target path; the
  number shown here is illustrative)* — the attacker-controlled path value.

Nothing here is "malicious code." It's a completely ordinary file-deletion routine, triggered
by an object lifecycle event you control. This is the cleanest illustration of why this bug
class is described as "abusing legitimate application logic," not injecting new code.

## 4. POP Chains (Property-Oriented Programming) in PHP

When the single magic method available doesn't do anything dangerous *directly*, you chain
through it the same way described generically in File 02: the magic method's body calls a
method on an object stored in one of its properties, and **you get to choose what class that
property actually holds** at deserialization time (PHP doesn't enforce property types unless
the class explicitly declares typed properties, and even then there are bypasses). This is
called a **POP chain** (Property-Oriented Programming), the PHP-specific name for the general
"gadget chain" concept.

Example chain shape:

```php
class A {
    private $obj;
    public function __destruct() {
        $this->obj->process(); // calls process() on whatever $obj actually is
    }
}

class B {
    private $cmd;
    public function process() {
        system($this->cmd); // dangerous sink
    }
}
```

If the application has classes `A` and `B` available (autoloaded, or already `require`'d
somewhere in the codebase) you build a serialized `A` object whose `obj` property is itself a
serialized `B` object with `cmd` set to your command:

```
O:1:"A":1:{s:3:"obj";O:1:"B":1:{s:3:"cmd";s:8:"id; whoami";}}
```

- Outer object: class `A`, 1 property named `obj`.
- The *value* of `obj` is not a string — it's another full object definition (`O:1:"B":...`)
  nested directly inside. PHP deserializes nested objects recursively, which is exactly the
  mechanism that makes chaining possible: one property can itself be an arbitrarily deep object
  graph.
- Inner object: class `B`, 1 property `cmd`, value `"id; whoami"` (an OS command injection
  payload at the very end of the chain — the actual sink).

When `A` is destructed, `__destruct()` runs `$this->obj->process()`. Since `$obj` was
deserialized as a `B` instance, this calls `B::process()`, which runs `system($this->cmd)` —
and `cmd` is fully attacker-controlled. This two-class example is intentionally simplified to
show the mechanism; real POP chains in CMS/framework codebases (WordPress plugins, Laravel,
phpMyAdmin, etc.) are often 5–15 classes deep and are why tools like **PHPGGC** (PHP Generic
Gadget Chains, a ysoserial-equivalent for PHP) exist — it ships pre-built chains for many common
PHP libraries so you don't have to manually trace through every framework's source from scratch.

## 5. PHAR Deserialization — Deserialization Without `unserialize()`

A distinct and important PHP-specific technique: certain PHP filesystem functions (`file_exists`,
`is_dir`, `file_get_contents`, `fopen`, and others) will trigger deserialization **as a side
effect**, even when the code never calls `unserialize()` directly, if the path passed to them
uses the `phar://` stream wrapper pointing at a malicious `.phar` archive.

Why this matters: it turns *any* file-path-accepting function that touches attacker-influenced
paths into a deserialization sink — vastly increasing the real-world attack surface beyond
"only code that explicitly calls `unserialize()`."

Mechanism, piece by piece:

1. A `.phar` (PHP Archive) file has a **metadata section** stored in a serialized format as part
   of its file structure (this is legitimate PHP packaging functionality, not a bug in itself).
2. You craft a `.phar` file whose metadata is a serialized malicious object (using the same POP
   chain principles from Section 4).
3. You need a file with a *different* extension than `.phar` to actually get it onto the server
   in the first place — this technique is typically combined with a file upload feature that
   doesn't validate file *content*, only the extension (e.g. rename your `.phar` to `.jpg` and
   upload it as an "avatar").
4. You then trigger any vulnerable filesystem function with a `phar://` URI pointing at that
   uploaded file, e.g.:
   ```
   phar://./uploads/avatar.jpg/test.txt
   ```
   - `phar://` — tells PHP to use the Phar stream wrapper instead of treating the rest as a
     plain path.
   - `./uploads/avatar.jpg` — the path to your uploaded archive (note: still has the renamed,
     non-`.phar` extension — the wrapper doesn't care about the extension).
   - `/test.txt` — an arbitrary internal path *within* the archive; this part of the URI doesn't
     need to correspond to anything real, since the deserialization of the metadata happens as
     soon as PHP recognizes and opens the archive, before it even gets to resolving this inner
     path.
5. The moment PHP's stream wrapper opens the file as a Phar archive to resolve that URI, it
   reads and deserializes the metadata section — running your POP chain exactly as if you'd
   called `unserialize()` on it directly.

This is the basis of PortSwigger's Expert-tier *"Using PHAR deserialization to deploy a custom
gadget chain"* lab. The takeaway for real engagements: any file upload feature combined with
*any* later filesystem operation on attacker-influenced filenames is a deserialization risk,
not just an upload/path-traversal risk.

## 6. Real-World Notes

- This is overwhelmingly a **session-cookie** vulnerability pattern in practice. Always decode
  every cookie you see during recon — `O:` near the start of a Base64-decoded value is an
  instant flag.
- Frameworks built on PHP (WordPress, Drupal, Magento, Laravel, phpMyAdmin) have all had
  published CVEs in exactly this class; check disclosed CVEs and known PHPGGC chains for the
  detected framework/plugin versions before attempting to build a chain from scratch.
- Composer's `vendor/` directory (if exposed or leaked) is your gadget-hunting ground for
  custom-chain construction — it tells you exactly which libraries (and which versions) are
  present, the same role `pom.xml`/`build.gradle` plays for Java in File 04.

## 7. What's Next

File 04 moves to Java, where the magic-method concept becomes `readObject()`, and where chains
are almost always built from **third-party libraries** rather than the application's own code
— making tool-assisted exploitation (File 05, ysoserial) the dominant real-world technique.

---
*Sensitive topic note: none — this file is purely technical/educational security content.*
