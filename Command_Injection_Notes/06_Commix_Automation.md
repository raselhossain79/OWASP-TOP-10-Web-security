# Commix — Automated Command Injection Exploitation

## 1. What Commix Is

Commix ("COMmand Injection eXploiter") is the command-injection equivalent of sqlmap: an open-source automation tool that takes a target request, systematically tests it against a large library of injection techniques (in-band, blind/time-based, and various OS/shell-specific payload families), and — if successful — gives you an interactive pseudo-shell on the target. It is maintained at github.com/commixproject/commix and is standard tooling in real penetration testing engagements once manual testing (as covered in files 02–05) has confirmed or strongly suggested an injection point exists.

**Why use it after manual testing, not instead of it:** Manual testing teaches you the underlying mechanism and lets you understand exactly what's happening — which is also what lets you correctly interpret commix's results, debug when it fails, and explain findings in a report with real technical understanding rather than just pasting tool output. Commix is for *efficiency and coverage* once you already understand what it's doing under the hood.

## 2. Installation

```
git clone https://github.com/commixproject/commix.git
cd commix
python3 commix.py --help
```

**Breakdown:**
- `git clone https://github.com/commixproject/commix.git` — downloads the full source repository to your local machine.
- `cd commix` — moves into the cloned directory, since commix is run directly from source (it's a Python script, not typically installed as a system package).
- `python3 commix.py --help` — invokes the tool with Python 3 and the `--help` flag, which prints the full list of available options without running an actual scan — used here just to confirm the installation works and to see the option list directly from your installed version.

## 3. Basic Usage — Targeting a URL Parameter

```
python3 commix.py --url="http://target.com/ping?ip=8.8.8.8" --batch
```

**Breakdown:**
- `--url="..."` — specifies the target URL, including the parameter (`ip`) and a baseline valid value (`8.8.8.8`) that commix will use as the foundation for injecting payloads. Commix automatically tests every parameter present in the URL by default unless you restrict it.
- `--batch` — runs in non-interactive mode, automatically accepting commix's default answer for every yes/no prompt it would otherwise ask you during the scan (e.g., "continue testing other techniques after first success?"). Essential for unattended/scripted runs; omit this if you want to manually review each prompt during an engagement where you want full control over scan behavior.

## 4. Targeting POST Data

```
python3 commix.py --url="http://target.com/diagnostics" --data="ip=8.8.8.8&action=ping" --batch
```

**Breakdown:**
- `--data="..."` — specifies the POST body to send, in standard URL-encoded form format (`key=value&key=value`). Commix parses this string and tests each parameter within it for injection, exactly as it would with URL query parameters.
- `--batch` — same as above.

## 5. Specifying the Exact Injectable Parameter

```
python3 commix.py --url="http://target.com/diagnostics" --data="ip=8.8.8.8&action=ping" -p ip
```

**Breakdown:**
- `-p ip` — restricts testing to only the named parameter (`ip`), instead of commix's default behavior of testing every parameter in the request. Use this once you already have a strong manual hint (from your own testing in files 02–03) about exactly which parameter is vulnerable — it significantly speeds up the scan and avoids noisy/unnecessary requests against unrelated parameters, which matters for staying within engagement scope and avoiding unnecessary load on the target.

## 6. Specifying the Operating System

```
python3 commix.py --url="http://target.com/diagnostics?ip=8.8.8.8" --os=win
```

**Breakdown:**
- `--os=win` — tells commix to use Windows-specific payload syntax (`&`, `cmd.exe`-style operators, `dir`/`type` commands for verification) instead of its default Linux-oriented payload set. Use this when you've already fingerprinted the target as Windows (via response headers like `Server: Microsoft-IIS`, or via earlier manual testing) — it avoids commix wasting requests on payload families that can't possibly work against the actual target shell, directly paralleling the OS-aware payload selection covered in files 02–04.

## 7. Specifying Injection Technique

Commix supports forcing a specific technique class rather than letting it auto-detect, useful when you already know (from manual testing) which category applies:

```
python3 commix.py --url="http://target.com/diagnostics?ip=8.8.8.8" --technique=T
```

**Breakdown:**
- `--technique=T` — restricts testing to the **time-based blind** technique class specifically. Commix's technique identifiers:
  - `C` — classic/in-band (result-based, output reflected directly).
  - `T` — time-based blind (uses delay commands, conceptually identical to the `sleep`-based detection in `03_Blind_Command_Injection.md`).
  - `F` — file-based (writes output to a file and retrieves it, conceptually identical to the redirection technique in `03_Blind_Command_Injection.md` Section 5).
  - `E` — tempfile-based technique used internally for certain shell upload/retrieval scenarios.
- Forcing a single technique narrows the request volume substantially, which is good practice for staying efficient and minimizing noise on the target once you already have a manual hypothesis about which category fits.

## 8. Retrieving a Shell After Confirmed Injection

```
python3 commix.py --url="http://target.com/diagnostics?ip=8.8.8.8" --os-cmd="whoami"
```

**Breakdown:**
- `--os-cmd="whoami"` — instead of running commix's full automated detection-and-exploitation flow, this directly executes the single specified OS command against a parameter commix has already confirmed (or is confirming in the same run) as injectable, and prints the result. Useful for quick, targeted verification once you just want to run one specific command rather than drop into a full interactive shell.

For a full interactive pseudo-shell instead of single commands:

```
python3 commix.py --url="http://target.com/diagnostics?ip=8.8.8.8" --os-shell
```

**Breakdown:**
- `--os-shell` — once injection is confirmed, this drops you into an interactive prompt where you can type OS commands one after another and see their output returned through the same injection channel, without re-specifying `--os-cmd` for every single command. This is the closest commix equivalent to sqlmap's `--sql-shell`/`--os-shell` functionality, and is generally the most efficient mode for active post-exploitation enumeration during an engagement.

## 9. Reverse Shell Generation

```
python3 commix.py --url="http://target.com/diagnostics?ip=8.8.8.8" --reverse-tcp
```

**Breakdown:**
- `--reverse-tcp` — commix can automatically generate and inject a reverse shell payload, prompting you for your listener IP and port, then crafting an OS-appropriate command (e.g., a Bash `/dev/tcp` reverse shell on Linux, or a PowerShell-based reverse shell on Windows) and sending it through the confirmed injection point. This requires you to have a listener already running (e.g., `nc -lvnp <port>`) before triggering this flag — commix doesn't start a listener for you.

## 10. Filter/WAF Bypass Options in Commix

This directly extends the manual techniques in `05_Filter_WAF_Bypass.md` — commix has built-in flags that automate exactly those classes of bypass.

### `--tamper`

```
python3 commix.py --url="http://target.com/diagnostics?ip=8.8.8.8" --tamper=space2ifs
```

**Breakdown:**
- `--tamper=space2ifs` — applies a named tamper script that automatically rewrites every literal space character in generated payloads into the `${IFS}` shell-expansion equivalent covered in `05_Filter_WAF_Bypass.md` Section 3 — this is commix automating exactly that manual bypass technique. Other built-in tamper scripts include things like `base64encode` (automating the Base64-encoded payload technique from file 05 Section 4) and various character-substitution scripts targeting specific known WAF signatures.
- Multiple tamper scripts can be chained with commas, e.g. `--tamper=space2ifs,base64encode`, applying them in sequence to the generated payload.

### `--skip-waf`

**Breakdown:**
- Some commix versions include flags to actively detect known WAF fingerprints first and adjust payload strategy accordingly, rather than blindly sending the default payload set into a WAF that will simply block it outright and waste requests/risk triggering rate-limiting or IP blocking. Check `python3 commix.py --help` on your installed version for the exact current flag name, since this has been renamed/restructured across versions.

### `--random-agent`

**Breakdown:**
- Randomizes the `User-Agent` header on each request — not a payload bypass per se, but useful for evading simplistic WAF rules that fingerprint and block based on commix's (or other automated tools') default User-Agent string specifically.

## 11. Useful Auxiliary Flags

```
python3 commix.py --url="http://target.com/diagnostics?ip=8.8.8.8" --level=3 --delay=1 --timeout=10
```

**Breakdown:**
- `--level=3` — controls how thorough/aggressive the scan is, on commix's internal scale; higher levels test a larger number of payload variants and injection point locations (e.g., also testing HTTP headers like `User-Agent`, `Referer`, and cookies, not just the obvious URL/body parameters), at the cost of significantly more requests sent.
- `--delay=1` — adds a 1-second pause between each request commix sends, used to reduce load on the target and avoid tripping rate-limiting or basic DoS-detection thresholds — important in real engagements and especially in bug bounty programs with strict rate-limit rules.
- `--timeout=10` — sets the maximum time (in seconds) commix will wait for a response before considering a request timed out; relevant because time-based blind techniques (`--technique=T`) inherently involve commix waiting for delayed responses, so this needs to be set comfortably higher than your expected injected delay value to avoid false negatives from premature timeouts.

## 12. Authentication and Session Handling

```
python3 commix.py --url="http://target.com/diagnostics?ip=8.8.8.8" --cookie="session=abc123xyz"
```

**Breakdown:**
- `--cookie="..."` — attaches the specified cookie header to every request commix sends, necessary for testing injection points that sit behind authentication, exactly as you would manually set a session cookie in Burp Repeater.

## 13. PortSwigger Lab Mapping

Commix is **not used to solve PortSwigger Academy labs** — Academy labs are designed for manual technique learning, and using full automation defeats the pedagogical purpose (and several labs have constraints, like requiring Collaborator-specific OOB interaction logging, that don't map cleanly onto commix's generic automation). The correct way to use commix relative to your Academy practice is:

1. Solve the lab manually first using the techniques in files 02–05, to build real understanding.
2. Optionally, afterward, re-run commix against the same lab URL/parameter purely as a **tool-familiarization exercise** — to see how its automated detection output compares to what you already found manually, and to practice reading its output format for real engagements where manual-only testing isn't time-efficient at scale.

## 14. Real-World Notes

- Commix is most valuable in engagements with **many candidate injection points** (e.g., a large internal application with dozens of admin diagnostic forms) where manually testing every parameter individually isn't time-efficient — point it at each candidate endpoint and let it triage which ones are worth manual deep-dives.
- It is also valuable specifically for OOB and time-based techniques at scale, since manually crafting and testing every operator/encoding permutation by hand (as shown across files 02–05) is exactly the repetitive work automation tools exist to remove.
- Always validate commix's positive findings manually before including them in a report — automated tools occasionally produce false positives, particularly with timing-based techniques on infrastructure with variable latency, exactly as discussed in `03_Blind_Command_Injection.md`.

## 15. Common Mistakes

- Running commix with default settings against a heavily rate-limited or WAF-protected production target without `--delay` and without WAF-aware tamper scripts, resulting in the testing IP being blocked mid-scan.
- Treating a commix "vulnerable" result as sufficient evidence for a report without re-confirming manually and capturing the actual underlying request/response or Collaborator interaction yourself — clients and reviewing engineers generally expect manually-verified evidence, not just raw tool output, for high/critical findings.
- Forgetting `-p` to restrict scope, and letting commix test every single parameter and header at `--level=3`+ against a target where you only had permission to test a specific feature — an important scope-discipline issue in real engagements, not just an efficiency one.

## 16. Report-Writing Notes

- If commix was used as part of the testing methodology, state this explicitly in the methodology section, alongside the manual confirmation steps taken afterward — auditors and clients value transparency about tooling, and pairing automated + manual confirmation strengthens the credibility of the finding.
- Include the **exact commix command line used** in an appendix or methodology section if the report's audience is technical (e.g., another security team that will need to reproduce the finding) — this is standard practice in detailed penetration test reports, mirroring how you'd document an exact sqlmap command line for a SQLi finding.

---
**Previous file:** `05_Filter_WAF_Bypass.md`
**Next file:** `07_Cheatsheet_and_Lab_Mapping.md`
