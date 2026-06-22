# In-Band (Output-Visible) Command Injection

## 1. What "In-Band" Means Here

In-band command injection is the case where the result of your injected command appears directly in the HTTP response — in the page body, a downloaded file, an error message, or a response header. This is the starting point for learning the mechanics because confirmation is immediate and visual, before moving to blind/OOB techniques where confirmation requires indirect signals.

## 2. Identifying a Candidate Parameter

Look for functionality that *smells like* it shells out to an OS utility:
- Ping / traceroute / DNS lookup tools
- File conversion, image resizing, PDF generation
- "Export to..." or "Backup now" features
- Filename parameters in upload/download flows
- Any parameter whose value resembles a hostname, IP, or filename

## 3. Linux Target — Step-by-Step Payload Construction

Assume a vulnerable parameter `ip` used by a "Network diagnostics" feature that runs `ping` and displays the output.

### Payload: `; whoami`

Full injected value: `8.8.8.8; whoami`

**Breakdown:**
- `8.8.8.8` — a valid IP address. This is included so the *original* intended command (`ping 8.8.8.8`) still executes "normally" alongside your injection. This matters because if the original command throws a visible error instead of running cleanly, some applications might short-circuit and never reach your appended command, or the anomaly might tip off defenders monitoring logs.
- `;` — the Linux command separator. It tells the shell "terminate the previous command here, regardless of its exit status, and begin a new one." This is the most reliable chaining operator for in-band testing because it doesn't depend on the success/failure of the first command, unlike `&&` or `||`.
- `whoami` — the actual payload. A minimal, low-impact command used purely to *prove* code execution. It prints the username the web server process is running as (e.g., `www-data`, `apache`, `tomcat`) — valuable both as proof-of-concept and as immediate intelligence about your privilege level on the box.

**Resulting full shell command executed:**
```
ping 8.8.8.8; whoami
```
The shell runs `ping 8.8.8.8` to completion, then unconditionally runs `whoami`, and both outputs are captured by the application and (in a vulnerable app) returned in the response.

### Payload: `| id`

Full injected value: `8.8.8.8 | id`

**Breakdown:**
- `|` — the pipe operator. Strictly, this sends the *output* of `ping 8.8.8.8` into `id` as input, which `id` ignores (it doesn't read stdin for its normal operation), so practically this behaves like a chaining operator here — `id` still executes and its own output is what matters.
- `id` — prints user ID, group ID, and group memberships, e.g., `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. More detailed than `whoami` for understanding what groups you might leverage for privilege escalation later.

### Payload: backtick command substitution — `` `whoami` ``

Full injected value: `` 8.8.8.8; echo `whoami` ``

**Breakdown:**
- `echo` — prints whatever follows to stdout. Used here as a wrapper because command substitution itself doesn't print anything; something has to print the *substituted* value.
- `` `whoami` `` — the shell executes `whoami` first, captures its output, and substitutes that output as literal text into the `echo` command line before `echo` runs. So if `whoami` returns `www-data`, the shell rewrites the line to effectively `echo www-data` before execution.
- Why use this over direct chaining: command substitution is useful when the injection point is **inside another command's arguments**, not just appendable at the end — e.g., if the vulnerable code is `tar czf backup_$INPUT.tar.gz /data`, you can't simply append `; whoami` cleanly without breaking the filename syntax, but you might be able to use `` $(whoami) `` style substitution depending on context.

### Payload: `$()` substitution — `$(whoami)`

Full injected value: `8.8.8.8; echo $(whoami)`

**Breakdown:**
- `$(whoami)` — modern equivalent of backticks. The shell executes `whoami` and substitutes the result inline. Preferred over backticks in your own testing notes/scripts because it nests cleanly, e.g., `$(cat $(echo /etc/passwd))`, whereas nesting backticks requires escaping (`` `cat \`echo /etc/passwd\`` ``) and is error-prone to write by hand.

### Useful Follow-On Enumeration Commands (Linux)

Once you've confirmed execution, these are standard next steps — each broken down:

```
uname -a
```
- `uname` — prints system information.
- `-a` — "all": combines kernel name, hostname, kernel release, kernel version, machine hardware name, and OS name into one line. Used to fingerprint the exact kernel version for known privilege-escalation exploits.

```
cat /etc/passwd
```
- `cat` — concatenates and prints file contents to stdout.
- `/etc/passwd` — the system's user account database (readable by all users by default on Linux); reveals usernames, UIDs, home directories, and default shells — useful for understanding what other accounts exist on the box.

## 4. Windows Target — Step-by-Step Payload Construction

Assume the same diagnostic feature, but the backend is a Windows IIS server shelling out via `cmd.exe`.

### Payload: `& whoami`

Full injected value: `8.8.8.8 & whoami`

**Breakdown:**
- `&` — the Windows `cmd.exe` command separator equivalent to Linux `;`. Runs the second command unconditionally after the first.
- `whoami` — same purpose as on Linux: identifies the account context (e.g., `nt authority\iusr`, `nt authority\system`, or a specific service account) — immediately tells you your privilege level (an IIS app pool identity vs. SYSTEM is a massive difference in severity).

### Payload: `& dir`

Full injected value: `8.8.8.8 & dir`

**Breakdown:**
- `dir` — the Windows directory-listing command, equivalent to Linux `ls`. Confirms execution visually with a recognizable file listing in the response, useful as an unambiguous PoC for a report screenshot.

### Important Windows Caveat: No Backtick/`$()` Support in `cmd.exe`

`cmd.exe` has no native command-substitution syntax. A payload like `` `whoami` `` or `$(whoami)` will simply be treated as literal text (or cause a syntax error) on a pure `cmd.exe` backend. Don't waste time replaying Linux substitution payloads against confirmed Windows `cmd.exe` targets — go straight to `&`, `&&`, `|`, `||`.

### If the Backend Uses PowerShell Instead of `cmd.exe`

Payload: `; whoami`

Full injected value: `8.8.8.8; whoami`

**Breakdown:**
- `;` — PowerShell's statement separator (same symbol as Linux, different shell underneath, same unconditional-chaining effect).
- PowerShell *does* support `$(...)` subexpression syntax similarly to Linux: `Write-Output $(whoami)` would work. But the **backtick is PowerShell's escape character**, not command substitution — reusing a Linux-style backtick payload here will not behave as expected and is a common source of false negatives. Always confirm which shell (`cmd.exe` vs `powershell.exe`) is actually invoked before choosing your operator set.

## 5. PortSwigger Lab Mapping (Academy Progression Order)

This file corresponds to the **first lab** in PortSwigger's OS Command Injection topic:

| Order | Lab Name | What It Teaches | Relevant Technique From This File |
|---|---|---|---|
| 1 | **OS command injection, simple case** | A "store feedback / product stock check" feature directly concatenates a `productID` (or similar) parameter into a shell command, and output is reflected in the page. | Use `;`-chained `whoami` exactly as shown in Section 3 — this lab is solved with classic in-band injection. |

**Approach for this lab specifically:** Identify the vulnerable parameter (commonly `storeId` in the stock-checker feature), inject `; whoami` (or `| whoami`), and confirm the username appears in the response. The lab is solved once you successfully retrieve the output of `whoami`.

## 6. Real-World Notes

- In-band injection is rare in mature, internet-facing production apps (it's the easiest to catch in code review and via WAFs), but **very common in internal tooling, admin panels, and DevOps/CI systems** where less scrutiny is applied because "only trusted staff use this."
- A common engagement mistake: testers find one working payload (e.g., `;`) and stop, missing that `&&`/`||`/`|` chaining might reveal *additional* injection points elsewhere in the same app that filter `;` specifically but not other operators.
- Don't rely solely on `whoami`/`id` for proof-of-concept in a report if the engagement scope allows slightly more — a `uname -a` or `dir` showing real filesystem/system content makes a stronger, more convincing finding for stakeholders who aren't technical, because raw usernames alone are sometimes underestimated as "just a username."

## 7. Common Mistakes

- Forgetting to include a *valid* value for the original parameter (e.g., a real IP for `ping`) — some applications validate the original argument before ever reaching the shell, so an injection appended to garbage input never executes.
- Not URL-encoding special characters when needed for GET-based parameters, causing the payload to be mangled before it reaches the server.
- Confusing pipe (`|`) behavior — assuming it always "fails silently" if the first command produces no usable stdin for the second, when in practice the second command often still runs fine because most simple commands (`whoami`, `id`, `dir`) don't require stdin at all.

## 8. Report-Writing Notes

- Always include the **raw request and response** showing the injected command's output verbatim — this is the strongest possible evidence for a critical-severity command injection finding.
- Note the **OS and shell** identified (Linux/`sh`, Windows/`cmd.exe`, or PowerShell) since remediation guidance differs slightly in phrasing (though the root-cause fix — avoid shell invocation — is the same across all three).

---
**Previous file:** `01_Overview_and_Classification.md`
**Next file:** `03_Blind_Command_Injection.md`
