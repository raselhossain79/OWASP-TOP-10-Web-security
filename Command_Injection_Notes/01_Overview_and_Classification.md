# OS Command Injection — Overview and Classification

## 1. What OS Command Injection Is

OS Command Injection (also called shell injection) occurs when an application takes user-supplied input and passes it — directly or with insufficient sanitization — into a function that executes operating system commands. The application's intent is usually benign: ping a host the user entered, convert a file the user uploaded, look up a DNS record, run a backup script with a filename parameter. The vulnerability exists because the application concatenates untrusted input into a command string that is handed to a shell interpreter (`/bin/sh`, `cmd.exe`, `powershell.exe`), instead of passing arguments directly to the target program without shell involvement.

This is OWASP Top 10 category **A03:2021 – Injection**, alongside SQL injection, but the impact ceiling is different: SQL injection compromises a database; OS command injection compromises the **host operating system** itself — file system, processes, network access, and often a path to full server compromise or internal network pivoting.

### Why It Happens (Root Cause)

In server-side code, there are two fundamentally different ways to run an external program:

1. **Shell-mediated execution** — the application builds a single string (e.g. `"ping " + userInput`) and hands it to a shell to parse and execute. Examples: PHP `shell_exec()`, `system()`, `exec()`, `passthru()`; Python `os.system()`, `subprocess.run(cmd, shell=True)`; Node.js `child_process.exec()`; Java `Runtime.exec("sh -c " + input)`.
2. **Direct process execution (no shell)** — the application passes the program name and an argument array directly to the OS, bypassing shell parsing entirely. Examples: Python `subprocess.run([prog, arg1, arg2], shell=False)`; Node.js `child_process.execFile()` or `spawn()` with an args array; Java `ProcessBuilder` with a `List<String>`.

Command injection is only possible in mode 1. The shell is what interprets `;`, `|`, `&&`, backticks, etc. as control operators rather than literal text. If the application never invokes a shell, there is no metacharacter for an attacker to exploit — this is also the primary remediation, not just an exploitation note.

## 2. Shell Metacharacters — The Attack Surface

These characters are reserved by shell interpreters to chain, pipe, or substitute commands. An attacker injects them into a vulnerable parameter to break out of the intended single command and run an arbitrary additional one.

### Linux / Unix Shells (`sh`, `bash`)

| Operator | Name | Behavior |
|---|---|---|
| `;` | Command separator | Runs the second command regardless of whether the first succeeded or failed. Most reliable for in-band injection when output is shown. |
| `\|` | Pipe | Sends the *output* of the first command as input to the second. Useful when you want to filter/process output, less useful for pure injection unless the original command produces something pipeable. |
| `&&` | AND | Runs the second command **only if** the first command exits with status 0 (success). Useful to confirm a precondition before running a payload. |
| `\|\|` | OR | Runs the second command **only if** the first command fails (non-zero exit). Useful when the original command is expected to fail (e.g., pinging an invalid host) so your payload still fires. |
| `` ` `` (backticks) | Command substitution (legacy) | The shell executes the enclosed command first and substitutes its output into the surrounding command line. e.g. `echo \`whoami\`` runs `whoami` and prints the result. |
| `$()` | Command substitution (modern) | Functionally identical to backticks but supports nesting and is generally preferred in modern shell scripting. e.g. `echo $(whoami)`. |
| `&` | Background operator | Runs the preceding command asynchronously in the background, then immediately proceeds to the next. Sometimes used so the *original* intended command output still returns to the user while your payload runs invisibly. |
| `\n` (newline) | Line separator | If input lands inside a script being interpreted line-by-line, a literal newline can act like `;`. |

### Windows (`cmd.exe`)

| Operator | Name | Behavior |
|---|---|---|
| `&` | Command separator | Runs the second command regardless of the first's exit code — the Windows equivalent of Linux `;`. |
| `&&` | AND | Same semantics as Linux: second command runs only if the first succeeds. |
| `\|\|` | OR | Second command runs only if the first fails. |
| `\|` | Pipe | Same piping behavior as Linux. |
| No backtick/`$()` equivalent in `cmd.exe` | — | `cmd.exe` has no native command-substitution syntax. This is a key practical difference: many Linux payloads (`$(whoami)`) simply will not work against a Windows target running `cmd.exe`. |

### PowerShell (when the backend shells out to `powershell.exe`)

| Operator | Name | Behavior |
|---|---|---|
| `;` | Statement separator | Same as Linux `;` — always runs the next statement. |
| `\|` | Pipe | Passes objects (not just text) down the pipeline. |
| `$()` | Subexpression | PowerShell *does* support `$(...)` substitution, similar in spirit to Linux. |
| `` ` `` (backtick) | Escape character (NOT substitution) | Critical distinction: in PowerShell the backtick is the **escape** character, not command substitution. Using a Linux-style backtick payload against a PowerShell backend will not behave like it does on Linux — this is a common mistake testers make when blindly reusing Linux payloads. |

**Real-world note:** Always fingerprint the OS and shell before committing to a payload family. A Windows IIS/.NET app calling `cmd.exe /c` needs `&`-style chaining; the same app calling out to a bundled PowerShell script needs PowerShell-aware syntax. Throwing Linux backtick payloads at a Windows target and concluding "not vulnerable" is a common false negative in real engagements.

## 3. The Three Sub-Types of Command Injection

### 3.1 In-Band (Classic / Visible Output)

The result of the injected command is reflected directly in the HTTP response. This is the easiest to detect and exploit because confirmation is immediate — you see `uid=33(www-data) gid=33(www-data)` or a directory listing right in the page.

### 3.2 Blind Command Injection (No Output Shown)

The application executes your injected command but never reflects its output anywhere in the response. The response might be identical (same status code, same body, same timing on the surface) whether or not your payload worked. You must use indirect, out-of-band-from-output techniques such as:
- **Time-based detection** — inject a `sleep N` / `ping -c N` and measure response delay.
- **Conditional/boolean detection** — make a command's side effect depend on a condition and observe a behavioral difference (e.g., different HTTP status, different response length).
- **File-write detection** — write a file to a location the application later serves statically, then request that file.

Covered in depth in `03_Blind_Command_Injection.md`.

### 3.3 Out-of-Band (OOB) Command Injection

Neither the HTTP response nor local timing is used. Instead, the injected command causes the **target server itself** to initiate an outbound connection (DNS lookup or HTTP request) to an attacker-controlled listener, which captures both confirmation and (if crafted correctly) exfiltrated data. This is the technique of choice when:
- The application is fully blind (no timing signal either, e.g., heavily asynchronous processing).
- You want to exfiltrate command output without relying on response-length inference, which is slow and error-prone.

Covered in depth in `04_OutOfBand_Command_Injection.md`.

## 4. How This Shows Up in Real Engagements

- **File conversion / image processing services** that shell out to ImageMagick, FFmpeg, or Pandoc with user-controlled filenames are a classic source — filenames or metadata fields get concatenated into a shell command.
- **Network diagnostic features** (ping, traceroute, DNS lookup tools built into admin panels) are extremely common in internal/admin interfaces and are frequently overlooked because "it's just for IT staff."
- **Legacy PHP applications** using `system()`/`exec()`/`shell_exec()` for things like PDF generation, email sending via `sendmail`, or backup scripts triggered from a web form.
- **CI/CD and DevOps tooling** that takes branch names, commit messages, or webhook payloads and passes them into shell scripts — a high-value target because these run with build-server privileges.
- **IoT/embedded device web UIs** which very frequently shell out to busybox utilities for configuration tasks (Wi-Fi setup, firmware update triggers).

## 5. Common Mistakes (Both as a Tester and as a Developer)

- **Tester mistake:** Assuming a blacklist filter (blocking `;` for example) means the parameter is safe, without testing alternative operators (`|`, `&&`, newline, backticks) or encoding bypasses.
- **Tester mistake:** Using only Linux-style payloads against a target that later turns out to be Windows-based, concluding "not vulnerable" prematurely.
- **Developer mistake (root cause):** Believing that escaping or blacklisting specific characters is sufficient, instead of avoiding shell invocation entirely via parameterized/direct process execution (`subprocess.run([...], shell=False)`, `ProcessBuilder` with a list, etc.).
- **Developer mistake:** Validating input only for *expected format* (e.g., checking it "looks like" an IP address with a weak regex) rather than using a strict allowlist combined with no shell invocation.

## 6. Report-Writing Considerations

When documenting a finding:
- Always state explicitly **which sub-type** was confirmed (in-band, blind, or OOB) and **why** — e.g., "Output was not reflected in the response; injection was confirmed via a 10-second response time delta when injecting `sleep 10`, consistent across 5 repeated requests to rule out network jitter."
- Include the **exact vulnerable parameter, HTTP method, and full request** (sanitized of any session tokens if shared externally).
- State the **underlying execution context** if determinable (e.g., "the parameter is passed to PHP's `shell_exec()` based on response behavior consistent with `/bin/sh` metacharacter handling").
- Always include **remediation guidance that addresses root cause** — i.e., recommend avoiding shell invocation entirely (parameterized exec, allowlist validation), not just "filter semicolons," since blacklist fixes are routinely bypassed and auditors will flag a recommendation that only addresses the PoC payload rather than the vulnerability class.

## 7. PortSwigger Mapping for This File

This overview file maps conceptually to the **introductory material** PortSwigger provides before Lab 1 (OS command injection, simple case) in the **OS command injection** topic. No lab is attempted from this file alone — proceed to `02_InBand_Command_Injection.md` for Lab 1.

---
**Next file:** `02_InBand_Command_Injection.md`
