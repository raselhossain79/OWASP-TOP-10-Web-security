# Blind Command Injection

## 1. What Makes This "Blind"

In blind command injection, your payload executes successfully on the server, but **no output is ever reflected** in the HTTP response — not in the body, not in headers, not in a downloadable file. The response might look byte-for-byte identical whether your injected command succeeded, failed, or was never reached at all. You need an indirect signal. The three standard signal types are:

1. **Time delay** — make the command take measurably longer to execute.
2. **Conditional behavior** — make a *visible* side effect of the response depend on a true/false condition you control.
3. **Out-of-band side channel** — covered separately in `04_OutOfBand_Command_Injection.md`, but mentioned here because it's the natural escalation when time-based and conditional techniques are too noisy or unreliable.

## 2. Time-Based Detection — Linux

### Payload: `; sleep 10`

Full injected value: `8.8.8.8; sleep 10`

**Breakdown:**
- `;` — unconditional command separator, as covered in the in-band file; ensures `sleep 10` runs regardless of whether `ping 8.8.8.8` succeeds.
- `sleep` — a Linux utility that does nothing except pause execution for the specified duration. Chosen specifically because it has **no side effects** other than time — it doesn't write files, doesn't touch the network, doesn't require special permissions, making it the cleanest possible "is my injection point being executed at all" probe.
- `10` — the number of seconds to pause, given as a plain integer argument to `sleep`. A value of 10 is large enough to be unambiguous against normal network jitter (typically tens to a few hundred milliseconds) but not so large that it causes the request to hit a server/proxy timeout and produce a false negative.

**Detection methodology:**
- Send a baseline request with a harmless value (e.g., just `8.8.8.8`) and record response time (e.g., ~50ms).
- Send the same request with `; sleep 10` appended and record response time.
- If the response now takes approximately 10 seconds longer, the input is being executed in a shell context — this is strong evidence of command injection even though you saw zero output.
- **Always repeat the test 2–3 times** with different delay values (e.g., `sleep 10` then `sleep 5`) to rule out coincidental network latency; a real positive will scale precisely with the value you choose.

### Payload (alternative): `; ping -c 10 127.0.0.1`

**Breakdown:**
- `ping` — sends ICMP echo requests.
- `-c 10` — "count": limits ping to exactly 10 packets instead of running indefinitely. Each packet typically takes ~1 second by default, so this produces an approximate 10-second delay.
- `127.0.0.1` — the loopback address, used so the ping doesn't depend on external network reachability from the target server, which might be firewalled — `sleep` is generally preferred over `ping` for this exact reason (fewer environmental dependencies), but `ping` is a useful alternative if `sleep` itself happens to be filtered or unavailable on a minimal container image.

## 3. Time-Based Detection — Windows

### Payload (cmd.exe): `& timeout /t 10`

Full injected value: `8.8.8.8 & timeout /t 10`

**Breakdown:**
- `&` — Windows command separator (unconditional chaining), equivalent role to Linux `;`.
- `timeout` — a built-in Windows command that pauses script/command execution.
- `/t 10` — specifies the wait duration in seconds. The `/t` switch is required syntax for `timeout` to accept a numeric duration argument.

**Caveat:** `timeout` requires an attached console/input handle in some older Windows versions and can fail silently in certain non-interactive contexts (e.g., some IIS worker process configurations). If `timeout` doesn't produce a reliable delay, fall back to:

### Payload (cmd.exe alternative): `& ping -n 10 127.0.0.1`

**Breakdown:**
- `ping -n 10 127.0.0.1` — Windows `ping` uses `-n` (not `-c` like Linux) to specify packet count. `127.0.0.1` again avoids dependency on outbound network reachability.

## 4. Conditional (Boolean) Detection

Used when you want to confirm not just "does code execute" but **answer a yes/no question** about the system (e.g., "does this file exist," "is this the right OS," "does this command produce output longer than X") purely from a behavioral difference in the response — without OOB infrastructure.

### Technique: Conditional Delay

Payload (true branch): `; ping -c 1 127.0.0.1 && sleep 10`

Full example testing "does `/etc/shadow` exist and is it readable by us" (a precondition often relevant for privesc planning):

```
; [ -r /etc/shadow ] && sleep 10
```

**Breakdown:**
- `[ -r /etc/shadow ]` — POSIX test syntax. `-r` checks whether the file at the given path exists **and** is readable by the current user; the test command returns exit status 0 (true/success) if so, non-zero (false) otherwise.
- `&&` — runs the following command **only if** the test returned success (exit 0). This is the crucial operator for conditional logic — unlike `;`, it makes execution of the second command depend on the first.
- `sleep 10` — the observable signal: if the response is delayed ~10 seconds, the condition was true (the file exists and is readable by the web server user); if the response returns immediately, the condition was false.

This single primitive — "wrap a test in `[ ... ] && sleep N`" — is the building block for extracting arbitrary boolean facts about the filesystem, environment variables, or command output one bit at a time, conceptually similar to blind boolean-based SQL injection but operating on the OS instead of the database.

### Technique: Conditional Output via Application Behavior

If the application's *visible* behavior differs based on command success/failure even without printing output directly (e.g., it shows a generic "Error" page if the underlying shell command returns non-zero, versus a normal page if it returns zero), you can use:

Payload: `; test -f /etc/passwd`

**Breakdown:**
- `test -f /etc/passwd` — `test` (same as `[ ... ]` syntax) with `-f` checking for existence of a *regular file* at the path. Exit code 0 if it exists.
- No explicit success/failure command needed here — you're relying on the **application's own error-handling behavior** changing based on the exit code of the *whole* chained command, which is a more fragile signal than the explicit `sleep` technique above, but worth knowing because some applications behave this way and it requires zero extra payload complexity.

## 5. File-Write/Read Detection (When Time-Based Signals Are Unreliable)

If response timing is too noisy (e.g., heavily load-balanced infrastructure, async job queues with unpredictable processing time), an alternative confirmation method:

Payload: `; echo vulnerable_test_123 > /var/www/html/proof.txt`

**Breakdown:**
- `echo vulnerable_test_123` — prints a unique, identifiable string. Using a unique string (not something generic like "test") avoids false positives from pre-existing files.
- `>` — shell redirection operator; instead of printing to stdout, it writes the output to the specified file, **overwriting** that file if it exists (use `>>` instead to append without overwriting, which is safer against accidentally destroying a legitimate file).
- `/var/www/html/proof.txt` — a path inside the web root, chosen specifically because files here are typically served statically by the web server — meaning after this command runs, you can simply browse to `https://target/proof.txt` to retrieve and confirm execution, entirely independent of the original injection response.

**Caveat:** Requires you to know (or guess) the web root path, and requires write permission for the web server user on that directory — not always the case, especially on hardened production servers. State this assumption clearly in a report if used.

## 6. PortSwigger Lab Mapping (Academy Progression Order)

| Order | Lab Name | What It Teaches | Relevant Technique From This File |
|---|---|---|---|
| 2 | **Blind OS command injection with time delays** | Injection point produces no output at all; you must infer execution purely from response time. | Section 2 — `; sleep 10` time-based detection. This is the canonical lab for this exact technique. |
| 3 | **Blind OS command injection with output redirection** | You can write output to a file the application later serves statically (commonly via a "Submit feedback" form that triggers a backend script, with a writable directory revealed in the lab description). | Section 5 — redirect command output to a web-accessible file with `>`, then retrieve it via a normal GET request. |
| 4 | **Blind OS command injection with out-of-band interaction** | No timing signal is reliable (fully async backend); requires triggering an outbound DNS/HTTP request to Burp Collaborator. | This lab is the bridge to `04_OutOfBand_Command_Injection.md` — covered fully there, but conceptually it's the next escalation after this file's techniques fail. |

**Important Academy-specific note:** In the "output redirection" lab, the actual exfiltration technique used is to run `whoami` and redirect its output into a file inside the image-serving directory (e.g., `/var/www/images/`), then request that file directly — combining this file's Section 5 technique with knowledge of the lab's specific writable path, which the lab description provides.

## 7. Real-World Notes

- Blind command injection is the **most common form encountered in real engagements** — modern frameworks rarely echo raw command output to users, so if injection exists at all, it's usually blind by default. Testers who only know in-band techniques will systematically under-report findings.
- Time-based detection is noisy on production infrastructure with load balancers, caching layers, or WAFs that introduce their own variable latency — always run a baseline comparison and repeat tests before reporting a positive.
- In bug bounty programs specifically, **be conservative with delay values** (don't use `sleep 60` as a first probe) — aggressive blind testing can resemble a denial-of-service pattern and some programs explicitly prohibit large delays; check program rules before testing.

## 8. Common Mistakes

- Using only a single timing test and treating it as conclusive — network jitter, server load, or a coincidentally slow request can produce false positives; always test multiple delay values and compare against a clean baseline.
- Forgetting that `&&`-based conditional payloads silently fail to fire if the *first* part of your injected chain (e.g., the original `ping` command) itself fails — always confirm chaining behavior in a controlled lab environment first.
- Choosing a file-write path without web-root knowledge, then concluding "not vulnerable" when the write succeeded but you simply guessed the wrong public path for retrieval.

## 9. Report-Writing Notes

- For time-based findings, include **the actual timestamps/timings from repeated tests** in the report (e.g., "baseline: 4 requests averaging 48ms; payload requests averaging 10,052ms across 4 repetitions") — raw repeated evidence is far more convincing than a single screenshot, and directly preempts a "could this be jitter?" question from a reviewing engineer.
- For file-write-based findings, document the exact path written to and retrieved from, and note explicitly that this required write access to a specific directory — this is useful context for remediation prioritization (a writable web root is itself a secondary finding worth flagging).

---
**Previous file:** `02_InBand_Command_Injection.md`
**Next file:** `04_OutOfBand_Command_Injection.md`
