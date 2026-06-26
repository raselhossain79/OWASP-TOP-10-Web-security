# Insecure Deserialization — Pentester Reference Series

A complete, GitHub-ready reference on Insecure Deserialization vulnerabilities, mapped under
**OWASP A08:2021 — Software and Data Integrity Failures**, treated as its own dedicated
vulnerability class due to its distinct exploitation mechanics, tooling, and per-language depth.

This series follows the same standard as the SQL Injection, XSS, OS Command Injection, NoSQL
Injection, SSTI, XXE, and LDAP Injection note sets: every payload and tool command is broken
down piece by piece, every technique is tied to real-world engagement framing, and every
PortSwigger Web Security Academy lab is mapped in its correct Apprentice → Practitioner →
Expert difficulty sequence — not grouped by theme.

## File Index

| # | File | Covers |
|---|------|--------|
| 01 | [Overview-and-Classification.md](01-Overview-and-Classification.md) | What deserialization is, why it's dangerous, OWASP mapping, source/sink/gadget vocabulary, detection methodology |
| 02 | [Gadget-Chain-Concepts.md](02-Gadget-Chain-Concepts.md) | The universal theory behind gadget chains — magic methods, POP chains, sinks — independent of language |
| 03 | [PHP-Object-Injection.md](03-PHP-Object-Injection.md) | PHP serialization format, magic methods, POP chain construction, type juggling, PHAR deserialization |
| 04 | [Java-Deserialization-Gadget-Chains.md](04-Java-Deserialization-Gadget-Chains.md) | Java native serialization internals, `ObjectInputStream`/`readObject`, known vulnerable libraries |
| 05 | [ysoserial-Tool-Usage.md](05-ysoserial-Tool-Usage.md) | Full breakdown of ysoserial — every flag, every payload class, Java 16+ module workaround explained |
| 06 | [Python-Pickle-Deserialization.md](06-Python-Pickle-Deserialization.md) | Pickle opcodes, `__reduce__`, manual payload crafting, tool-assisted exploitation |
| 07 | [DotNet-Deserialization.md](07-DotNet-Deserialization.md) | BinaryFormatter, ViewState, JSON.NET `TypeNameHandling`, ysoserial.net usage |
| 08 | [Detection-and-WAF-Filter-Evasion.md](08-Detection-and-WAF-Filter-Evasion.md) | Blacklist/signature bypass techniques across PHP, Java, Python, .NET |
| 09 | [Cheatsheet-and-PortSwigger-Lab-Mapping.md](09-Cheatsheet-and-PortSwigger-Lab-Mapping.md) | Quick-reference cheatsheet + all 10 official Academy labs in correct difficulty order |

## How to Use This Series

- Read files **01 → 02** first. Gadget chain theory (02) is language-agnostic and is assumed
  knowledge in every per-language file that follows.
- Files **03–07** are per-language exploitation. Read them in this order if you want to follow
  the Academy's own progression (PHP and Java appear in the labs; Python and .NET are
  industry-standard extensions not present in the Academy — this is called out explicitly in
  file 09 so the lab mapping is never misrepresented).
- File **09** is your lab-day quick reference — keep it open in a second tab while practicing.

## Scope Note

PortSwigger Web Security Academy's Insecure Deserialization topic covers **PHP, Java, and
Ruby** only (10 labs total, confirmed against the live Academy lab list). This series adds
**Python and .NET** because both are extremely common in real engagements — Python via web
backends, ML/data pipelines, and CI tooling; .NET via enterprise web apps and ViewState. These
two language sections are explicitly marked as **non-Academy / real-world extension** content
so there's no confusion about what you can practice on PortSwigger versus what you need to
practice in your own lab (Docker containers, local VMs, etc.).

## Standing Rule

All notes, cheat sheets, and reference documents in this repository are written in full English
only. No Bangla or Banglish text appears anywhere in the written content.
