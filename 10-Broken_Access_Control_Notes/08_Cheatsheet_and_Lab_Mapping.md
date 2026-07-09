# Broken Access Control — Cheatsheet and PortSwigger Lab Mapping

## 1. Quick-Reference Payload / Technique Cheatsheet

### IDOR
| Technique | Example | Notes file |
|---|---|---|
| Sequential ID substitution | `id=1057` → `id=1058` | 02 |
| GUID reuse (harvested, not guessed) | `documents/<leaked-uuid>` | 02 |
| Static file enumeration | `/download-transcript/1.txt` … `N.txt` | 02 |
| Redirect data leakage | Read body of a `302` before following it | 02 |
| Blind/action IDOR | `POST .../4471/mark-read` as wrong user | 02 |

### Privilege Escalation
| Technique | Example | Notes file |
|---|---|---|
| Cookie role tampering | `Cookie: role=user` → `role=admin` | 03 |
| Hidden field / mass assignment | `{"email":"x","roleid":1}` on a self-update endpoint | 03 |
| Unprotected admin route | `GET /admin` with no role check | 03 |
| Unpredictable admin URL leaked via JS | `var isAdmin=false; ... '/admin-9f8a3e21'` in page source | 03 |

### Missing Function-Level Access Control
| Technique | Example | Notes file |
|---|---|---|
| URL-override header | `X-Original-URL: /admin/deleteUser` + request to `/` | 04 |
| HTTP method substitution | `GET` instead of blocked `POST` | 04 |
| Case mismatch | `/ADMIN/DELETEUSER` | 04 |
| Suffix pattern mismatch (Spring) | `/admin/deleteUser.anything` | 04 |
| Trailing slash mismatch | `/admin/deleteUser/` | 04 |

### Path Traversal (as Access Control)
| Technique | Example | Notes file |
|---|---|---|
| Simple traversal | `../../../etc/passwd` | 05 |
| Absolute path bypass | `/etc/passwd` | 05 |
| Non-recursive strip bypass | `....//....//....//etc/passwd` | 05 |
| Double URL-encode bypass | `..%252f..%252f..%252fetc/passwd` | 05 |
| Start-of-path validation bypass | `/var/www/images/../../../etc/passwd` | 05 |
| Null byte extension bypass | `../../../etc/passwd%00.png` | 05 |

### Forced Browsing / Process / Referer
| Technique | Example | Notes file |
|---|---|---|
| robots.txt / sitemap leak | `GET /robots.txt` | 06 |
| Directory brute-force | ffuf/gobuster against a wordlist | 06 |
| Skip-ahead in multi-step process | `POST .../confirm` directly, skipping steps 1–2 | 06 |
| Referer forgery | `Referer: https://target/admin` on an unrelated session | 06 |

## 2. PortSwigger Web Security Academy — Access Control Labs (Verified Correct Order)

This is the **exact sequence as published on the Academy's Access Control topic page** (`portswigger.net/web-security/access-control`), Apprentice through Practitioner. There is no Expert-rated lab in this specific topic.

| # | Difficulty | Lab Name | Primary Technique | Notes File |
|---|---|---|---|---|
| 1 | APPRENTICE | Unprotected admin functionality | No check on `/admin`, found via direct navigation | 03 / 06 |
| 2 | APPRENTICE | Unprotected admin functionality with unpredictable URL | URL leaked via JS source disclosure | 03 / 06 |
| 3 | APPRENTICE | User role controlled by request parameter | `role=` cookie/parameter tampering | 03 |
| 4 | APPRENTICE | User role can be modified in user profile | Mass assignment of `roleid` via self-update endpoint | 03 |
| 5 | APPRENTICE | User ID controlled by request parameter | Basic sequential-ID IDOR | 02 |
| 6 | APPRENTICE | User ID controlled by request parameter, with unpredictable user IDs | GUID-based IDOR, ID leaked elsewhere in the app | 02 |
| 7 | APPRENTICE | User ID controlled by request parameter with data leakage in redirect | Reading the body of a `302` before it redirects | 02 |
| 8 | APPRENTICE | User ID controlled by request parameter with password disclosure | IDOR exposing a password-reset/disclosure path, chained to vertical escalation | 02 / 03 |
| 9 | APPRENTICE | Insecure direct object references | Static file enumeration (`N.txt` transcripts) | 02 |
| 10 | PRACTITIONER | URL-based access control can be circumvented | `X-Original-URL` header bypass of front-end path matching | 04 |
| 11 | PRACTITIONER | Method-based access control can be circumvented | HTTP verb substitution (`GET` for blocked `POST`) | 04 |
| 12 | PRACTITIONER | Multi-step process with no access control on one step | Skipping directly to the action-performing final step | 06 |
| 13 | PRACTITIONER | Referer-based access control | Forged `Referer` header | 06 |

## 3. PortSwigger Web Security Academy — Path Traversal Labs (Verified Correct Order)

All six labs in this topic are rated **APPRENTICE**.

| # | Difficulty | Lab Name | Bypass Technique | Notes File |
|---|---|---|---|---|
| 1 | APPRENTICE | File path traversal, simple case | Raw `../` sequences, no filtering at all | 05 |
| 2 | APPRENTICE | File path traversal, traversal sequences blocked with absolute path bypass | Supplying an absolute path (`/etc/passwd`) instead of a relative traversal | 05 |
| 3 | APPRENTICE | File path traversal, traversal sequences stripped non-recursively | Doubled sequences (`....//`) that reconstruct `../` after a single-pass strip | 05 |
| 4 | APPRENTICE | File path traversal, traversal sequences stripped with superfluous URL-decode | Double URL-encoding (`%252f`) so the sequence reassembles after the filter runs | 05 |
| 5 | APPRENTICE | File path traversal, validation of start of path | Prefixing the required base directory before the traversal sequence | 05 |
| 6 | APPRENTICE | File path traversal, validation of file extension with null byte bypass | `%00` null byte truncation before a required `.png`/`.jpg` suffix | 05 |

## 4. Suggested Practice Order Across Both Topics

Working strictly in Academy-published order within each topic (as required), a sensible combined progression that builds from simplest to most subtle bypass logic is:

1. Complete Access Control labs 1–9 (all Apprentice) — covers unprotected functionality, parameter-based role/ID tampering, and basic IDOR end to end.
2. Complete Path Traversal labs 1–6 (all Apprentice) — covers the filesystem-level IDOR variant and every common sanitization-bypass pattern (absolute path, non-recursive strip, double-decode, prefix-only validation, null byte).
3. Return to Access Control labs 10–13 (Practitioner) — platform-layer/method bypasses, multi-step process abuse, and Referer-based control, which build directly on the function-level concepts established in lab 1–2 and file 4 of this series.

This order keeps each topic internally faithful to the Academy's own progression while sequencing Path Traversal between the Apprentice and Practitioner halves of Access Control, since its concepts (sanitization bypass, trust-boundary mismatch) directly reinforce what the Practitioner-level Access Control labs require.

## 5. Burp Suite Workflow Checklist for This Category

- [ ] Capture two low-privilege sessions (e.g. `wiener` / `carlos`) and, if available, one admin session.
- [ ] Run Autorize passively while browsing the full application as the highest-privilege account (file 7).
- [ ] For every endpoint accepting an ID, sweep with Intruder and diff responses across both low-privilege sessions (file 2).
- [ ] For every state-changing endpoint, retest with each non-default HTTP method (file 4).
- [ ] Fetch `/robots.txt` and `/sitemap.xml`, and grep all JS bundles for `admin`, `role`, `isAdmin`, `permission` (file 6).
- [ ] For any multi-step workflow, capture and replay only the final, action-performing request directly (file 6).
- [ ] Build an AuthMatrix grid for any application with 3+ distinct roles before final reporting (file 7).
- [ ] For any file-serving parameter, run all six Path Traversal bypass variants in sequence (file 05).
