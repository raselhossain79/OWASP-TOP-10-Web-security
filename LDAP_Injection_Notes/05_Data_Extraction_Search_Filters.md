# Data Extraction via LDAP Search Filters

**Prerequisite**: files 02–04. This file covers the scenario where the application **does** reflect search results to you (a staff directory, address book, or admin lookup tool) — your goal shifts from "infer one bit at a time" to "abuse filter logic and wildcards to pull more data than the feature was designed to expose."

## 1. The Baseline Feature and Its Intended Restriction

A typical "find a colleague" feature builds a filter like:

```
(&(objectClass=person)(department=Sales)(cn=*INPUT*))
```

— intended to let a Sales employee search only within their own department, by name substring. The developer's mental model: "users can only search names within their own department." Your job: prove that restriction is enforceable only at the string level, not the directory level.

## 2. Wildcard Abuse — Pulling Every Entry Regardless of Intended Scope

**Payload, name search field**: `*)(department=*`

**Resulting filter**:
```
(&(objectClass=person)(department=Sales)(cn=*)(department=*))
```

Wait — walk through it carefully, because the placement matters. The actual injected fragment closes the `cn=*INPUT*` term early:

**Payload**: `*))(|(cn=*`

**Resulting filter**:
```
(&(objectClass=person)(department=Sales)(cn=*))(|(cn=*)(...trailing...))
```

Breakdown:
| Fragment | Effect |
|---|---|
| `*` | Satisfies the wildcard name match trivially |
| `))` | Closes both the `cn=*` term AND the outer `&` group — the department restriction is now "locked in" as already-evaluated and complete |
| `(\|(cn=*` | Opens a brand-new OR group, sibling to the AND group, with its own always-true presence test on `cn` — which every person entry has |

The net effect: the search returns the union of "Sales department people matching the name" (the original restricted intent) **plus** "literally everyone with a `cn` attribute" (your injected group) — i.e., the entire directory, regardless of department. This is the LDAP equivalent of a UNION-based SQLi data dump: you're not breaking the original query, you're appending an unrestricted sibling query that the server ORs in.

## 3. Attribute Enumeration — Discovering What's There Before Asking For It

Real directories have dozens of attributes per entry, many undocumented from the outside (`employeeID`, `homeDirectory`, `description`, `extensionAttributeN`, custom Active Directory schema extensions). You typically don't know attribute names in advance. Two practical approaches:

**Approach A — known-attribute wordlist.** Use a standard LDAP/AD attribute list (`cn`, `sn`, `givenName`, `mail`, `telephoneNumber`, `title`, `department`, `manager`, `memberOf`, `description`, `employeeID`, `userPrincipalName`, `sAMAccountName`, `homeDirectory`, `userPassword`/`unicodePwd`) and probe each with a presence filter injected into the search term:

```
*)(employeeID=*
```
If the response set or behavior changes (more results, different result), the attribute exists on at least some entries and is searchable through this injection point.

**Approach B — schema enumeration via root DSE / schema subentry**, *if you have any direct LDAP protocol access* (not just through the web app) — querying `cn=schema` or the root DSE can return the directory's full attribute schema directly. This is a separate, protocol-level reconnaissance step (using `ldapsearch` with valid or anonymous bind), not a web-injection technique, but it's standard practice on internal engagements to pull the schema first so your web-layer injection payloads target attributes you already know exist, rather than guessing blind.

## 4. Extracting Specific Attribute Values Through a Reflected Search

Once an attribute is confirmed to exist, and assuming the search feature reflects whatever attribute(s) it's configured to display (commonly just `cn`/name, sometimes `mail` or `title`), the real extraction value comes from **forcing the directory to return entries you weren't supposed to see**, combined with **whatever fields the UI happens to render** — you're not choosing which attributes get displayed (that's fixed by the app's template), you're choosing which *entries* get included in what's displayed.

If the feature lets you pivot to view "full profile" for any returned entry (a common UX pattern — search results are clickable), the injection in section 2 effectively becomes **unauthorized access to every employee's full directory profile**, not just a same-department colleague's. This is usually the actual, reportable impact: not "I can read raw LDAP filter syntax" but "I can view full HR/AD profile data — phone numbers, manager chains, employee IDs, internal usernames — for the entire organization, including users in departments I should have zero visibility into."

## 5. `memberOf` / Group-Membership Pivoting (AD-Specific, High Real-World Value)

Active Directory entries carry a `memberOf` attribute listing group DNs. If your injection lets you search/filter by `memberOf`, you can answer questions like "who is in the Domain Admins group" directly through the web app's search feature:

```
*)(memberOf=*Domain Admins*
```
This combines a substring match (`*Domain Admins*`) with the structural closing/reopening from section 2. **This is one of the highest-value real-world outcomes of LDAP injection on an AD-backed search feature** — it turns an innocuous "find a colleague" box into a privileged-group enumeration tool, directly useful for your AD pentesting / attack-path-mapping work (the same kind of intel BloodHound collects, but surfaced through a totally unrelated web vulnerability).

## 6. PortSwigger Academy Lab Mapping

**No PortSwigger Academy lab exists for LDAP data extraction / UNION-style filter abuse** — see file 01, section 6. Unlike SQLi's clear Apprentice (basic UNION) → Practitioner (blind UNION, error-based) → Expert progression, there's no equivalent ladder here.

**Practice alternatives**:
- **OWASP WebGoat → LDAP Injection lesson** — its later steps (after the login-bypass step covered in file 03) typically move into search/filter manipulation for data exposure, the closest available structured equivalent.
- **Self-hosted OpenLDAP lab**, extended from files 03/04's setup: seed multiple departments and a few group memberships, then test the section 2 and section 5 payloads against your own directory and confirm the returned result set in `ldapsearch` matches what your injected web filter produced — this closes the loop between "what I sent" and "what the directory actually matched," which is the best way to build real intuition for this filter grammar.

## 7. Real-World Note

On real engagements, this technique class is most often discovered through **a low-effort, easily dismissed-looking internal tool** — a staff lookup widget, a "find IT contact" box on an intranet homepage — that nobody threat-modeled because it "just searches names." Always test these. The combination of weak input validation + a feature that's directly wired to Active Directory is common precisely because these tools are treated as low-risk internal conveniences rather than authentication-adjacent attack surface.
