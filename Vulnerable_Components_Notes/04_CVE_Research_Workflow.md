# 04 — CVE Research Workflow: NVD, Exploit-DB, Supply Chain, and Responsible Verification

This file is the bridge between "I found a version number" (File 02/03) and
"I can write a defensible finding" (File 06). Treat it as a checklist you run
every single time a concrete software/version is identified.

## 1. Reading a CVE correctly

A CVE ID (e.g. `CVE-2017-9805`) is just an **identifier** for a specific
publicly disclosed vulnerability — it carries no severity or exploitability
information by itself. You always need to pull the actual record.

Key fields to extract from any CVE record:

- **Description** — what the flaw actually is (e.g. "OGNL injection in the
  REST plugin allows remote code execution").
- **CVSS score and vector string** — the standardized severity score (0–10)
  plus the vector string that explains *why* (e.g.
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` for CVSS v3). Always read the vector,
  not just the headline number — two CVEs can both score "9.8 Critical" for
  very different reasons (one needs no auth, one needs a low-privilege
  account first), which matters for how you describe real-world risk to the
  client.
- **Affected version range** — the exact range of versions impacted (e.g.
  "Struts 2.3.5 before 2.3.31, Struts 2.5 before 2.5.10"). This is the single
  most important field — it's what you compare your fingerprinted version
  against.
- **References** — links to the vendor advisory, patch commit, and any public
  write-ups or exploit code.

## 2. Using NVD (National Vulnerability Database) effectively

NVD (nvd.nist.gov) is the canonical, authoritative source for CVE records,
CVSS scoring, and CPE (Common Platform Enumeration) mappings.

### Searching NVD

The web UI search supports filtering by keyword, CVE ID, CPE, publish date
range, and CVSS severity. For a pentest workflow:

1. Search by **product + version** keyword first (e.g. `apache struts 2.3.31`).
2. If too many/no results, search by **CPE** instead — CPE strings follow a
   structured format like `cpe:2.3:a:apache:struts:2.3.31:*:*:*:*:*:*:*`
   (vendor:product:version), which gives precise, unambiguous matching versus
   free-text keyword search.
3. Cross-check the **"Known Affected Software Configurations"** section on
   the CVE detail page — this lists the exact CPE version ranges NVD has
   confirmed as affected, which is more reliable than trusting a blog post's
   summary of the same CVE.

### Using the NVD API (for scripted/bulk workflows)

```bash
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:apache:struts:2.3.31:*:*:*:*:*:*:*" -H "apiKey: $NVD_API_KEY"
```

Breakdown:

- `curl -s` — `-s` (silent) suppresses curl's progress meter so only the JSON
  response is printed/captured.
- `"https://services.nvd.nist.gov/rest/json/cves/2.0?..."` — the NVD REST API
  v2.0 endpoint for CVE lookups.
- `cpeName=cpe:2.3:...` — the query parameter that filters results to CVEs
  whose affected-configuration list matches this specific CPE string. This is
  the scripted equivalent of the manual CPE search described above.
- `-H "apiKey: $NVD_API_KEY"` — passes your NVD API key in the request header.
  **Get a free key** by registering at the NVD API key request page —
  without one, you're limited to roughly 5 requests per 30 seconds (vs. 50
  per 30 seconds with a key), which matters when scripting lookups across a
  large number of fingerprinted components on a bigger engagement.

## 3. Using Exploit-DB effectively

Exploit-DB (exploit-db.com, mirrored offline via `searchsploit`) catalogs
public proof-of-concept and weaponized exploit code. It answers a different
question than NVD: not "is this theoretically vulnerable" but "does a
working public exploit already exist."

### Using searchsploit (offline Exploit-DB mirror, ships with Kali/Parrot)

```bash
searchsploit "Apache Struts" 2.3.31
```

Breakdown:

- `searchsploit` — invokes the offline Exploit-DB search tool.
- `"Apache Struts"` — the quoted product name term to search for.
- `2.3.31` — an additional term narrowing results to that specific version;
  searchsploit does simple substring/term matching across exploit titles, so
  combining product name and version narrows the result list considerably.

Other flags worth knowing:

- `-m <EDB-ID>` — **mirrors** (copies) a specific exploit by its Exploit-DB ID
  into your current directory, so you can read/review the full PoC code
  before deciding whether to use it.
- `-x <EDB-ID>` — examines an exploit's source/PoC content directly in the
  terminal without copying the file, useful for quickly checking what a PoC
  actually does before running anything.
- `-w` — shows the original Exploit-DB website URL for each result instead of
  the local path, useful for citing the source in a report.
- `--update` — updates the local searchsploit database; run this regularly
  since the offline copy can lag behind exploit-db.com by hours to days.

### Reading and vetting an exploit before use

**Never run an Exploit-DB PoC against a client target without reading it
first.** This is a standard, non-negotiable step in professional practice:

1. Read the full PoC source/script — confirm what it actually does (e.g. does
   it just print a version confirmation, or does it drop a webshell, modify
   files, or crash the service?).
2. Check the **submission date** against the **patch date** in the vendor
   advisory — a PoC submitted before a patch may not work against a backported
   fix even if the version number looks unpatched on paper.
3. Test destructive/unstable PoCs in a local lab replica (e.g. spin up the
   same vulnerable version in a Docker container) before ever pointing one at
   a live client asset, if the RoE permits exploitation at all.
4. If a PoC requires modification (e.g. updating a target URL/callback
   address), document exactly what you changed for your own audit trail.

## 4. Supply chain risk basics (pentester-scoped)

You don't need to build an SBOM pipeline to reason usefully about supply
chain risk during an engagement. The practical questions to ask:

- **Is this a direct or transitive dependency?** A transitive dependency
  (a dependency of a dependency, like Log4j being pulled in by some other
  library the dev team chose directly) is risk the organization inherited
  without a direct decision — flag this distinction in reports, since the
  remediation owner and urgency framing differ (it's often harder/slower for
  a team to patch something they didn't directly choose to include).
- **Is the upstream project still maintained?** Check the project's repo for
  recent commits/releases. An abandoned library with a known CVE and no
  maintainer to ever patch it is a *worse* long-term risk than an actively
  maintained one with the same CVE, because there's no patch coming — the only
  fix is migration to an alternative.
- **Was this pulled from an official registry or a third-party mirror/CDN?**
  Components loaded from unofficial sources carry additional integrity risk
  (the artifact itself could be tampered with) beyond just "is this version
  vulnerable" — this is the same risk class as real-world incidents like
  compromised npm/PyPI packages.
- **Pin vs. floating versions:** If you have build-config access, check
  whether dependency versions are pinned to exact versions or allowed to
  float (e.g. `^1.2.3` in `package.json`, which permits automatic minor/patch
  upgrades). Floating versions reduce the "stale dependency" risk but
  introduce a different risk: an unreviewed automatic update could silently
  pull in a malicious or broken release — this is exactly the failure mode
  behind several real npm supply-chain compromise incidents.

This is intentionally a lighter-weight checklist than a full SCA/SBOM program
— it's meant to let you flag supply-chain-flavored risk intelligently inside
a normal pentest report, not to replace dedicated supply-chain security
tooling.

## 5. Putting it together — the actual workflow

For every fingerprinted component + version from Files 02/03:

1. **NVD lookup** by product + version (or CPE) → get the CVE list, CVSS
   scores, and confirmed affected-version ranges.
2. **Filter** to CVEs whose affected range actually includes your confirmed
   version — don't report a CVE just because the product name matches if the
   version is outside the affected range.
3. **Exploit-DB / searchsploit lookup** for each remaining CVE → determine if
   a public PoC exists, which raises real-world urgency (public exploit =
   lower bar for any attacker, not just a skilled one).
4. **Vendor advisory check** → confirm the exact patched version and whether
   any compensating controls (config changes, feature flags) are documented
   as mitigations if patching isn't immediately possible.
5. **Verify, don't assume** → apply the responsible verification steps from
   File 01 §3 Phase 4 before finalizing the finding.
6. **Write the finding** with: component, confirmed version, CVE(s), CVSS,
   exploit availability, and concrete remediation — feeding directly into
   File 06's checklist.
