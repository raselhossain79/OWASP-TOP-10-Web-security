# A08:2021 — Software and Data Integrity Failures: Overview and Classification

## 1. What this category actually covers

OWASP introduced A08:2021 as a new category in the 2021 Top 10 revision. It groups
together a set of vulnerabilities that share one root cause: **something downstream
trusted something upstream without verifying it was genuine and unmodified.**

That "something" can be:

- A software update (the client trusts the update server).
- A third-party package (the build trusts the package registry).
- A CI/CD pipeline step (the pipeline trusts the code/config it pulls and executes).
- A browser loading a script (the page trusts a CDN to serve the file it asked for).
- A serialized object (the application trusts that the byte stream wasn't tampered with).

Official OWASP mapping folds in CWE-345 (Insufficient Verification of Data
Authenticity), CWE-353 (Missing Support for Integrity Check), CWE-426 (Untrusted
Search Path), CWE-494 (Download of Code Without Integrity Check), and CWE-829
(Inclusion of Functionality from Untrusted Control Sphere), among others. Insecure
deserialization (CWE-502) was merged into A08 in the 2021 revision — in the 2017 list
it was its own category, A8:2017-Insecure Deserialization.

## 2. Scope of this series

This note series deliberately covers the **non-deserialization** side of A08, because
deserialization already has its own dedicated, deeper series in this repository
(`Insecure-Deserialization/`). Revisit that series for `ysoserial`, gadget chains, and
PortSwigger's 10-lab deserialization track.

What this series focuses on instead:

| File | Topic |
|---|---|
| `02-supply-chain-and-dependency-attacks.md` | Dependency confusion, typosquatting, malicious package compromise, lockfile/build-script abuse |
| `03-cicd-pipeline-security.md` | Poisoned Pipeline Execution, GitHub Actions injection, runner abuse, unsigned/unverified software update mechanisms |
| `04-client-side-integrity.md` | Subresource Integrity (SRI), CDN-hosted script trust, third-party JavaScript supply chain |
| `05-cheatsheet-and-lab-mapping.md` | Defensive checklist + honest PortSwigger Academy coverage assessment |

A common thread you'll see repeated across every file: **integrity failures are rarely
exploited through clever payload crafting. They're exploited through trust
relationships that nobody questioned.** That's why this category reads more like
applied threat modeling and DevSecOps than classic web app pentesting — there's no
single injection point to fuzz. The "exploit" is usually: find the place where
verification was supposed to happen, confirm it didn't, then walk through the open
door.

## 3. Why this category exists — real-world breach catalog

These are not hypothetical risks. Every sub-topic in this series maps to at least one
publicly documented incident with significant real-world impact.

### SolarWinds Orion (2020) — unsigned/compromised update channel
Attackers (tracked as UNC2452/Nobelium) compromised SolarWinds' build environment and
inserted a backdoor (SUNBURST) into the Orion IT-monitoring platform's legitimate,
digitally-signed update packages. Because the malicious DLL was signed with
SolarWinds' real code-signing certificate, it passed every signature check on the
client side. Roughly 18,000 customers — including multiple US federal agencies —
pulled the trojanized update through their normal, trusted patching process. This is
the textbook example of why integrity checking has to extend *into* the build
pipeline, not just to the final binary's signature.

### CodeCov Bash Uploader (2021)
Attackers modified the `codecov-bash` uploader script hosted on CodeCov's
infrastructure, exploiting an error in their Docker image creation process to extract
credentials. Because thousands of CI pipelines downloaded and *executed* this script
directly via `curl | bash` on every build — with no integrity check on the fetched
script — the attackers gained the ability to exfiltrate environment variables
(API keys, credentials, tokens) from every pipeline that ran it, for roughly two
months before detection.

### event-stream npm package (2018)
A maintainer of the popular `event-stream` package transferred ownership to an
anonymous contributor who had been "helpfully" submitting patches. The new
"maintainer" published a version containing a dependency (`flatmap-stream`) with
obfuscated code designed to steal cryptocurrency wallet credentials specifically from
applications built with the Copay wallet, which depended on `event-stream`
transitively. Nobody asked who this new maintainer was before millions of downloads
pulled the malicious version.

### ua-parser-js, coa, and rc npm packages (2021)
Maintainer npm accounts were compromised (credential reuse / phishing), and malicious
versions publishing cryptominers and password-stealing code were pushed directly to
the registry under the legitimate package names. Because these are extremely
high-download-count transitive dependencies pulled in by frameworks like
`create-react-app`, the blast radius was enormous despite the window of compromise
being only a few hours.

### xz-utils backdoor (2024)
A multi-year social-engineering operation resulted in a backdoor being inserted into
`liblzma` (part of the widely-used `xz-utils` compression library) by a trusted
co-maintainer account. The backdoor specifically targeted OpenSSH via a chain through
`systemd`'s `liblzma` linkage, and was nearly distributed into major Linux
distributions' stable releases. It was caught by chance — a developer noticed
unexplained CPU overhead during SSH login latency testing. This incident is widely
cited as the moment "supply chain security" stopped being a niche concern and became
a board-level conversation.

### polyfill.io CDN compromise (2024)
The domain `polyfill.io` — which served a popular JavaScript polyfill library
embedded via `<script src="https://cdn.polyfill.io/...">` on an estimated 100,000+
websites — was sold to a new owner. The new operator modified the served JavaScript
to redirect mobile users to malicious sites and inject other payloads, directly into
every site that loaded the script without integrity verification. Sites with
Subresource Integrity (`integrity="sha384-..."`) on that script tag were unaffected,
because the browser would have rejected the modified file. This is the canonical
case study for `04-client-side-integrity.md`.

### Dependency confusion research (Alex Birsan, 2021)
Independent security researcher Alex Birsan demonstrated that internal/private
package names used by major companies (Apple, PayPal, Microsoft, Shopify, Netflix,
Yelp, Uber, and others) could be claimed on *public* registries (npm, PyPI, RubyGems).
Because many build tools default to checking the public registry, or resolve by
"highest version wins" across registries without strict namespace pinning, internal
build and CI systems pulled and executed the attacker's public package instead of the
real internal one — resulting in over $130,000 in bug bounties and a new named attack
class: **dependency confusion**.

### 3CX supply chain attack (2023)
The 3CX desktop softphone application's official, digitally signed installer was
itself compromised at the build stage (a downstream effect of an earlier compromise
of a different vendor's software, X_TRADER) — meaning the "verified, signed"
installer customers downloaded from 3CX's own website was malicious. This is a
second, independent confirmation that signature verification alone is not sufficient
if the **build environment that produces the signed artifact** is compromised.

## 4. Industry frameworks that respond directly to A08

These came up enough in real incident retrospectives that they're now baseline
vocabulary in any serious AppSec or DevSecOps conversation. You'll see them
referenced again in the CI/CD and supply chain files:

- **SLSA (Supply-chain Levels for Software Artifacts)** — a maturity framework (now
  under OpenSSF) defining build provenance levels, from "no guarantees" (SLSA 0) to
  "hermetic, fully verifiable, two-party-reviewed builds" (SLSA 4 equivalent in the
  current spec). It directly targets the SolarWinds/3CX failure mode: verifying not
  just the artifact's signature, but *how and where* it was built.
- **Sigstore / cosign** — a free, OIDC-identity-based code-signing system (no
  long-lived private keys to leak) for signing and verifying container images,
  binaries, and arbitrary artifacts. Used heavily for verifying container provenance
  in Kubernetes/cloud-native pipelines.
- **in-toto** — a framework for cryptographically recording each step of a software
  supply chain (who ran what, on what input, producing what output) so that the final
  consumer can verify the entire chain of custody, not just the last step.
- **SBOM (Software Bill of Materials)** — a formal, machine-readable inventory of every
  component (and sub-component) in a piece of software, typically in **CycloneDX** or
  **SPDX** format. SBOMs don't prevent supply chain attacks by themselves, but they're
  the prerequisite for being able to answer "are we affected by this CVE" in hours
  instead of weeks — this was the core operational pain point exposed by both
  Log4Shell and the xz-utils backdoor.
- **NIST SSDF (Secure Software Development Framework, SP 800-218)** — the framework
  referenced in US federal procurement requirements (Executive Order 14028) for
  software vendors to attest to secure build practices, largely written in direct
  response to SolarWinds.

## 5. Real-world note: this is a "design and process" category, not a "payload" category

Across the rest of this series you will notice something different from SQL
injection, XSS, or even deserialization: there is rarely a single crafted string that
"is" the exploit. Instead, the deliverable from a pentest or bug bounty report in this
category is usually one of:

1. **Proof a registry namespace is unclaimed** (dependency confusion) — proof is a
   harmless package that gets installed and phones home.
2. **Proof a pipeline step executes attacker-controlled input** (CI/CD) — proof is a
   benign command (`whoami`, `id`, an outbound DNS request) executed in the runner's
   context.
3. **Proof a resource loads without integrity verification** (client-side) — proof is
   showing the response headers/HTML lack `integrity` attributes or CSP enforcement,
   plus a controlled demonstration of what an attacker-modified response would do.

Keep that framing in mind as you go through the other files — the "exploitation"
sections describe *how an attacker would weaponize the gap*, but the actual
deliverable in legitimate testing is almost always a safe proof-of-concept, not a
working backdoor.
