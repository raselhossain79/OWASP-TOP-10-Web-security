# A08:2021 — Software and Data Integrity Failures (Non-Deserialization)

Note series covering the OWASP A08:2021 category, focused specifically on the
integrity failures that are **not** insecure deserialization. Deserialization
(CWE-502) has its own separate, dedicated series in this repository
(`Insecure-Deserialization/`) — see that series for `ysoserial`, gadget chains, and
PortSwigger's 10-lab deserialization track.

This series covers the rest of A08: CI/CD pipeline integrity, software supply chain
and dependency attacks, unsigned/unverified software update mechanisms, and
client-side script integrity (CDN trust, Subresource Integrity).

## File index

| File | Contents |
|---|---|
| [`01-overview-and-classification.md`](01-overview-and-classification.md) | A08 scope and CWE mapping, what this series excludes and why, real-world breach catalog (SolarWinds, CodeCov, event-stream, xz-utils, polyfill.io, 3CX, dependency confusion research), industry frameworks (SLSA, Sigstore, in-toto, SBOM, NIST SSDF) |
| [`02-supply-chain-and-dependency-attacks.md`](02-supply-chain-and-dependency-attacks.md) | Dependency confusion mechanics and recon, typosquatting, malicious package/maintainer takeover, detection tooling (`confused`, `npm audit signatures`, `pip-audit`, Socket/OSSF Scorecard-class tools) |
| [`03-cicd-pipeline-security.md`](03-cicd-pipeline-security.md) | Poisoned Pipeline Execution (direct and indirect), GitHub Actions tag-pinning vs SHA-pinning, expression-interpolation shell injection, self-hosted runner abuse, secrets exfiltration via logs, unsigned/unverified update mechanisms, signature/provenance verification (`gpg`, `cosign`, `slsa-verifier`) |
| [`04-client-side-integrity.md`](04-client-side-integrity.md) | Subresource Integrity mechanics, SRI hash generation, the polyfill.io CDN compromise, CSP `require-sri-for` and `script-src`, Magecart-style third-party script supply chain, why continuously-deployed third-party scripts need different controls than SRI |
| [`05-cheatsheet-and-lab-mapping.md`](05-cheatsheet-and-lab-mapping.md) | Honest PortSwigger Academy coverage assessment (no dedicated labs exist for this category — verified directly, not assumed), self-built practice setups as an alternative, full defensive/testing checklist, quick-reference command index, report-writing framing notes |

## Why there's no dedicated automation-tool file

Every other series in this repository includes a dedicated "automation tool" file
(the sqlmap-equivalent pattern). This category doesn't get one, by design: there is
no single tool that automates exploitation across CI/CD risk, dependency confusion,
and client-side integrity simultaneously, because these aren't variations on one
payload class — they're three distinct trust-boundary failures in three different
parts of the software lifecycle. Where category-specific tooling genuinely exists
and is worth knowing (`confused` for dependency confusion, `zizmor`/`actionlint` for
GitHub Actions, `cosign`/`slsa-verifier` for artifact verification), it's documented
inline in the relevant file instead, with full flag-by-flag breakdowns, the same as
every command in this series.

## Lab practice note

PortSwigger Web Security Academy has no dedicated topic for this category (see
`05-cheatsheet-and-lab-mapping.md`, section 1, for the full verification and
reasoning). Hands-on practice for this series is self-built — local registry
simulation, throwaway GitHub Actions repos, and local SRI sandboxes — rather than
Academy labs. That alternative practice setup is documented in the same file.

## Conventions used throughout this series

- Every command is broken down piece by piece — what each flag does and why the
  resulting behavior is exploitable or defensive, never "just run this."
- Every technique file includes at least one verified, named real-world incident,
  not hypothetical scenarios.
- Full English only, no Bangla/Banglish.
- Honest disclosure where Academy lab coverage doesn't exist, rather than a
  fabricated mapping.
