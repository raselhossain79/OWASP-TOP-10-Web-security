# Cheatsheet and PortSwigger Lab Mapping — A08 (excluding Deserialization)

## 1. Honest PortSwigger Web Security Academy coverage assessment

This is stated plainly and up front, the same way the Insecure Design (A04) series in
this repository disclosed having no automation-tool file: **as of the time this note
was written, PortSwigger Web Security Academy has no dedicated topic or labs covering
CI/CD pipeline security, dependency confusion, typosquatting/package takeover, or
Subresource Integrity / client-side script integrity.**

This was verified directly against the Academy's live "All topics" page rather than
assumed from memory. The full current topic list (Server-side, Client-side, and
Advanced categories) was checked, and none of the categories in this series have a
matching entry. The only Advanced-topic overlap with A08 at all is **Insecure
deserialization** (10 labs), which is intentionally out of scope for this series and
covered separately in this repository's own deserialization note series.

### 1.1 Why this gap exists (and isn't a documentation oversight)

PortSwigger's Academy labs are built around a model where you interact with a
deployed, deliberately vulnerable **web application** and exploit it through HTTP
requests/responses. Every category this series covers breaks that model in a
specific way:

- **CI/CD pipeline security** requires a build/deploy pipeline to attack — there's
  no equivalent of "a vulnerable pipeline you can point Burp Repeater at." The
  artifact is YAML configuration and runner behavior, not an HTTP-reachable surface.
- **Dependency confusion** requires a package registry ecosystem (npm/PyPI/etc.) and
  an actual publish action — the "exploit" happens during `npm install`, not during
  a request to a running web app.
- **Subresource Integrity** is partially testable through a web app (you can audit
  whether a deployed page sets `integrity` attributes correctly), but there's no lab
  built around "find the missing SRI attribute," and the realistic exploitation
  (compromising the actual third-party host) isn't something a training lab can
  safely simulate end-to-end.

This mirrors the same honest gap already documented for Insecure Design (A04) in
this repository — both categories are fundamentally about **process and
architecture decisions** rather than a single exploitable request/response pair, and
the Academy's lab format is optimized for the latter.

### 1.2 What to do instead for hands-on practice

Rather than fabricate a lab mapping that doesn't exist, here is what real-world
practitioners actually use to build hands-on skill in this category:

- **Dependency confusion**: stand up a private package registry locally (e.g.
  **Verdaccio** for npm, or a local `pip` index via `pypiserver`), then deliberately
  create a name collision scenario between a "private" package you publish locally
  and a placeholder you publish to a registry you control, and walk through resolving
  it both vulnerably (default config) and correctly (scoped/pinned config). This
  reproduces the exact mechanism from section 1 of `02-supply-chain-and-dependency-
  attacks.md` without touching any real public registry.
- **CI/CD pipeline security**: create a personal, throwaway GitHub repository with a
  deliberately weak Actions workflow (tag-pinned third-party Action, a
  `pull_request_target` trigger, unsafe expression interpolation as shown in
  `03-cicd-pipeline-security.md`), open pull requests against it from a second test
  account, and observe the behavior directly. Then run `zizmor` and `actionlint`
  against both the vulnerable and hardened versions to see the tooling output change.
- **Subresource Integrity**: serve a static page locally with a script tag pointing
  at a file under your own control on a second local port (simulating "third-party"
  hosting), add a correct `integrity` hash, then modify the served file and observe
  the browser block it — followed by removing the hash and observing the same
  modified file execute silently. This reproduces the polyfill.io failure mode in a
  fully safe, local sandbox.

This is a deliberately different practice setup from the rest of the series in this
repository, and that's worth noting honestly rather than papering over with a
mapping that doesn't reflect reality.

## 2. Defensive / testing checklist by category

### 2.1 Supply chain and dependency attacks

- [ ] Confirm every internal/private package scope is explicitly pinned to a private
  registry in config (`.npmrc` scope mapping, `pip.conf` `index-url`), not relying on
  default resolution order.
- [ ] Confirm internal package names are pre-registered (even as empty placeholders)
  on every public registry the org's tooling could resolve against.
- [ ] Run `confused` (or equivalent) against manifest files to identify unclaimed
  internal-sounding package names.
- [ ] Verify lockfiles are committed, enforced in CI (`npm ci` instead of
  `npm install`, `pip install --require-hashes`), and fail the build on drift.
- [ ] Run `npm audit signatures` / `pip-audit` as a standard CI gate, not an ad hoc
  manual check.
- [ ] Review new/changed maintainers and unscheduled releases on high-impact
  dependencies before accepting an automated version bump.

### 2.2 CI/CD pipeline security

- [ ] Audit every third-party Action/plugin reference for tag-pinning vs SHA-pinning;
  flag every mutable reference.
- [ ] Confirm `pull_request_target` (and equivalents in other CI systems) is never
  combined with a checkout of the PR's own untrusted head ref.
- [ ] Confirm self-hosted/persistent runners are never reachable by public fork pull
  requests.
- [ ] Confirm secrets are scoped to the minimum required jobs/environments, not
  injected globally into every workflow.
- [ ] Run `zizmor` and `actionlint` (or the GitLab/Azure equivalents) as a CI gate on
  every workflow file change.
- [ ] Confirm any `curl | bash` or equivalent fetch-and-execute pattern in build
  scripts is replaced with a pinned, hash-verified download.
- [ ] Confirm update/release artifacts are signed (cosign/GPG) and that verification
  failure is a **fatal**, not logged-and-ignored, condition on the consuming end.
- [ ] Where feasible, adopt SLSA provenance generation and verification rather than
  bare signature checks, to also cover build-environment compromise (the SolarWinds/
  3CX failure mode).

### 2.3 Client-side integrity

- [ ] Audit every third-party-hosted `<script>`/`<link>` tag for an `integrity`
  attribute paired with `crossorigin`.
- [ ] Confirm SRI hash regeneration is automated in the build pipeline for any
  vendored/bundled third-party resource, not a manual one-time task.
- [ ] Where SRI isn't operationally feasible (continuously-deployed third-party
  scripts), confirm compensating controls: CSP `script-src` allow-listing, iframe
  sandboxing of vendor widgets, and vendor security assessment as part of
  procurement.
- [ ] Consider `require-sri-for` in CSP as an organizational guardrail, checking
  current browser support before relying on it as a sole control.

## 3. Quick-reference command index

| Goal | Command |
|---|---|
| Check if a package name is unclaimed (npm) | `npm view <pkg> versions --json` |
| Check if a package name is unclaimed (PyPI) | `pip index versions <pkg>` |
| Audit dependency confusion across a manifest | `./confused -l npm package.json` |
| Verify npm provenance attestations | `npm audit signatures` |
| Scan installed Python packages for known CVEs | `pip-audit` |
| Find mutable (non-SHA-pinned) GitHub Actions | `grep -rn "uses:" .github/workflows/ \| grep -v "@[0-9a-f]\{40\}"` |
| Static-analyze GitHub Actions workflows | `zizmor .github/workflows/` |
| Lint GitHub Actions syntax/expression issues | `actionlint` |
| Verify a GPG-signed release artifact | `gpg --verify file.sig file` |
| Verify a Sigstore-signed artifact | `cosign verify-blob --key cosign.pub --signature file.sig file` |
| Verify SLSA build provenance | `slsa-verifier verify-artifact file --provenance-path file.intoto.jsonl --source-uri <repo>` |
| Generate an SRI hash for a script | `curl -s <url> \| openssl dgst -sha384 -binary \| openssl base64 -A` |
| Find external `<script>` tags missing SRI | `curl -s <url> \| grep -oP '<script[^>]+src="https?://[^"]+\.js"[^>]*>'` |

## 4. Real-world note: how to frame a finding in this category in a report

Every finding in this category should explicitly name three things, because a
client/reviewer in this space (2026 baseline expectation, post-SolarWinds/xz-utils/
polyfill.io) will ask for all three if you don't volunteer them:

1. **The trust boundary that was assumed instead of verified** (e.g. "the build
   pipeline trusts the `v1` tag of this Action to always point at reviewed code").
2. **The realistic attacker who benefits from that gap** (a malicious package
   maintainer, a compromised CDN operator, an opportunistic registry squatter — not
   a generic "attacker").
3. **The industry-standard control that closes it**, named specifically (SHA-pinning,
   SRI + crossorigin, SLSA provenance, scoped private-registry config) rather than a
   vague "implement integrity checks" — specificity here is what distinguishes a
   credible A08 finding from a checkbox-compliance one.
