# CI and Release Automation

**Project:** NAILS (NixOS Anti-forensics Isolation & Layering System)

This repository is public. The CI and release workflows are written for a public GitHub project while preserving the current supply-chain posture: deterministic Nix builds, SBOM generation, provenance, and release verification.

## Workflow inventory

| Workflow | Purpose | Triggers |
|---|---|---|
| `.github/workflows/ci.yml` | Primary quality gate for Rust code, coverage, dependency policy, SBOM generation, flaky-test detection, and benchmark enforcement | Push to `main`/`dev`, PRs targeting `main`/`dev`, manual dispatch |
| `.github/workflows/scheduled.yml` | Maintenance that never gates a merge: the full-graph dependency policy scan (`just deny-full`), the `deny.toml` ignore expiry check, the crate fetcher canary, Rust cache warming, the stress loop (`just stress`), informational benchmarks and an opt-in geiger report | Weekly schedule (cache warming twice a week), manual dispatch with a `task` input |
| `.github/workflows/forensics-eval-regression.yml` | Cheap non-privileged forensics regression lane covering Python tests plus a fixture-backed smoke run | Push to `main`/`dev`, PRs targeting `main`/`dev`, manual dispatch |
| `.github/workflows/e2e-tests.yml` | Nix-based smoke validation for the fast CI E2E subset | Push/PR to `dev` with path filters, manual dispatch |
| `.github/workflows/e2e-tests-full.yml` | Full Hetzner-backed E2E suite for trusted manual runs and PR runs gated by native GitHub environment approval | `pull_request_target` to `main` with path filters, manual dispatch |
| `.github/workflows/forensics-eval-fast.yml` | GitHub-hosted fast `forensics-eval` unittest lane for lightweight evaluator coverage under `nix/forensics-eval/tests` | Push/PR with path filters covering fast tests, related evaluator code, selected docs, and manual dispatch |
| `.github/workflows/forensics-eval-full.yml` | Full Hetzner-backed forensics-eval suite, executed as a single live-target job on trusted manual runs | Manual dispatch |
| `.github/workflows/forensics-eval-full-pr-metadata.yml` | Metadata-only `pull_request_target` companion for full forensics eval PR visibility without calling the privileged reusable shard | `pull_request_target` to `main` with path filters |
| `.github/workflows/nix-pr-verify.yml` | Verifies the canonical `.#nails-release` derivation on pushes and PRs | Push to `main`/`dev`, PRs targeting `main`/`dev`, manual dispatch |
| `.github/workflows/release.yml` | Tag-driven release entrypoint: exact stable tags are verification-only, while suffixed prerelease tags publish immutable GitHub prereleases | Push of `v*` tags |
| `.github/workflows/publish-release.yml` | Deliberate manual stable-release publisher that requires an exact stable tag input and creates the GitHub release once in final form | Manual dispatch |
| `.github/workflows/release-core.yml` | Reusable release implementation that builds the canonical bundle, verifies determinism, generates SBOMs, creates attestations, and optionally creates a GitHub release | Called from `release.yml` and `publish-release.yml` |
| `.github/workflows/reproducibility.yml` | Reusable workflow that performs two independent rebuilds and compares the resulting release bundles | Called from `release-core.yml`, manual dispatch |

## CI policy

### `ci.yml` quality gate

The main CI workflow runs these jobs:

1. **Lint & Format** — `cargo fmt`, `cargo clippy`, the Rust file length check, and the unit tests for the E2E tooling in `scripts/tests/`.
2. **Dependency Policy** — `just deny` (cargo-deny over the shipped dependency graph): bans, licenses and sources on every run; advisories and the `deny.toml` ignore expiry check only when `Cargo.toml`, `Cargo.lock` or `deny.toml` change, or on manual runs.
3. **Tests** — `cargo nextest run` across four shards.
4. **Coverage Enforcement** — `just coverage` (cargo-llvm-cov over nextest); the line-coverage threshold is defined once, in the `justfile`.
5. **SBOM Generation** — CycloneDX 1.6 JSON via `cargo sbom`, validated with `cyclonedx-cli`.
6. **Unsafe Code Audit** — `cargo geiger` report upload.
7. **Burn-In Loop** — ten full test iterations on PRs and manual dispatch; the weekly stress loop runs in `scheduled.yml`.
8. **Benchmarks** — enforced Criterion budgets on `main` and manual runs.
9. **`ci-success`** — final aggregate status check.

### Important gate behavior

- `ci-success` is the branch-protection-friendly summary job.
- **Burn-in** and **benchmarks** are intentionally conditional. A skipped job does not fail `ci-success`; a failed conditional job does.
- **Advisories gate dependency changes only.** A newly published RustSec advisory does not fail unrelated PRs or `main`; the weekly `just deny-full` run in `scheduled.yml` reports it, including advisories for crates that never ship (other targets, dev-dependencies). See [security-validation.md](security-validation.md#dependency-policy).
- **E2E tests are not folded into `ci-success`.** They run in their own workflow when relevant source, Nix, or manifest files change.
- **Nix release-path verification is also separate.** `nix-pr-verify.yml` is the dedicated check for the exact release derivation used by the release workflow.

This split is deliberate: the repository keeps fast, broadly applicable CI in `ci.yml` while preserving deeper release-path and NixOS validation in dedicated workflows.

### Tracking issues for unattended runs

Runs nobody watches end in a job that calls the `.github/actions/report-status` composite action: `ci.yml` on pushes to `main`, `scheduled.yml`, and `release.yml`. It keeps one open issue per workflow and label in step with the latest run:

- A failed or cancelled job opens the issue (label `ci-red`, title `CI red: <workflow>`; `CI red: main` for `ci.yml`), or comments on it with the run link and the red jobs when it is already open.
- A run in which every reported job passed closes the issue. A run that skipped some jobs without a failure (for example a manual dispatch of a single `scheduled.yml` task) leaves it as it is.
- The full-graph advisory scan and the `deny.toml` ignore expiry check report under their own `advisory` label (`Dependency advisories`), so they never touch the `ci-red` issue or any pull request check. The informational benchmark and geiger jobs never report.

Only the reporting jobs get `issues: write`. The rules live in `report_status.py` next to the action and are tested in `scripts/tests/test_report_status.py`.

### `forensics-eval-regression.yml` behavior

- The workflow is the cheap, branch-protection-friendly forensics lane for ordinary push/PR/manual CI.
- It runs on GitHub-hosted runners without repository secrets or Hetzner provisioning.
- It executes `python3 -m unittest discover -s nix/forensics-eval/tests -p 'test_*.py'`.
- It also executes the fixture-backed smoke check `./nix/forensics-eval/checks/smoke-demo.sh`, so the new Python/fixture path is visibly covered in normal CI.
- This lane is intentionally fixture/demo-only; it does **not** claim live support for graphical or vfat profiles.

### Test ownership split

- Normal E2E owns product behavior and lifecycle validation: activate/deactivate flows, cleanup, verify/preflight paths, state/session handling, and similar end-to-end product behavior.
- Legacy forensic E2E owns coarse VM-internal forensic spot checks.
- `forensics-eval` owns staged evidence export, baseline-aware analysis, report generation, and campaign-style forensic evaluation.
- `forensics-eval` should not duplicate normal E2E coverage. If a check is mainly about product correctness rather than exported evidence and forensic comparisons, it belongs in normal E2E.

### `e2e-tests.yml` behavior

- The workflow runs `./scripts/run-e2e-tests.sh`, not the aggregate `e2e.ci` link-farm target directly.
- In CI, the runner defaults to the `ci` suite (or can be pinned explicitly with `NAILS_E2E_DEFAULT_TARGET=ci`).
- The runner expands suites/groups from Nix metadata into concrete leaf tests, deduplicates them in stable first-seen order, and executes them sequentially.
- `./scripts/run-e2e-tests.sh --dry-run ci` prints the exact resolved leaf test list without executing it.
- The workflow is explicitly positioned as the **smoke** E2E lane, while `e2e-tests-full.yml` remains the comprehensive gated suite.
- Workflow concurrency is branch/PR-aware with `cancel-in-progress: true`, so superseded smoke runs are cancelled automatically.
- Trigger scope: pushes to `dev`, PRs targeting `dev`, and manual dispatch. `main` and PRs to `main` are owned by `e2e-tests-full.yml` to avoid duplicate E2E runs.
- Path coverage includes the E2E runner script, relevant workflow files, the `setup-nix` action, flake inputs, and Cargo manifests so smoke runs follow CI/E2E infrastructure changes more reliably.

This keeps suite membership in one source of truth under `nix/e2e-tests/default.nix`, while making CI execution order explicit and safer for shared-host runner state than invoking the aggregate `e2e.ci` derivation as a single build target.

### `e2e-tests-full.yml` behavior

- The workflow runs `./scripts/run-e2e-tests.sh all` on an ephemeral Hetzner self-hosted runner.
- Public PR approval now uses the workflow's own `pull_request_target` trigger plus a metadata-only job bound to the GitHub environment `hetzner-pr`.
- That approval job performs no checkout and executes no PR code, so GitHub's native **Review deployments** flow gates runner provisioning directly.
- After approval, the trusted GitHub-hosted resolver job fetches the current PR head repository/ref/SHA from the GitHub API and passes that exact target into the reusable Hetzner worker.
- Workflow concurrency is PR-aware and uses `cancel-in-progress: true`, so a newer push to the same PR cancels older waiting/running privileged runs.
- The shard workflow checks out the exact approved SHA with `persist-credentials: false` and verifies that `HEAD` matches before executing PR code.
- The workflow provisions the runner on a GitHub-hosted job, runs the suite on the returned self-hosted label, and always attempts teardown afterward.
- Full-E2E shard selection is deterministic but runtime-aware: `./scripts/run-e2e-tests.sh` uses checked-in historical leaf durations from `nix/e2e-tests/shard-durations.json` to greedily balance shard load instead of plain round-robin, and refuses to run when a weight is at or above its test's timeout.
- Each shard records per-test durations, uploads them as the `e2e-durations-shard-N` artifact (kept 90 days) and appends a weight-drift report with `::warning::` annotations to its step summary. The report never fails the job; regenerating the weights is described in `nix/e2e-tests/README.md`.
- Every test VM gets 2 cores and 4 GB of memory (`nix/e2e-tests/lib/vm-config.nix`). The size is fixed rather than derived from the runner, so a test evaluates to the same derivation on every host and no build needs `--impure`.
- The reusable shard workflow now uses an explicit minimal secret contract instead of `secrets: inherit`: `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID`.
- Required repository configuration: `PERSONAL_ACCESS_TOKEN` for self-hosted runner registration, `HCLOUD_TOKEN` for Hetzner API create/delete, and `HCLOUD_SSH_KEY_ID` as a repository secret or repository variable for SSH bootstrap.
- Broad log and metrics artifact uploads were removed from this workflow to avoid collecting blanket runner output from privileged Hetzner runs.

### `forensics-eval-full.yml` behavior

- The workflow is the privileged live-evaluation lane, not a replacement for normal E2E or the older VM-internal forensic spot checks.
- The workflow runs a single Hetzner-backed job through `.github/workflows/forensics-eval-full-shard.yml` on one ephemeral self-hosted runner.
- That reusable workflow now invokes `./scripts/run-forensics-eval-tests.sh live` with no sharding.
- The `live` target is the metadata-defined built-in live-supported group, which currently resolves to the single built-in path `direct-baseline/direct-headless`.
- A hosted preflight now checks out the exact approved SHA, validates iterations, resolves `live` from current metadata, and fails closed unless it remains exactly `direct-baseline/direct-headless`.
- That fail-closed guard is deliberate: unsupported leaves such as `graphical` and `vfat-boot` are not treated as built-in live-supported.
- Built-in live support should not be described more broadly than that single path until additional combinations are explicitly supported.
- `.github/workflows/forensics-eval-full.yml` is now `workflow_dispatch`-only so the workflow that calls `.github/workflows/forensics-eval-full-shard.yml` is never triggered by `pull_request_target`.
- `.github/workflows/forensics-eval-full-pr-metadata.yml` preserves the prior PR visibility as a metadata-only companion workflow and does not call the reusable shard, provision runners, or execute repository code.
- Manual runs still resolve a trusted checkout target on GitHub-hosted infrastructure and then pass that exact target into the reusable Hetzner worker.
- Manual workflow concurrency remains branch-aware and uses `cancel-in-progress: true`, so superseded trusted runs cancel older waiting/running privileged runs.
- The reusable worker checks out the exact approved SHA with `persist-credentials: false` and verifies that `HEAD` matches before executing PR code.
- The reusable shard workflow now uses an explicit minimal secret contract instead of `secrets: inherit`: `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID`.
- Before upload, the privileged run now builds a bounded review bundle manifest, fails if required review artifacts are missing, and sanitizes copied review-bundle analyzer evidence/snippet content without mutating the source campaign outputs in `tmp/`.
- The uploaded `full-forensics-eval-results` bundle is intentionally limited to campaign summaries, per-run manifests/summaries/reports/scenario JSON, compare summaries and findings diffs, baseline-vs-stage JSON diffs, stage-hash JSON, analyzer JSON outputs, live stage metadata JSON, and command return-code files.
- The review-bundle manifest now records whether sanitization was applied and which copied files were redacted.
- Current limitation: the artifact bundle still does not upload raw stage trees, disk images, blanket runner logs, or command stdout/stderr, so it is useful for review and triage but not a complete offline-forensics evidence package.
- Required repository configuration matches the full E2E workflow: `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID` (the SSH key ID may be stored as a repository variable instead of a secret).

### `forensics-eval-fast.yml` behavior

- The workflow is a GitHub-hosted fast lane for lightweight `forensics-eval` tests under `nix/forensics-eval/tests`.
- It intentionally avoids Nix builds, VM-backed E2E execution, and live forensic runs.
- The lane keeps a minimal `python -m unittest discover -s nix/forensics-eval/tests -p 'test*.py' -v` contract rather than using `pytest`.
- Path filters cover the fast tests plus closely related evaluator code and workflow/docs inputs: `nix/forensics-eval/tests/**`, `nix/forensics-eval/analyzers/**`, `nix/forensics-eval/runners/**`, `nix/forensics-eval/fixtures/**`, `scripts/run-forensics-eval-tests.sh`, `.github/workflows/forensics-eval-fast.yml`, `nix/forensics-eval/README.md`, and `docs/ci.md`.
- It is the right place for parser, schema, planner, report, and similar fast analysis tests that fit the unittest lane, but not for duplicating normal E2E behavior coverage or implying full live-suite coverage.

### Required GitHub environment configuration for privileged PR runs

Create a repository environment named `hetzner-pr` and configure it with:

- **Required reviewers**: the maintainers who are allowed to approve privileged Hetzner-backed PR runs.
- Optional **deployment branch policy** restricted to `main` if you want the approval gate limited to the default-branch workflow context.

The environment job is approval-only; it does not need environment secrets. Repository secrets remain explicitly mapped into the reusable Hetzner workflows after approval.

## Nix setup and binary cache

Every workflow that needs Nix uses the composite action `.github/actions/setup-nix`. The installer (`cachix/install-nix-action`) is pinned there once, Dependabot keeps that pin current, and every job gets the same `nix.conf`: KVM, `system-features = nixos-test benchmark big-parallel kvm`, `always-allow-substitutes = true` and `accept-flake-config = false`.

The action also connects the project's public Cachix cache:

- **Reads.** The cache is added as an extra substituter next to cache.nixos.org. Its signing key is pinned in `action.yml`, so no substitute is trusted on first use. Every job reads it unless it sets `cache: 'false'`, including fork pull requests and the Hetzner lanes.
- **Pushes.** A job pushes only when it runs for a trusted event and receives `CACHIX_AUTH_TOKEN`. The trusted events are pushes to `main`, scheduled runs, manual dispatches and pull requests from a branch of this repository. Fork pull requests, `pull_request_target` and every other event stay read-only. The decision lives in `.github/actions/setup-nix/cache_plan.py` and is tested in `scripts/tests/test_setup_nix_cache_plan.py`.
- **What is pushed.** The cachix daemon uploads each path as soon as Nix builds it, so a cancelled run keeps its finished work. A push filter limits uploads to three name prefixes:
  - `nails-*`: the binary that every VM test embeds;
  - `rust-default-*`: the Rust toolchain, whose closure holds its components;
  - `vm-test-run-*`: passed VM tests, which later runs fetch instead of booting the test again.

  `nails-release-*` is never pushed. Each path goes up with its closure, except what cache.nixos.org already serves. To push more, add a prefix to `PUSH_ALLOW` in `cache_plan.py`.
- **Who gets the token.** Only `e2e-tests.yml` and `nix-pr-verify.yml` pass it. GitHub withholds secrets from fork pull requests and Dependabot runs, so those stay read-only too. The Hetzner shard workflows never receive the token because they run the code of the pull request under test.
- **Release builds.** `release-core.yml` and `reproducibility.yml` set `cache: 'false'` and never read the project cache. `nails` is therefore compiled from source in every release and rebuild job, and nothing from the cache can end up in a release.

Workflows load the action from the checked-out tree, so the Hetzner lanes and the release workflows need a revision that already contains it; rebase older pull requests before running them there.

Anyone who can push a branch to this repository can push to the cache: once a run has configured the token, the code under test can read it. Write access already implies that trust, and release artifacts never come from the cache.

### Setting up the cache

Until the cache name and key are filled in, the action logs `no project cache is configured` and jobs use cache.nixos.org only. To set the cache up:

1. Create a public cache on cachix.org.
2. In `.github/actions/setup-nix/action.yml`, set `CACHIX_NAME` to the cache's name and `CACHIX_PUBLIC_KEY` to its public signing key (`<name>.cachix.org-1:...`). Append `# pragma: allowlist secret` to the key line so the secret scanner accepts it.
3. Create an auth token with write access to that cache and store it as the Actions repository secret `CACHIX_AUTH_TOKEN`. Do not add it as a Dependabot secret.

## Release policy

### Release trigger behavior

- **Exact stable tags (`v<version>`)**: automatic runs are **verification-only**. They build the canonical bundle, run determinism checks, generate SBOMs/attestations, and do **not** publish a GitHub release.
- **Suffixed prerelease tags (`v<version>-...`)**: automatic runs build the same canonical bundle and publish an immutable **GitHub prerelease** directly from that prerelease tag.
- **`publish-release.yml` manual dispatch**: maintainers provide an exact stable tag such as `v0.2.0`; the workflow validates it against `Cargo.toml`, rejects suffixed tags, and creates the stable GitHub release directly without promoting or editing an existing release.

This is the immutable-release policy: ordinary branch pushes do not trigger the heavy release workflow, exact stable tags are validated automatically, and stable publication only happens through a deliberate manual workflow.

### What the release workflows do

On every run, the workflow:

1. Builds `.#nails-release` with `accept-flake-config = false`.
2. Verifies same-runner determinism with `nix-store --realise --check -K`.
3. Smoke-tests the extracted archive.
4. Generates and validates a CycloneDX SBOM.
5. Uploads the canonical release bundle as a workflow artifact.
6. Calls `reproducibility.yml` to perform two independent rebuild comparisons.
7. Generates a GitHub artifact attestation when repository visibility supports it.

On release-creation runs (`v<version>-...` prerelease tag pushes or manual `publish-release.yml` stable publication), they also:

8. Generates **SLSA Level 3 provenance** (`nails.intoto.jsonl`).
9. Creates a GitHub release exactly once with `gh release create --verify-tag`.

### Release assets

Published stable releases and prereleases contain:

- `nails-*.tar.gz`
- `nails`
- `checksums.txt`
- `sbom.cdx.json`
- `nails.intoto.jsonl`

## Public verification guidance

### Verify the canonical release build locally

```bash
nix build -L .#nails-release -o result --option accept-flake-config false
```

### Verify checksums from a published release

```bash
sha256sum --check checksums.txt
```

### Verify SLSA provenance for a published release

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

slsa-verifier verify-artifact nails-*.tar.gz \
  --provenance-path nails.intoto.jsonl \
  --source-uri github.com/WitteShadovv/nails
```

The `--source-uri` value must match the repository identity embedded in provenance.

### Verify the GitHub artifact attestation

```bash
gh attestation verify nails --repo WitteShadovv/nails
```

GitHub artifact attestations are generated in the release workflow when repository visibility supports them. They complement, but do not replace, the published SLSA provenance file.

## Local commands that mirror CI

The `justfile` is the single source of these commands; `just --list` shows them all. The `nix develop` shell provides every tool they need and installs the git hooks on first entry.

```bash
just check        # formatting, clippy and the test suite (the pre-push gate)
just ci-rust      # everything the ci.yml Rust jobs run, including coverage
just coverage     # line coverage; the threshold is defined only in the justfile
just deny         # dependency policy over the shipped graph
just nix-lint     # nixfmt, deadnix and statix over the tracked Nix files
just e2e ci       # build one E2E target or group
nix build -L .#nails-release -o result --option accept-flake-config false
```

A commit runs only the fast, offline pre-commit hooks (formatting, file and secret checks); `just check` runs on push through the pre-push hook.

## Secrets and permissions

- `CODECOV_TOKEN` is optional and only affects Codecov upload from `main` pushes.
- `CACHIX_AUTH_TOKEN` is optional. With it, `e2e-tests.yml` and `nix-pr-verify.yml` push build results to the project binary cache for trusted events (see [Nix setup and binary cache](#nix-setup-and-binary-cache)). Store it as an Actions secret only.
- Full Hetzner-backed E2E runs require explicitly mapped reusable-workflow secrets for `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID` (the SSH key ID may still be sourced from a repository variable inside the shard workflow).
- Full Hetzner-backed forensics-eval runs require the same explicitly mapped `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID` contract.
- Release provenance and GitHub attestations use GitHub OIDC permissions; no long-lived signing secret is required.

## Operational caveats

- Workflow artifacts are useful for maintainers and contributors, but the **public distribution channel is the immutable GitHub release created from a validated tag**.
- Exact stable tag pushes are always validation-only.
- Stable publication requires `publish-release.yml` and an exact stable tag that matches `Cargo.toml`.
- Automatic prerelease publication is reserved for validated suffixed tags that match the current `Cargo.toml` version.
- E2E validation and Nix release-path verification are separate workflows and should be treated as part of the overall release posture even though they are not aggregated into `ci-success`.
- Ordinary forensics CI is fixture-backed; the privileged live workflow is fail-closed to `direct-baseline/direct-headless` until built-in live support expands.
- The pinned `Cyclenerd/hcloud-github-runner` action still embeds the GitHub runner registration token into Hetzner cloud-init/user-data during runner creation. This patch prevents PR-context provisioning and narrows data handling, but the upstream bootstrap-token exposure remains a caveat until the action design changes.

## Related documents

- [SECURITY.md](../SECURITY.md)
- [docs/security-validation.md](security-validation.md)
- [docs/release-artifact-reproducibility.md](release-artifact-reproducibility.md)
