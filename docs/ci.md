# CI and Release Automation

**Project:** NAILS (NixOS Anti-forensics Isolation & Layering System)

This repository is public. The CI and release workflows are written for a public GitHub project while preserving the current supply-chain posture: deterministic Nix builds, SBOM generation, provenance, and release verification.

## Workflow inventory

| Workflow | Purpose | Triggers |
|---|---|---|
| `.github/workflows/ci.yml` | Primary quality gate for Rust code, coverage, dependency policy, SBOM generation, flaky-test detection, and benchmark enforcement | Push to `main`/`dev`, PRs targeting `main`/`dev`, weekly schedule, manual dispatch |
| `.github/workflows/e2e-tests.yml` | Nix-based end-to-end validation for the fast CI E2E subset | Push/PR to `dev` with path filters, manual dispatch |
| `.github/workflows/e2e-tests-full.yml` | Full Hetzner-backed E2E suite for trusted `main` pushes and maintainer-triggered manual runs | Push to `main`, PRs targeting `main`, manual dispatch |
| `.github/workflows/forensics-eval-full.yml` | Full Hetzner-backed forensics-eval suite, executed as a single live-target job on trusted manual runs | PRs targeting `main`, manual dispatch |
| `.github/workflows/nix-pr-verify.yml` | Verifies the canonical `.#nails-release` derivation on pushes and PRs | Push to `main`/`dev`, PRs targeting `main`/`dev`, manual dispatch |
| `.github/workflows/release.yml` | Builds the canonical release bundle, verifies determinism, generates SBOMs, creates attestations, and publishes public prereleases from `main` | Push to `main`/`dev`, manual dispatch |
| `.github/workflows/reproducibility.yml` | Reusable workflow that performs two independent rebuilds and compares the resulting release bundles | Called from `release.yml`, manual dispatch |

## CI policy

### `ci.yml` quality gate

The main CI workflow runs these jobs:

1. **Lint & Format** — `cargo fmt`, `cargo clippy`, and the Rust file length check.
2. **Security Audit** — `cargo audit` plus `cargo deny check advisories licenses bans sources`.
3. **Tests** — `cargo nextest run` across four shards.
4. **Coverage Enforcement** — `cargo llvm-cov` with an **85%** line-coverage threshold.
5. **SBOM Generation** — CycloneDX 1.6 JSON via `cargo sbom`, validated with `cyclonedx-cli`.
6. **Unsafe Code Audit** — `cargo geiger` report upload.
7. **Burn-In Loop** — ten full test iterations on PRs, scheduled runs, and manual dispatch.
8. **Benchmarks** — enforced Criterion budgets on `main` and manual runs.
9. **`ci-success`** — final aggregate status check.

### Important gate behavior

- `ci-success` is the branch-protection-friendly summary job.
- **Burn-in** and **benchmarks** are intentionally conditional. A skipped job does not fail `ci-success`; a failed conditional job does.
- **E2E tests are not folded into `ci-success`.** They run in their own workflow when relevant source, Nix, or manifest files change.
- **Nix release-path verification is also separate.** `nix-pr-verify.yml` is the dedicated check for the exact release derivation used by the release workflow.

This split is deliberate: the repository keeps fast, broadly applicable CI in `ci.yml` while preserving deeper release-path and NixOS validation in dedicated workflows.

### `e2e-tests.yml` behavior

- The workflow runs `./scripts/run-e2e-tests.sh`, not the aggregate `e2e-ci` link-farm target directly.
- In CI, the runner defaults to the `ci` suite (or can be pinned explicitly with `NAILS_E2E_DEFAULT_TARGET=ci`).
- The runner expands suites/groups from Nix metadata into concrete leaf tests, deduplicates them in stable first-seen order, and executes them sequentially.
- `./scripts/run-e2e-tests.sh --dry-run ci` prints the exact resolved leaf test list without executing it.
- Trigger scope: pushes to `dev`, PRs targeting `dev`, and manual dispatch. `main` and PRs to `main` are owned by `e2e-tests-full.yml` to avoid duplicate E2E runs.

This keeps suite membership in one source of truth under `nix/e2e-tests/default.nix`, while making CI execution order explicit and safer for shared-host runner state than invoking the aggregate `e2e-ci` derivation as a single build target.

### `e2e-tests-full.yml` behavior

- The workflow runs `./scripts/run-e2e-tests.sh all` on an ephemeral Hetzner self-hosted runner.
- It uses `pull_request` (never `pull_request_target`), but only provisions the runner for trusted `push` and `workflow_dispatch` contexts.
- All PRs fail at the trust gate with an explicit message instead of provisioning, because secret-backed self-hosted runners are unsafe in PR contexts. Maintainers must use `workflow_dispatch` for trusted manual validation.
- The workflow provisions the runner on a GitHub-hosted job, runs the suite on the returned self-hosted label, and always attempts teardown afterward.
- The reusable shard workflow now uses an explicit minimal secret contract instead of `secrets: inherit`: `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID`.
- Required repository configuration: `PERSONAL_ACCESS_TOKEN` for self-hosted runner registration, `HCLOUD_TOKEN` for Hetzner API create/delete, and `HCLOUD_SSH_KEY_ID` as a repository secret or repository variable for SSH bootstrap.
- Broad log and metrics artifact uploads were removed from this workflow to avoid collecting blanket runner output from privileged Hetzner runs.

### `forensics-eval-full.yml` behavior

- The workflow runs a single Hetzner-backed job through `.github/workflows/forensics-eval-full-shard.yml` on one ephemeral self-hosted runner.
- That reusable workflow now invokes `./scripts/run-forensics-eval-tests.sh live` with no sharding.
- The `live` target is the metadata-defined built-in live-supported group, which currently resolves to `direct-baseline/direct-headless`.
- The workflow runs on `workflow_dispatch` and on pull requests targeting `main`.
- PR-triggered runs fail at the trust gate and never auto-provision secret-backed Hetzner runners. Maintainers must use `workflow_dispatch` for trusted manual validation.
- The reusable shard workflow now uses an explicit minimal secret contract instead of `secrets: inherit`: `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID`.
- The single run uploads only JSON summaries (`summary.json`, compare `summary.json`, and `campaign-summary.json`); markdown reports, raw evidence bundles, analyzer markdown reports with evidence snippets, and `run-manifest.json` are not uploaded.
- Required repository configuration matches the full E2E workflow: `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID` (the SSH key ID may be stored as a repository variable instead of a secret).

## Release policy

### Branch behavior

- **`main`**: builds the canonical release bundle and publishes a **GitHub prerelease**.
- **`dev`**: runs the same canonical build and determinism checks, but **does not publish a GitHub release**.
- **`workflow_dispatch`**: allows maintainers to run the release workflow manually for validation.

This is the conservative public-facing policy: only `main` produces publicly visible release entries, while `dev` remains a verification branch.

### What `release.yml` does

On every run, the workflow:

1. Builds `.#nails-release` with `accept-flake-config = false`.
2. Verifies same-runner determinism with `nix-store --realise --check -K`.
3. Smoke-tests the extracted archive.
4. Generates and validates a CycloneDX SBOM.
5. Uploads the canonical release bundle as a workflow artifact.
6. Calls `reproducibility.yml` to perform two independent rebuild comparisons.
7. Generates a GitHub artifact attestation when repository visibility supports it.

On `main`, it also:

8. Generates **SLSA Level 3 provenance** (`nails.intoto.jsonl`).
9. Publishes a **GitHub prerelease** containing the canonical artifacts.

### Release assets

Public prereleases from `main` contain:

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

### Verify SLSA provenance for a `main` prerelease

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

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo audit
cargo deny check advisories licenses bans sources
cargo nextest run --no-fail-fast --status-level all
cargo llvm-cov --all-features --workspace --all-targets --cobertura --output-path ./coverage/cobertura.xml
nix build -L .#nails-release -o result --option accept-flake-config false
```

## Secrets and permissions

- `CODECOV_TOKEN` is optional and only affects Codecov upload from `main` pushes.
- Full Hetzner-backed E2E runs require explicitly mapped reusable-workflow secrets for `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID` (the SSH key ID may still be sourced from a repository variable inside the shard workflow).
- Full Hetzner-backed forensics-eval runs require the same explicitly mapped `PERSONAL_ACCESS_TOKEN`, `HCLOUD_TOKEN`, and `HCLOUD_SSH_KEY_ID` contract.
- Release provenance and GitHub attestations use GitHub OIDC permissions; no long-lived signing secret is required.

## Operational caveats

- Workflow artifacts are useful for maintainers and contributors, but the **public distribution channel is the GitHub prerelease published from `main`**.
- `dev` release runs are validation-only by design.
- E2E validation and Nix release-path verification are separate workflows and should be treated as part of the overall release posture even though they are not aggregated into `ci-success`.
- Forensics-eval CI currently runs only the metadata-defined `live` target, so unsupported non-live leaves remain excluded until live support expands.
- The pinned `Cyclenerd/hcloud-github-runner` action still embeds the GitHub runner registration token into Hetzner cloud-init/user-data during runner creation. This patch prevents PR-context provisioning and narrows data handling, but the upstream bootstrap-token exposure remains a caveat until the action design changes.

## Related documents

- [SECURITY.md](../SECURITY.md)
- [docs/security-validation.md](security-validation.md)
- [docs/release-artifact-reproducibility.md](release-artifact-reproducibility.md)
