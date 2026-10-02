# CI and Release Automation

**Project:** NAILS (NixOS Anti-forensics Isolation & Layering System)

This repository is public. The CI and release workflows are written for a public GitHub project while preserving the current supply-chain posture: deterministic Nix builds, SBOM generation, provenance, and release verification.

## Workflow inventory

| Workflow | Purpose | Triggers |
|---|---|---|
| `.github/workflows/ci.yml` | The pull request gate: lint, tests with coverage and doctests, dependency policy, privileged mount tests, the Nix release build and the flake checks, summarised by the single required `gate` job | PRs targeting `main`, push to `main`, manual dispatch |
| `.github/workflows/scheduled.yml` | Maintenance that never gates a merge: the full-graph dependency policy scan (`just deny-full`), the `deny.toml` ignore expiry check, the crate fetcher canary, Rust cache warming, the stress loop (`just stress`), informational benchmarks and the monthly transitive `Cargo.lock` refresh | Weekly schedule (cache warming twice a week, lockfile refresh monthly), manual dispatch with a `task` input |
| `.github/workflows/pr-title.yml` | Holds the pull request title to the same Conventional Commits grammar as the commit-msg hook, so a squash merge lands a valid subject on `main` | Pull request opened, edited, synchronized or reopened |
| `.github/workflows/update-flake-lock.yml` | Monthly refresh of the version sources Dependabot has no ecosystem for: `flake.lock` (`nix flake update`) and the pre-commit hook revisions (`pre-commit autoupdate`), each opening its own pull request | Monthly schedule, manual dispatch |
| `.github/workflows/forensics-eval-regression.yml` | Cheap non-privileged forensics regression lane covering Python tests plus a fixture-backed smoke run | Push to `main`/`dev`, PRs targeting `main`/`dev`, manual dispatch |
| `.github/workflows/e2e.yml` | The NixOS VM suite on GitHub-hosted runners: affected tests per pull request, the whole suite per push to `main`, every test driver nightly; runner-parameterised, so the same workflow runs on a self-hosted label | PRs targeting `main` (one path filter), push to `main`, nightly schedule, manual dispatch, `workflow_call` |
| `.github/workflows/forensics-eval-fast.yml` | GitHub-hosted fast `forensics-eval` unittest lane for lightweight evaluator coverage under `nix/forensics-eval/tests` | Push/PR with path filters covering fast tests, related evaluator code, selected docs, and manual dispatch |
| `.github/workflows/release.yml` | Tag-driven release entrypoint: exact stable tags are verification-only, while suffixed prerelease tags publish immutable GitHub prereleases | Push of `v*` tags |
| `.github/workflows/publish-release.yml` | Deliberate manual stable-release publisher that requires an exact stable tag input and creates the GitHub release once in final form | Manual dispatch |
| `.github/workflows/release-core.yml` | Reusable release implementation that builds the canonical bundle, verifies determinism, generates SBOMs, creates attestations, and optionally creates a GitHub release | Called from `release.yml` and `publish-release.yml` |
| `.github/workflows/reproducibility.yml` | Reusable workflow that performs two independent rebuilds and compares the resulting release bundles | Called from `release-core.yml`, manual dispatch |

## CI policy

### `ci.yml` quality gate

Every work job runs in parallel. None waits for another; each is gated only on the path filter of the `changes` job:

| Job | Runs when | What it does |
|---|---|---|
| `changes` | always | `python3 -m ci.changes` decides which filters the change matches (`rust`, `deps`, `nix`, `workflows`). The path rules live in `ci/changes.py` and nowhere else. |
| `lint` | `rust` | Fails on a `Cargo.lock` that does not match the manifests (`cargo metadata --locked`), then `just fmt-check`, `just lint` (clippy with `--locked -D warnings`, which also enforces the [lint policy](#lint-policy)), `just line-count` and the orphan module check. |
| `rust` | `rust` | `just coverage` (cargo-llvm-cov over nextest with the `ci` profile) and `just doctest`. The line-coverage threshold is defined once, in the `justfile`, and the figure goes to the job summary. The tests run against a private `TMPDIR` that must be empty afterwards. |
| `deps` | `rust` or `deps` | `just deny bans licenses sources`; advisories and the `deny.toml` ignore expiry check only when `Cargo.toml`, `Cargo.lock` or `deny.toml` changed. |
| `privileged-mounts` | `rust` | The `#[ignore]`d real-overlayfs tests, built unprivileged and run as root in a private mount namespace. |
| `nix-build` | `rust` or `nix` | `nix build .#nails-release` (the release derivation) and a smoke test of the archive: contents, `nails --version` and `checksums.txt`. |
| `lint-misc` | `nix` or `workflows` | The unit tests of the CI and E2E tooling (`scripts/tests`, `ci/tests`) and `nix flake check`: nixfmt, statix, deadnix, shellcheck, actionlint, zizmor and the E2E shard weights. |
| `gate` | always | The one required status. It fails when any job failed or was cancelled and passes when the path filter skipped one. |

### Important gate behavior

- **Require `gate`, not the individual jobs.** `gate` replaced the former `CI Success` check; the branch ruleset for `main` must list `gate` as its required check from this workflow (a maintainer setting).
- **Path filter.** Only pull requests are filtered; a pull request is compared with the first parent of its merge commit. Pushes to `main` and manual runs run every job, and so does a change to `ci.yml` or `ci/changes.py`. A docs-only pull request runs `changes` and `gate` and nothing else.
- **One Rust cache.** Every Rust job uses the rust-cache key `ci`; only the `rust` job saves it, and only on `main`. `scheduled.yml` restores the same key twice a week so it does not expire.
- **Flaky tests.** The nextest `ci` profile (`.config/nextest.toml`) retries a failed test once and kills a test after three 60-second slow periods. A test that passes on its retry is listed as FLAKY in the job summary and flagged with a warning; a red run uploads `target/nextest/ci/junit.xml` as the `junit` artifact. The weekly stress loop in `scheduled.yml` runs without retries.
- **Fork-safe.** No job in `ci.yml` writes to the pull request, so a fork pull request and any other run with a read-only token pass the gate. Only `report-status` has a write permission (`issues: write`), and it runs only on pushes to `main`.
- **Advisories gate dependency changes only.** A newly published RustSec advisory does not fail unrelated PRs or `main`; the weekly `just deny-full` run in `scheduled.yml` reports it, including advisories for crates that never ship (other targets, dev-dependencies). See [security-validation.md](security-validation.md#dependency-policy).
- **E2E tests are not folded into `gate`.** They run in `e2e.yml`, whose `e2e-result` job is the status to require.
- **Off the pull request path.** The SBOM is generated only by the release workflow; benchmarks run in `scheduled.yml` and never gate.

### Lint policy

The policy is compiled in, so `cargo build`, clippy and every editor enforce it the same way:

- **Unsafe code is denied.** `[workspace.lints]` in the root `Cargo.toml` sets `unsafe_code = "deny"` for every crate and target, and both members opt in with `[lints] workspace = true`. A production unsafe site carries a scoped `#[allow(unsafe_code)]` on the smallest item around it, and `clippy::undocumented_unsafe_blocks` requires a `// SAFETY:` comment on each block. Test code may use unsafe freely (`#![cfg_attr(test, allow(unsafe_code))]` in each crate root). A new unsafe block anywhere else fails the build, which replaces the former cargo-geiger report.
- **Function size.** `clippy::too_many_lines` and `clippy::cognitive_complexity` warn, so `-D warnings` fails on them. Their thresholds in `clippy.toml` sit at the largest function when the lints were introduced: no function may grow past that, and the limits go down as functions are split. A function far beyond them carries an `#[expect]` with a reason, which turns into a warning once the function is fixed.
- **File size.** `scripts/check-line-count.sh` counts code lines (neither blank nor a `//` comment) per file. Production files warn above 500 and fail above 850; test files (`tests.rs`, `tests_*.rs`, `*_tests.rs`, anything below `tests/` or `benches/`) only warn, above 1500. It has no exemption list and needs only POSIX tools, and the pre-commit hook, `just check` and the `lint` job run the same script, in well under a second.

### Tracking issues for unattended runs

Runs nobody watches end in a job that calls the `.github/actions/report-status` composite action: `ci.yml` on pushes to `main`, `e2e.yml` on pushes to `main` and nightly, `scheduled.yml`, and `release.yml`. It keeps one open issue per workflow and label in step with the latest run:

- A failed or cancelled job opens the issue (label `ci-red`, title `CI red: <workflow>`; `CI red: main` for `ci.yml`), or comments on it with the run link and the red jobs when it is already open.
- A run in which every reported job passed closes the issue. A run that skipped some jobs without a failure (for example a manual dispatch of a single `scheduled.yml` task) leaves it as it is.
- The full-graph advisory scan and the `deny.toml` ignore expiry check report under their own `advisory` label (`Dependency advisories`), so they never touch the `ci-red` issue or any pull request check. The informational benchmark job never reports.

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

### `e2e.yml` behavior

One workflow runs the NixOS VM suite in every lane. A `plan` job decides what runs, a matrix of `shard` jobs runs it, and `e2e-result` reports the outcome:

| Trigger | Mode | Selection |
|---|---|---|
| Pull request to `main` | `affected` | The `ci` group plus every test whose derivation differs from the base branch (`python3 -m ci.e2e plan --affected`). A test file change adds that test; a change to `nails` changes every test. |
| Pull request with the `full-e2e` label | `all` | Every test. |
| Push to `main` | `all` | Every test; a test whose derivation already passed is substituted from the binary cache instead of booting again. |
| Nightly schedule | `execute` | Every test driver runs directly (`run --execute`), so cached results do not count. The performance tests run in an informational job that never fails the run. |
| Manual dispatch or `workflow_call` | input | `mode` (`affected`, `ci`, `all`, `execute`), `runner` and `max-shards`. |

- **One path filter.** The `plan` job compares the change with its base. When nothing under `nails-core/`, `nails-cli/`, `nix/`, `ci/e2e/`, the setup-nix action, this workflow, the flake, the Cargo manifests or `rust-toolchain.toml` changed, no VM boots and `e2e-result` passes. A docs-only pull request therefore costs one short job.
- **No secrets for untrusted code.** There is no `pull_request_target` and no approval environment. Fork and Dependabot pull requests run like any other and read the binary cache without being able to write to it.
- **Sharding.** `python3 -m ci.e2e plan --max-shards N --format github-matrix` balances the selected tests over as many shards as hold about 900 weighted seconds each (`SHARD_SECONDS` in `ci/e2e/plan.py`), never more than `max-shards` (10 by default) and never an empty one. Each shard's job timeout is 1.5 times its weighted load plus a 15-minute setup allowance (at least 30 minutes).
- **Runner.** `runner` is the `runs-on` value as JSON and applies to the shards; `plan`, `e2e-result` and the reporting jobs always run on `ubuntu-24.04`. Hosted runners get KVM from setup-nix; a self-hosted runner must provide `/dev/kvm`. A single-use self-hosted runner can serve one job only, so dispatch with `max-shards: 1` for it.
- **Execution.** Each shard runs its tests with `python3 -m ci.e2e run --retries 1`: one `nix build --keep-going` over all of them (or, in `execute` mode, one driver after another). A test whose output is missing after the build failed. Failed tests run once more; a pass on that retry is listed as FLAKY in the step summary and raises a warning annotation, and the shard stays green. A test that fails twice fails the shard.
- **Artifacts.** Each shard uploads its per-test durations (`e2e-durations-shard-N`, kept 90 days) and, only when it failed, the logs of its failed tests (`e2e-logs-shard-N`, kept 14 days). Nothing else from the runner is uploaded.
- **Weights.** Every shard appends a weight-drift report to its summary. The nightly run regenerates `nix/e2e-tests/shard-durations.json` from its durations and offers the result as the `shard-durations` artifact with a diff in the summary; committing it is a deliberate change.
- **Unattended runs.** Pushes to `main` and nightly runs end in `report-status`, which keeps the `CI red: E2E` issue in step with the latest run (see [Tracking issues for unattended runs](#tracking-issues-for-unattended-runs)).
- **Concurrency.** A newer push to a pull request cancels its older run; runs on `main` always finish, because each one fills the cache for the next.

Every test VM gets 2 cores and 2 GB of memory, 4 GB for graphical nodes (`nix/e2e-tests/lib/vm-config.nix`, `graphical-vm-config.nix`). The size is fixed rather than derived from the runner, so a test evaluates to the same derivation on every host, no build needs `--impure`, and two VMs fit a four-vCPU hosted runner. Every test runs with a 900 s driver timeout unless it declares a longer `globalTimeout`.

The target is that `mode=all` finishes in at most 10 shards and about 20 minutes on hosted runners. Record the measured shard count and wall-clock time of a full hosted run here once one has completed.

### `forensics-eval-fast.yml` behavior

- The workflow is a GitHub-hosted fast lane for lightweight `forensics-eval` tests under `nix/forensics-eval/tests`.
- It intentionally avoids Nix builds, VM-backed E2E execution, and live forensic runs.
- The lane keeps a minimal `python -m unittest discover -s nix/forensics-eval/tests -p 'test*.py' -v` contract rather than using `pytest`.
- Path filters cover the fast tests plus closely related evaluator code and workflow/docs inputs: `nix/forensics-eval/tests/**`, `nix/forensics-eval/analyzers/**`, `nix/forensics-eval/runners/**`, `nix/forensics-eval/fixtures/**`, `scripts/run-forensics-eval-tests.sh`, `.github/workflows/forensics-eval-fast.yml`, `nix/forensics-eval/README.md`, and `docs/ci.md`.
- It is the right place for parser, schema, planner, report, and similar fast analysis tests that fit the unittest lane, but not for duplicating normal E2E behavior coverage or implying full live-suite coverage.

## Nix setup and binary cache

Every workflow that needs Nix uses the composite action `.github/actions/setup-nix`. The installer (`cachix/install-nix-action`) is pinned there once, Dependabot keeps that pin current, and every job gets the same `nix.conf`: KVM, `system-features = nixos-test benchmark big-parallel kvm`, `always-allow-substitutes = true` and `accept-flake-config = false`.

The action also connects the project's public Cachix cache:

- **Reads.** The cache is added as an extra substituter next to cache.nixos.org. Its signing key is pinned in `action.yml`, so no substitute is trusted on first use. Every job reads it unless it sets `cache: 'false'`, including fork pull requests.
- **Pushes.** A job pushes only when it runs for a trusted event and receives `CACHIX_AUTH_TOKEN`. The trusted events are pushes to `main`, scheduled runs, manual dispatches and pull requests from a branch of this repository. Fork pull requests and every other event stay read-only. The decision lives in `.github/actions/setup-nix/cache_plan.py` and is tested in `scripts/tests/test_setup_nix_cache_plan.py`.
- **What is pushed.** The cachix daemon uploads each path as soon as Nix builds it, so a cancelled run keeps its finished work. A push filter limits uploads to three name prefixes:
  - `nails-*`: the binary that every VM test embeds;
  - `rust-default-*`: the Rust toolchain, whose closure holds its components;
  - `vm-test-run-*`: passed VM tests, which later runs fetch instead of booting the test again.

  `nails-release-*` is never pushed. Each path goes up with its closure, except what cache.nixos.org already serves. To push more, add a prefix to `PUSH_ALLOW` in `cache_plan.py`.
- **Who gets the token.** Only `e2e.yml` and the `nix-build` job of `ci.yml` pass it. GitHub withholds secrets from fork pull requests and Dependabot runs, so those stay read-only too.
- **Release builds.** `release-core.yml` and `reproducibility.yml` set `cache: 'false'` and never read the project cache. `nails` is therefore compiled from source in every release and rebuild job, and nothing from the cache can end up in a release.

Workflows load the action from the checked-out tree, so a run needs a revision that already contains it; rebase older pull requests before running them.

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
just check        # formatting, clippy, file sizes and the tests (the pre-push gate)
just line-count   # the Rust file size check alone
just ci-rust      # everything the ci.yml Rust jobs run, including coverage
just coverage     # line coverage; the threshold is defined only in the justfile
just deny         # dependency policy over the shipped graph
just nix-lint     # nixfmt, deadnix and statix over the tracked Nix files
nix flake check   # what the lint-misc job runs
just e2e ci       # build one E2E target or group
nix build -L .#nails-release -o result --option accept-flake-config false
```

A commit runs only the fast, offline pre-commit hooks (formatting, Rust file sizes, file and secret checks); `just check` runs on push through the pre-push hook.

## Secrets and permissions

- `CODECOV_TOKEN` is optional and only affects Codecov upload from `main` pushes.
- `CACHIX_AUTH_TOKEN` is optional. With it, `e2e.yml` and the `nix-build` job of `ci.yml` push build results to the project binary cache for trusted events (see [Nix setup and binary cache](#nix-setup-and-binary-cache)). Store it as an Actions secret only.
- No E2E lane needs any other secret. Nothing uses the `hetzner-pr` approval environment any more; it can be deleted.
- Release provenance and GitHub attestations use GitHub OIDC permissions; no long-lived signing secret is required.

## Operational caveats

- Workflow artifacts are useful for maintainers and contributors, but the **public distribution channel is the immutable GitHub release created from a validated tag**.
- Exact stable tag pushes are always validation-only.
- Stable publication requires `publish-release.yml` and an exact stable tag that matches `Cargo.toml`.
- Automatic prerelease publication is reserved for validated suffixed tags that match the current `Cargo.toml` version.
- E2E validation is a separate workflow with its own required check, `e2e-result`; it is not aggregated into `gate`.
- Ordinary forensics CI is fixture-backed; there is no live forensics lane.

## Related documents

- [SECURITY.md](../SECURITY.md)
- [docs/security-validation.md](security-validation.md)
- [docs/release-artifact-reproducibility.md](release-artifact-reproducibility.md)
