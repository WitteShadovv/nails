# CI and Release Automation

**Project:** NAILS (NixOS Anti-forensics Isolation & Layering System)

This repository is public. The CI and release workflows are written for a public GitHub project while preserving the current supply-chain posture: deterministic Nix builds, SBOM generation, provenance, and release verification.

## Workflow inventory

| Workflow | Purpose | Triggers |
|---|---|---|
| `.github/workflows/ci.yml` | The pull request gate: lint, tests with coverage and doctests, dependency policy, privileged mount tests, the Nix release build and the flake checks, summarised by the single required `gate` job | PRs targeting `main`, push to `main`, manual dispatch |
| `.github/workflows/scheduled.yml` | Maintenance that never gates a merge: the full-graph dependency policy scan (`just deny-full`), the `deny.toml` ignore expiry check, the crate fetcher canary, the reproducibility check (`reproducibility.yml`), Rust cache warming, the stress loop (`just stress`), the benchmarks (compared with the previous run's baseline) and the monthly transitive `Cargo.lock` refresh | Weekly schedule (cache warming twice a week, lockfile refresh monthly), manual dispatch with a `task` input |
| `.github/workflows/pr-title.yml` | Holds the pull request title to the same Conventional Commits grammar as the commit-msg hook, so a squash merge lands a valid subject on `main` | Pull request opened, edited, synchronized or reopened |
| `.github/workflows/update-flake-lock.yml` | Monthly refresh of the version sources Dependabot has no ecosystem for: `flake.lock` (`nix flake update`) and the pre-commit hook revisions (`pre-commit autoupdate`), each opening its own pull request | Monthly schedule, manual dispatch |
| `.github/workflows/forensics-eval-regression.yml` | Cheap non-privileged forensics regression lane covering Python tests plus a fixture-backed smoke run | Push to `main`/`dev`, PRs targeting `main`/`dev`, manual dispatch |
| `.github/workflows/e2e.yml` | The NixOS VM suite on GitHub-hosted runners: affected tests per pull request, the whole suite per push to `main`, every test driver nightly; runner-parameterised, so the same workflow runs on a self-hosted label | PRs targeting `main` (one path filter), push to `main`, nightly schedule, manual dispatch, `workflow_call` |
| `.github/workflows/forensics-eval-fast.yml` | GitHub-hosted fast `forensics-eval` unittest lane for lightweight evaluator coverage under `nix/forensics-eval/tests` | Push/PR with path filters covering fast tests, related evaluator code, selected docs, and manual dispatch |
| `.github/workflows/release.yml` | The whole release in one run: tag and version check, from-source build, rebuild on a fresh runner, the full E2E suite, SBOM, attestations and a draft GitHub release whose notes are the `CHANGELOG.md` section (see [Release workflow](#release-workflow)) | Push of `v*` tags, manual dispatch from a tag with a `tag` input |
| `.github/workflows/reproducibility.yml` | Builds `.#nails-release` from source on fresh runners and compares the results byte for byte: one rebuild against the release build, or two builds against each other | Called from `release.yml` and weekly from `scheduled.yml` |

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
- **Off the pull request path.** The SBOM is generated only by the release workflow; the benchmarks run weekly in `scheduled.yml` (see [Benchmarks](#benchmarks)) and the E2E performance tests nightly in `e2e.yml`. No pull request job checks a timing budget.

### Lint policy

The policy is compiled in, so `cargo build`, clippy and every editor enforce it the same way:

- **Unsafe code is denied.** `[workspace.lints]` in the root `Cargo.toml` sets `unsafe_code = "deny"` for every crate and target, and both members opt in with `[lints] workspace = true`. A production unsafe site carries a scoped `#[allow(unsafe_code)]` on the smallest item around it, and `clippy::undocumented_unsafe_blocks` requires a `// SAFETY:` comment on each block. Test code may use unsafe freely (`#![cfg_attr(test, allow(unsafe_code))]` in each crate root). A new unsafe block anywhere else fails the build, which replaces the former cargo-geiger report.
- **Function size.** `clippy::too_many_lines` and `clippy::cognitive_complexity` warn, so `-D warnings` fails on them. Their thresholds in `clippy.toml` sit at the largest function when the lints were introduced: no function may grow past that, and the limits go down as functions are split. A function far beyond them carries an `#[expect]` with a reason, which turns into a warning once the function is fixed.
- **File size.** `scripts/check-line-count.sh` counts code lines (neither blank nor a `//` comment) per file. Production files warn above 500 and fail above 850; test files (`tests.rs`, `tests_*.rs`, `*_tests.rs`, anything below `tests/` or `benches/`) only warn, above 1500. It has no exemption list and needs only POSIX tools, and the pre-commit hook, `just check` and the `lint` job run the same script, in well under a second.

### Benchmarks

`nails-core/benches/performance.rs` holds Criterion micro-benchmarks of the state, config, status, activation fast path and emergency orchestration code. Everything outside the state file runs against `MockFilesystem`, so the numbers track regressions between runs; real switching time is what the E2E performance test measures. Each fixture owns its temporary directory, so a run leaves the temp directory as it found it.

- **Where.** The `benchmarks` job of `scheduled.yml`, weekly or dispatched with `task: benchmarks`. The `bench` profile uses thin LTO (`[profile.bench]` in the root `Cargo.toml`) instead of inheriting the release profile's fat LTO.
- **Baseline.** Each run saves its results as the Criterion baseline `current`, exports them with critcmp and uploads the export as the `benchmark-baseline` artifact (kept 90 days). The next run downloads the newest unexpired one from `main` and writes the critcmp table of both runs to the job summary. The first run, or one without an earlier baseline, only records its own.
- **Alerts, not budgets.** A benchmark whose median is more than `ALERT_PERCENT` (25) slower than in the previous run raises a warning annotation; timing never fails the job. The job fails when the build or a benchmark breaks, or when a benchmark that `--list` names left no result, and then it reports through the `ci-red` issue like the other infrastructure tasks.
- **Locally.** `cargo bench -p nails-core --bench performance`; add `-- --save-baseline <name>` and compare two baselines with `critcmp <old> <new>`.

### Tracking issues for unattended runs

Runs nobody watches end in a job that calls the `.github/actions/report-status` composite action: `ci.yml` on pushes to `main`, `e2e.yml` on pushes to `main` and nightly, `scheduled.yml`, and `release.yml`. It keeps one open issue per workflow and label in step with the latest run:

- A failed or cancelled job opens the issue (label `ci-red`, title `CI red: <workflow>`; `CI red: main` for `ci.yml`), or comments on it with the run link and the red jobs when it is already open.
- A run in which every reported job passed closes the issue. A run that skipped some jobs without a failure (for example a manual dispatch of a single `scheduled.yml` task) leaves it as it is.
- The full-graph advisory scan and the `deny.toml` ignore expiry check report under their own `advisory` label (`Dependency advisories`), so they never touch the `ci-red` issue or any pull request check. The benchmarks job reports with the infrastructure tasks; only a broken build or a missing result turns it red, never a slowdown.

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
| Pull request to `main` | `affected` | The `ci` group plus every test whose derivation differs from the base branch (`python3 -m ci.e2e plan --affected`). A test file change adds that test; a change to `nails` changes every test. The `performance` group is always left out. |
| Pull request with the `full-e2e` label | `all` | Every test except the `performance` group. |
| Push to `main` | `all` | Every test except the `performance` group; a test whose derivation already passed is substituted from the binary cache instead of booting again. |
| Nightly schedule | `execute` | Every test driver runs directly (`run --execute`), so cached results do not count. The performance tests run here only, in an informational job of their own that never fails the run. |
| Manual dispatch or `workflow_call` | input | `mode` (`affected`, `ci`, `all`, `execute`), `runner` and `max-shards`. `release.yml` calls it with `all` for the tagged commit. |

- **One path filter.** The `plan` job of a pull request or push run compares the change with its base; a dispatch or a call runs the mode it asked for. When nothing under `nails-core/`, `nails-cli/`, `nix/`, `ci/e2e/`, the setup-nix action, this workflow, the flake, the Cargo manifests or `rust-toolchain.toml` changed, no VM boots and `e2e-result` passes. A docs-only pull request therefore costs one short job.
- **No secrets for untrusted code.** There is no `pull_request_target` and no approval environment. Fork and Dependabot pull requests run like any other and read the binary cache without being able to write to it.
- **Sharding.** `python3 -m ci.e2e plan --max-shards N --format github-matrix` balances the selected tests over as many shards as hold about 900 weighted seconds each (`SHARD_SECONDS` in `ci/e2e/plan.py`), never more than `max-shards` (10 by default) and never an empty one. Each shard's job timeout is 1.5 times its weighted load plus a 15-minute setup allowance (at least 30 minutes).
- **Performance tests.** Wall-clock budgets on shared runners cannot gate a merge, so the shards of every mode exclude the `performance` group, and the `performance` job runs it on the selected runner in `execute` mode only. `07-performance.nix` times each sample inside the guest, from the `duration_ms` that nails logs for an activation (`activate --json`) or a teardown and with the guest clock for `status`, and holds the slowest of a few samples to its budget. It times status, overlay-only activation, emergency and one default activation, with `nixos-rebuild` stubbed so the external build stays out of the budget.
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
- **Who gets the token.** Only `e2e.yml` (also when `release.yml` calls it) and the `nix-build` job of `ci.yml` pass it. GitHub withholds secrets from fork pull requests and Dependabot runs, so those stay read-only too.
- **Release builds.** The `build` job of `release.yml` and `reproducibility.yml` set `cache: 'false'` and never read the project cache. `nails` is therefore compiled from source in every release and rebuild job, and nothing from the cache can end up in a release. The release's E2E run reads the cache like any other E2E run; it gates the release but produces none of its files.

Workflows load the action from the checked-out tree, so a run needs a revision that already contains it; rebase older pull requests before running them.

Anyone who can push a branch to this repository can push to the cache: once a run has configured the token, the code under test can read it. Write access already implies that trust, and release artifacts never come from the cache.

### Setting up the cache

Until the cache name and key are filled in, the action logs `no project cache is configured` and jobs use cache.nixos.org only. To set the cache up:

1. Create a public cache on cachix.org.
2. In `.github/actions/setup-nix/action.yml`, set `CACHIX_NAME` to the cache's name and `CACHIX_PUBLIC_KEY` to its public signing key (`<name>.cachix.org-1:...`). Append `# pragma: allowlist secret` to the key line so the secret scanner accepts it.
3. Create an auth token with write access to that cache and store it as the Actions repository secret `CACHIX_AUTH_TOKEN`. Do not add it as a Dependabot secret.

## Release workflow

A release is one annotated `v*` tag on `main`; [RELEASING.md](../RELEASING.md) is the maintainer checklist. Pushing the tag starts `release.yml`, and the run ends in a draft GitHub release. Publishing the draft is the one manual step. A manual dispatch runs the same pipeline again for an existing tag. It must run from that tag (`gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z`), because the provenance records the ref and commit of the run as the source; every job therefore builds and tests the tagged commit with the workflow and tooling of the tag.

| Job | Needs | What it does |
|---|---|---|
| `version` | | Requires a run on an annotated tag, then runs `python3 -m ci.release check`: the tag must be `v` plus the workspace version, a `-dev` version is refused, every workspace package in `Cargo.lock` must carry the version, and `CHANGELOG.md` must have a non-empty section for it. That section, with a link to [verify-release.md](verify-release.md), becomes the release notes. A mistake fails here, before any build. |
| `build` | `version` | Builds `.#nails-release` without the project cache, so `nails` is compiled from source, with cargo's `--locked`. Smoke-tests the bundle: the archive `nails-<version>-x86_64-unknown-linux-musl.tar.gz` and its contents, `nails --version` and `checksums.txt`. |
| `rebuild` | `build` | Calls `reproducibility.yml`, which builds the bundle again on a fresh runner and compares every file with the `build` output byte for byte; a mismatch uploads a diffoscope report. |
| `e2e` | `version` | Calls `e2e.yml` with mode `all` on the tagged commit. A dispatch can pick the runner with `e2e-runner` and `e2e-max-shards`. |
| `sbom` | `build` | `cargo cyclonedx` (a checked binary from `taiki-e/install-action`) describes the `nails` binary for `x86_64-unknown-linux-musl`, without build-time dependencies. `python3 -m ci.release sbom-libc` adds the statically linked musl, whose version `build` reads from the pinned nixpkgs, and `cyclonedx validate --fail-on-errors` checks the result against CycloneDX 1.5. |
| `attest` | all of the above | `actions/attest` signs build provenance for the subjects of `checksums.txt` (the archive and the binary), and a second attestation binds the SBOM to them. Nothing is attested before every gate passed. |
| `draft-release` | `attest` | `gh release create --draft --verify-tag` with the four assets, marked as a prerelease for an `X.Y.Z-rc.N` version. An existing release is never modified. |
| `report-status` | every job | Keeps the `CI red: Release` issue in step (see [Tracking issues for unattended runs](#tracking-issues-for-unattended-runs)). |

- **Provenance level.** GitHub artifact attestations are SLSA v1.0 Build Level 2: signed provenance from a hosted build platform. The build does not run in an isolated reusable workflow, so the project does not claim Build Level 3. There is no provenance file among the assets; `gh attestation verify` fetches the attestation from GitHub.
- **Reproducibility.** The cross-runner comparison of `rebuild` is the evidence that the binary is reproducible. `nix-store --realise --check` is not used: it repeats only the archive packaging, on the same runner and with the same compiled binary. `scheduled.yml` runs `reproducibility.yml` every week on `main` with two independent builds, so a regression shows up before a release does.
- **Concurrency.** Runs for the same tag queue in the group `release-<tag>`; none cancels another.
- **Assets.** `nails`, `nails-<version>-x86_64-unknown-linux-musl.tar.gz`, `checksums.txt` and `sbom.cdx.json`.

## Verifying a release

[verify-release.md](verify-release.md) is the single description of how users check a release: `sha256sum --check --ignore-missing checksums.txt`, `gh attestation verify`, and where to do it. [release-artifact-reproducibility.md](release-artifact-reproducibility.md) explains how to rebuild the bundle and compare it with a release.

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
- Release attestations are signed with the `attest` job's OIDC identity (`id-token: write`); no long-lived signing secret exists.

## Operational caveats

- Workflow artifacts are useful for maintainers and contributors, but the **public distribution channel is the published GitHub release**, drafted by `release.yml` from a validated tag.
- A release run only drafts; a maintainer publishes the draft after reviewing it.
- E2E validation is a separate workflow with its own required check, `e2e-result`; it is not aggregated into `gate`.
- Ordinary forensics CI is fixture-backed; there is no live forensics lane.

## Related documents

- [SECURITY.md](../SECURITY.md)
- [docs/security-validation.md](security-validation.md)
- [docs/release-artifact-reproducibility.md](release-artifact-reproducibility.md)
