# CI and release automation

This repository is public. The CI and release workflows are written for a public GitHub project while preserving the current supply-chain posture: deterministic Nix builds, SBOM generation, provenance, and release verification.

## Test and CI tiers

Work runs in four tiers. Each is a superset of the one above it in coverage and cost, and each has a time budget enforced by step and job timeouts, so a slow addition shows up as a red run rather than a creeping wait.

| Tier | Runs | Budget | Scope |
|---|---|---|---|
| 1. pre-commit | On `git commit`, changed files only | under 10 s | Formatting, Rust file sizes, file and secret checks (`.pre-commit-config.yaml`). |
| 2. pre-push / `just check` | On `git push`, and on demand | about 90 s | `just fmt-check lint line-count test`: the whole offline Rust gate without coverage or Nix. |
| 3. PR gate | Every pull request to `main`, and every push to `main` | about 10 min p95 | `ci.yml` (summarised by `gate`), the affected `e2e.yml` run (`e2e-result`) and `pr-title.yml`. These three are the required checks. |
| 4. Post-merge, nightly, weekly | Schedules and labels, never a pull request | unbounded | The full E2E suite, the full-graph advisory scan, the crate fetcher canary, the stress loop, the benchmarks, the reproducibility check, batch fuzzing and the OpenSSF Scorecard analysis. A release runs on its tag. |

Tier 3 is everything a contributor must pass to merge. The informational `fuzz` job of `fuzz.yml` also runs on pull requests that change fuzzed code, outside the tier-3 budget: it pulls two images and builds every target with the address sanitizer before its five minutes of fuzzing. Tier 4 catches what a per-PR budget cannot afford (every VM test, the whole dependency graph, timing and determinism) and reports failures into tracking issues instead of a pull request check (see [Tracking issues for unattended runs](#tracking-issues-for-unattended-runs)).

## Workflow inventory

| Workflow | Trigger | Required check | Tier | Runner | Local `just` recipe |
|---|---|---|---|---|---|
| `.github/workflows/ci.yml` | PRs to `main` and `next`, push to either, dispatch | `gate` | 3 | `ubuntu-26.04` | `just ci-rust`, `just deny` |
| `.github/workflows/pr-title.yml` | Pull request opened, edited, synchronized, reopened | `pr-title` | 3 | `ubuntu-26.04` | the commit-msg hook |
| `.github/workflows/e2e.yml` | PRs to `main` and `next`, push to either, nightly, dispatch, `workflow_call` | `e2e-result` | 3 (affected) and 4 (nightly full) | `runner` input, default `ubuntu-26.04` | `just e2e` |
| `.github/workflows/distro-e2e.yml` | Nightly, `distro-e2e` label on PRs to `main` and `next`, dispatch, `workflow_call` | — (informational) | 4 | `runner` input, default `ubuntu-26.04` (KVM) | `nix build .#legacyPackages.x86_64-linux.e2e-distro.<scenario>` |
| `.github/workflows/next-nightly.yml` | Nightly, dispatch: starts the nightly `e2e.yml` and `distro-e2e.yml` runs of `next` | — | 4 | `ubuntu-26.04` | — |
| `.github/workflows/scheduled.yml` | Weekly, twice-weekly and monthly schedules, dispatch with a `task` input | — | 4 | `ubuntu-26.04` | `just deny-full`, `just stress`, `cargo bench`, `just mutants` |
| `.github/workflows/fuzz.yml` | PRs to `main` and `next` that change fuzzed code, daily schedule, dispatch | — (informational) | 3 (pull requests, outside its budget) and 4 (schedules) | `ubuntu-26.04` | `just fuzz-run <target>` |
| `.github/workflows/reproducibility.yml` | `workflow_call` from `release.yml`, weekly from `scheduled.yml` | — | 4 | `ubuntu-26.04` | `nix build .#nails-release` |
| `.github/workflows/scorecard.yml` | Push to `main`, weekly, branch protection rule change, dispatch | — (informational) | 4 | `ubuntu-26.04` | — |
| `.github/workflows/release.yml` | Push of `v*` tags, dispatch from a tag | — | release | `ubuntu-26.04` (E2E on the `e2e-runner` input) | `python3 -m ci.release check` |

The composite actions `.github/actions/setup-nix` and `.github/actions/report-status` are shared by these workflows and are not workflows themselves.

`just docs-check` (`ci/docs_check.py`) fails when a workflow file is not in this table, or the table names a workflow that no longer exists; the `ci/tests` suite runs the same check, so the drift also fails CI.

## CI policy

### `ci.yml` quality gate

Every work job runs in parallel. None waits for another; each is gated only on the path filter of the `changes` job:

| Job | Runs when | What it does |
|---|---|---|
| `changes` | always | `python3 -m ci.changes` decides which filters the change matches (`rust`, `fuzz`, `deps`, `nix`, `workflows`, `docs`). The path rules live in `ci/changes.py` and nowhere else. |
| `lint` | `rust` or `fuzz` | Fails on a `Cargo.lock` or a `fuzz/Cargo.lock` that does not match the manifests (`cargo metadata --locked`), then `just fmt-check` (the workspace and the fuzz crate), `just lint` (clippy with `--locked -D warnings`, which also enforces the [lint policy](#lint-policy)), `just line-count` and the orphan module check. |
| `rust` | `rust` | `just coverage` (cargo-llvm-cov over nextest with the `ci` profile) and `just doctest`. The production-code line-coverage threshold is defined once, in `.config/coverage.toml`, and the figure goes to the job summary. The tests run against a private `TMPDIR` that must be empty afterwards. The job clears `kernel.apparmor_restrict_unprivileged_userns` and sets `NAILS_REQUIRE_USERNS=1`, so the real-kernel tests (see [testing-strategy.md](testing-strategy.md)) run in their user + mount namespace and cannot skip (only a test that needs a delegated cgroup or a NixOS `/bin/sh` may, through `skip_host`). |
| `shuffle` | `rust` | `just shuffle`: the unit tests of every workspace crate, threaded and shuffled over twenty seeds, so an order-dependent leak through the shared process environment fails the gate. nextest isolates each test in its own process and cannot catch this, hence libtest here; the weekly `stress` job in `scheduled.yml` covers the same ground more heavily. |
| `deps` | `rust` or `deps` | `just deny bans licenses sources`; advisories and the `deny.toml` ignore expiry check only when `Cargo.toml`, `Cargo.lock` or `deny.toml` changed. |
| `privileged-mounts` | `rust` | The one `#[ignore]`d real-overlayfs test that needs real root (directory whiteouts need `trusted.*` xattrs), built unprivileged and run as root in a private mount namespace. The rest of `privileged_mounts.rs` runs rootless in the `rust` job. |
| `nix-build` | `rust` or `nix` | `nix build .#nails-release` (the release derivation) and a smoke test of the archive: contents, `nails --version` and `checksums.txt`. |
| `docs-check` | `docs` | Installs lychee and runs `scripts/docs-check.sh`: an offline link check of every tracked Markdown file and the retired-name guard. |
| `lint-misc` | `nix` or `workflows` | The unit tests of the CI and E2E tooling (`scripts/tests`, `ci/tests`, which includes `just docs-check`) and `nix flake check`: nixfmt, statix, deadnix, shellcheck, actionlint, zizmor and the E2E shard weights. |
| `gate` | always | The one required status. It fails when any job failed or was cancelled and passes when the path filter skipped one. |

### Important gate behavior

- **Require `gate`, not the individual jobs.** `gate` replaced the former `CI Success` check; the branch ruleset for `main` must list `gate` as its required check from this workflow (a maintainer setting).
- **Path filter.** Only pull requests are filtered; a pull request is compared with the first parent of its merge commit. Pushes to `main` or `next` and manual runs run every job, and so does a change to `ci.yml` or `ci/changes.py`. A docs-only pull request runs `changes`, `docs-check` and `gate` and nothing else.
- **One Rust cache.** Every Rust job uses the rust-cache key `ci`; only the `rust` job saves it, and only on pushes to `main` and `next`. A pull request restores the copy of the branch it targets, or that of `main`. `scheduled.yml` restores the key on `main` twice a week so it does not expire.
- **Gate time.** The lean parallel layout targets about 3.5 minutes for a Rust-only pull request on a warm cache (the `rust` job sets the critical path; a docs-only pull request is under a minute). This figure has to be measured on a hosted runner once the `ci` cache is warm on `main` and the confirmed number recorded here; the sandbox used for development cannot time it.
- **Flaky tests.** The nextest `ci` profile (`.config/nextest.toml`) retries a failed test once and kills a test after three 60-second slow periods. A test that passes on its retry is listed as FLAKY in the job summary and flagged with a warning; a red run uploads `target/nextest/ci/junit.xml` as the `junit` artifact. The weekly `stress` job in `scheduled.yml` runs `just stress`, which hunts order- and timing-dependent tests the gate's single run would miss: the suite threaded, then with `--test-threads=1`, then shuffled with a seed it prints (set `SHUFFLE_SEED` to replay a reported ordering), then repeated through nextest with no retries so any single failure fails the job.
- **Mutation testing.** The weekly `mutants` job in `scheduled.yml` runs `just mutants`, which has cargo-mutants change each mutable spot in the state machine (`nails-base/src/state/`) and re-run the tests. A mutation the suite still passes is a test gap that no coverage percentage would reveal; the job summary lists every surviving mutant, the full report uploads as the `mutants-report` artifact for triage, and a surviving mutant never fails the job. A run that catches no mutant fails, since it proves nothing; that happens, for example, when the filters match no code or no mutant builds.
- **Fork-safe.** No job in `ci.yml` writes to the pull request, so a fork pull request and any other run with a read-only token pass the gate. Only `report-status` has a write permission (`issues: write`), and it runs only on pushes to `main` and `next`.
- **One coverage threshold.** The line-coverage floor is `line_threshold` in `.config/coverage.toml` and nowhere else; `just coverage` reads it and enforces it locally and in CI, and the percentage goes to the job summary. The figure measures production code only: the in-memory filesystem mock, the shared test fixtures and every test file are excluded, so test infrastructure that never ships cannot inflate it. There is no Codecov step: the external upload added a token and a flaky network call without gating anything, so coverage is enforced only by the threshold and kept as the `coverage-report` artifact.
- **Advisories gate dependency changes only.** A newly published RustSec advisory does not fail unrelated PRs or `main`; the weekly `just deny-full` run in `scheduled.yml` reports it, including advisories for crates that never ship (other targets, dev-dependencies). See [security-validation.md](security-validation.md#dependency-policy).
- **E2E tests are not folded into `gate`.** They run in `e2e.yml`, whose `e2e-result` job is the status to require.
- **Off the pull request path.** The SBOM is generated only by the release workflow; the benchmarks run weekly in `scheduled.yml` (see [Benchmarks](#benchmarks)) and the E2E performance tests nightly in `e2e.yml`. No pull request job checks a timing budget.

### Lint policy

The policy is compiled in, so `cargo build`, clippy and every editor enforce it the same way:

- **Unsafe code is denied.** `[workspace.lints]` in the root `Cargo.toml` sets `unsafe_code = "deny"` for every crate and target, and every workspace member opts in with `[lints] workspace = true`. A production unsafe site carries a scoped `#[allow(unsafe_code)]` on the smallest item around it, and `clippy::undocumented_unsafe_blocks` requires a `// SAFETY:` comment on each block. Test code may use unsafe freely (`#![cfg_attr(test, allow(unsafe_code))]` in each crate root). A new unsafe block anywhere else fails the build, which replaces the former cargo-geiger report.
- **Function size.** `clippy::too_many_lines` and `clippy::cognitive_complexity` warn, so `-D warnings` fails on them. Their thresholds in `clippy.toml` sit at the largest function when the lints were introduced: no function may grow past that, and the limits go down as functions are split. A function far beyond them carries an `#[expect]` with a reason, which turns into a warning once the function is fixed.
- **File size.** `scripts/check-line-count.sh` counts code lines (neither blank nor a `//` comment) per file. Production files warn above 500 and fail above 850; test files (`tests.rs`, `tests_*.rs`, `*_tests.rs`, anything below `tests/` or `benches/`) only warn, above 1500. It has no exemption list and needs only POSIX tools, and the pre-commit hook, `just check` and the `lint` job run the same script, in well under a second.

### Benchmarks

`nails-core/benches/performance.rs` holds Criterion micro-benchmarks of the config, state, manager construction and status code. Everything outside the state file runs against `MockFilesystem`, so the numbers track regressions between runs; real switching time is what the E2E performance test measures. Each fixture owns its temporary directory, so a run leaves the temp directory as it found it.

- **Where.** The `benchmarks` job of `scheduled.yml`, weekly or dispatched with `task: benchmarks`. The `bench` profile uses thin LTO (`[profile.bench]` in the root `Cargo.toml`) instead of inheriting the release profile's fat LTO.
- **Baseline.** Each run saves its results as the Criterion baseline `current`, exports them with critcmp and uploads the export as the `benchmark-baseline` artifact (kept 90 days). The next run downloads the newest unexpired one from `main` and writes the critcmp table of both runs to the job summary. The first run, or one without an earlier baseline, only records its own.
- **Alerts, not budgets.** A benchmark whose median is more than `ALERT_PERCENT` (25) slower than in the previous run raises a warning annotation; timing never fails the job. The job fails when the build or a benchmark breaks, or when a benchmark that `--list` names left no result, and then it reports through the `ci-red` issue like the other infrastructure tasks.
- **Locally.** `cargo bench -p nails-core --bench performance`; add `-- --save-baseline <name>` and compare two baselines with `critcmp <old> <new>`.

### Tracking issues for unattended runs

Runs nobody watches end in a job that calls the `.github/actions/report-status` composite action: `ci.yml` on pushes to `main`, `e2e.yml` on pushes to `main` and nightly, `scheduled.yml`, `fuzz.yml` on its schedules, `scorecard.yml` on `main`, and `release.yml`. It keeps one open issue per workflow and label in step with the latest run:

- A failed or cancelled job opens the issue (label `ci-red`, title `CI red: <workflow>`; `CI red: main` for `ci.yml`), or comments on it with the run link and the red jobs when it is already open. The runs of `next` keep issues of their own (see [The integration branch `next`](#the-integration-branch-next)).
- A run in which every reported job passed closes the issue. A run that skipped some jobs without a failure (for example a manual dispatch of a single `scheduled.yml` task) leaves it as it is.
- The full-graph advisory scan and the `deny.toml` ignore expiry check report under their own `advisory` label (`Dependency advisories`), so they never touch the `ci-red` issue or any pull request check. The benchmarks job reports with the infrastructure tasks; only a broken build or a missing result turns it red, never a slowdown.

Only the reporting jobs get `issues: write`. The rules live in `report_status.py` next to the action and are tested in `scripts/tests/test_report_status.py`.

### `e2e.yml` behavior

One workflow runs the NixOS VM suite in every lane. A `plan` job decides what runs, a matrix of `shard` jobs runs it, and `e2e-result` reports the outcome:

| Trigger | Mode | Selection |
|---|---|---|
| Pull request to `main` or `next` | `affected` | The `ci` group plus every test whose derivation differs from the base branch (`python3 -m ci.e2e plan --affected`). A test file change adds that test; a change to `nails` changes every test. The `performance` group is always left out. |
| Pull request with the `full-e2e` label | `all` | Every test except the `performance` group. |
| Push to `main` or `next` | `all` | Every test except the `performance` group; a test whose derivation already passed is substituted from the binary cache instead of booting again. |
| Nightly schedule | `execute` | Every test driver runs directly (`run --execute`), so cached results do not count. The performance tests run here only, in an informational job of their own that never fails the run. |
| Manual dispatch or `workflow_call` | input | `mode` (`affected`, `ci`, `all`, `execute`), `runner`, `max-shards` and `tests`. `release.yml` calls it with `all` for the tagged commit. `tests` names the tests and groups to run, separated by spaces, commas or line breaks, in place of the mode's selection; the mode, `all` or `execute`, then says how they run, so `execute` boots a named test even when the binary cache holds a pass of it. A name has letters, digits, `-` and `_` and starts with a letter or digit. |

- **One path filter.** The `plan` job of a pull request or push run compares the change with its base; a dispatch or a call runs the mode it asked for. When nothing under `nails-base/`, `nails-core/`, `nails-cli/`, `nails-forensics/`, `nails-platform/`, `nails-session/`, `nails-teardown/`, `nix/`, `ci/e2e/`, the setup-nix action, this workflow, the flake, the Cargo manifests or `rust-toolchain.toml` changed, no VM boots and `e2e-result` passes. A docs-only pull request therefore costs one short job.
- **No secrets for untrusted code.** There is no `pull_request_target` and no approval environment. Fork pull requests and the runs Dependabot starts itself run like any other and read the binary cache without being able to write to it. A run that a person starts on a Dependabot pull request, by adding a label or pushing to it, gets the secrets like a run for any other branch of this repository (see [Cache trust rules](#cache-trust-rules)).
- **Planning.** For `affected`, the `plan` job first compares the derivation of `nails` at the base revision with this one's. Nearly every test boots `nails`, so when it differs every test is selected and no test is evaluated; a test that does not boot it then comes from the binary cache if it is unchanged. Otherwise the tests of both revisions are evaluated at once, in batches that run side by side (see **Execution**), and compared.
- **Sharding.** `python3 -m ci.e2e plan --max-shards N --format github-matrix` balances the selected tests over as many shards as hold about 300 weighted seconds each (`SHARD_SECONDS` in `ci/e2e/plan.py`, about the longest test's weight), never more than `max-shards` (10 by default) and never an empty one. Only an `affected` selection may hold no test, and then one empty shard passes; in every other mode, `tests` that name only empty groups included, a plan without a test fails instead of passing with nothing run. Each shard's job timeout is 1.5 times its weighted load plus a 15-minute setup allowance (at least 30 minutes).
- **Performance tests.** Wall-clock budgets on shared runners cannot gate a merge, so the shards of every mode exclude the `performance` group, and the `performance` job runs it on the selected runner in `execute` mode only. A run that names its tests in `tests` runs exactly those: a performance test among them runs in a shard, and the `performance` job does not run. `07-performance.nix` times each sample inside the guest and holds the slowest of a few samples to its budget: `status` and `check`, which only read; `activate` and `deactivate` from the trigger until the new userspace has settled after the soft-reboot (`trigger_to_settled`, over two `--overlay-only` round trips); and `emergency` until a shell on the plain decoy is back (`trigger_to_backdoor`).
- **Runner.** `runner` is the `runs-on` value as JSON and applies to the shards; `plan`, `e2e-result` and the reporting jobs always run on `ubuntu-26.04`. Hosted runners get KVM from setup-nix; a self-hosted runner must provide `/dev/kvm`. A single-use self-hosted runner can serve one job only, so dispatch with `max-shards: 1` for it.
- **Execution.** Each shard runs its tests with `python3 -m ci.e2e run --retries 1`. It first evaluates them in batches, each in a `nix eval` process of its own and as many processes at once as the runner's cores and memory allow, then builds them in one `nix build --keep-going` over all of them (or, in `execute` mode, builds their drivers in one `nix build` and runs one driver after another). A test whose output is missing after the build failed. Failed tests run once more; a pass on that retry is listed as FLAKY in the step summary and raises a warning annotation, and the shard stays green. A test that fails twice fails the shard.
- **Execute mode.** `run --execute` builds the driver of every test of its shard, then runs the drivers one after another in the job's shell, outside the Nix sandbox, so the shard gives them what a build would. A driver keeps each VM's disks, Nix store image and sockets in `XDG_RUNTIME_DIR`, falling back to `TMPDIR`, and on a hosted runner `XDG_RUNTIME_DIR` is a small tmpfs in RAM. Each test therefore runs with both set to a scratch directory of its own, `e2e-XXXXXXXX` in `$RUNNER_TEMP`, which a hosted runner keeps on its root disk, and the directory is removed with the VM state when the test ends. When `RUNNER_TEMP` is unset, as in a local run, the scratch directories go to `$TMPDIR`, or to `/tmp` without one, which then needs a few GB free, on disk rather than in a tmpfs. The directory name stays short because a Unix socket path holds at most 107 bytes and virtiofsd's socket sits at `vm-state-<node>/tmp.XXXXXXXXXX/nix-store` below it; a base directory that is missing, or too long for that, stops the run before any driver is built. Before `ci.e2e` starts, the `Run tests` step of an `execute` shard, like the performance job's step, raises the shell's hard open-file limit to 1,048,576 with `sudo prlimit`, as `nix-daemon.service` does for a build: virtiofsd asks for 1,000,000 descriptors, and the job's 65,536 run out in the tests that copy a whole NixOS closure through the host store. Without sudo the step raises a warning, and `run --execute` itself warns below 524,288. Both steps then print the free space of `/`, `$RUNNER_TEMP`, `$XDG_RUNTIME_DIR` and `/mnt`, the memory and the open-file limits.
- **Artifacts.** Each shard uploads its per-test durations (`e2e-durations-shard-N`, kept 90 days) and, only when it failed, the logs of its failed tests (`e2e-logs-shard-N`, kept 14 days). No privileged job uploads `**/*.log`, a performance file or metrics; nothing else from the runner leaves it.
- **Weights.** Every shard appends a weight-drift report to its summary, from the durations it recorded: a test's build time as nix reports it while it runs, or in `execute` mode its driver's run time. The nightly run regenerates `nix/e2e-tests/shard-durations.json` from its durations and offers the result as the `shard-durations` artifact with a diff in the summary; committing it is a deliberate change.
- **Unattended runs.** Pushes to `main` and `next` and the nightly runs of both end in `report-status`, which keeps the `CI red: E2E` issue, or `CI red: E2E (next)` for `next`, in step with the latest run (see [Tracking issues for unattended runs](#tracking-issues-for-unattended-runs)). A run of the whole suite (mode `all` or `execute`) dispatched on either branch reports too when its `report-status` input is set, as the nightly run of `next` does. Other dispatched runs report nothing, so a run of a few tests cannot close an issue about a test it left out.
- **Concurrency.** A newer push to a pull request cancels its older run, and so does any label added to it: the new run plans and runs the selection again, and the cancelled run still reports a failed `e2e-result` on the same commit. A run on `main` or `next` that has started always finishes, because each one fills the cache for the run after it; GitHub keeps only one waiting run per concurrency group, so a newer push replaces a run that has not started yet. A dispatched run with `report-status` set, such as the nightly run of `next`, waits in a group of its own, as the scheduled run does, so that another dispatched run on its branch cannot replace it.

Every test VM gets 2 cores and 2 GB of memory, 4 GB for graphical nodes (`nix/e2e-tests/lib/vm-config.nix`, `graphical-vm-config.nix`). The size is fixed rather than derived from the runner, so a test evaluates to the same derivation on every host, no build needs `--impure`, and two VMs fit a four-vCPU hosted runner. Every test runs with a 900 s driver timeout unless it declares a longer `globalTimeout`.

The target is that `mode=all` finishes in at most 10 shards and about 20 minutes on hosted runners. In October 2026 one commit ran in both modes on hosted `ubuntu-24.04` runners, with no project cache to substitute from, so every test booted:

- **`all` passed.** The push to `main` and a dispatched run each passed every test except the `performance` group, 58 tests, in 10 shards of 7 to 22 minutes, and took 21 to 26 minutes from plan to result. `nix build` may run as many tests of a shard at once as the runner has vCPUs, four on a hosted runner (the Nix installer sets `max-jobs = auto`).
- **`execute` failed.** The next two nightly runs failed alike: eight of the ten shards reached their job timeouts of 54 to 57 minutes, and `session-nixos-store-gc`, alone in its shard, failed on both attempts, although it passed in both `all` runs. The nightly runs after them failed too. The environment the drivers ran in was at fault, not the tests. Outside the sandbox the driver put the VM disks in the runner's `XDG_RUNTIME_DIR`, a tmpfs in RAM too small for the larger ones: the Nix store image of the nine tests that boot from one (`mkfs.erofs` needs about twice the image's 1.3 GB while it writes it), and most likely also the hidden disk that `session-nixos-store-gc` fills with a NixOS closure. What a failed test left there could fail the next one. The driver of the first runs then waited for the dead VM until the test's timeout ran out, hence the job timeouts; the current one fails such a test within seconds. Once the guests reached the host store over virtiofs, virtiofsd also inherited the job's hard open-file limit of 65,536, which ran out while `session-nixos-store-gc` and `session-nixos-hidden-system` copied a whole NixOS closure; each attempt then waited out its 1,200 s activation deadline. Execute mode now sets up both as a build does (see **Execute mode** above); until a nightly run passes with that, a red nightly run does not mean that `all`, the mode of pushes to `main` and of releases, fails.

### The portable distribution lane

`distro-e2e.yml` exercises the Debian and Ubuntu backend on a non-NixOS host, so regressions there are caught instead of passing unseen. It is informational and gates no merge until promoted; the NixOS `e2e.yml` suite stays NixOS-only.

There used to be a second, per-PR container lane (`distro-smoke` in `ci.yml`). It drove the removed live-overlay lifecycle and could not be ported: a container cannot soft-reboot, so it could not enter or leave a session at all, and the checks it could still make (the binary runs, detection and the pre-flight checks on a stock image) are a subset of what the VM lane runs. It was removed rather than kept as a misleading green check.

#### The VM tests (`distro-e2e.yml`)

`distro-e2e.yml` boots real Debian and Ubuntu cloud images on the NixOS test driver through `numtide/nix-vm-test` (`nix/distro-tests/`).

- **Trigger.** A nightly schedule, a pull request to `main` or `next` that gets the `distro-e2e` label, manual dispatch, and `workflow_call`. The nightly run of `next` is a dispatch from `next-nightly.yml`.
- **Runner.** Each VM needs KVM, so the `runner` input selects where the jobs run (a hosted `ubuntu-26.04` exposes `/dev/kvm`; a self-hosted KVM runner is a label list). The matrix is planned by `python3 -m ci.e2e distro-plan` and kept at or below eight parallel jobs (distributions times their shards).
- **Coverage.** One smoke scenario per distribution (`nix/distro-tests/tests/smoke.nix`): platform detection, the decoy-persistence preflight, activation soft-rebooting the stock cloud image into an overlay of its own root (every hidden write, `/usr` included, lands on the hidden root; the ESP stays read-only), deactivation and emergency soft-rebooting back, and the host-side decoy disk-image leak check with null and positive controls.
- **Adding a distribution** is one entry in `nix/distro-tests/images.nix`; see `nix/e2e-tests/README.md`. The image hashes and the `nix-vm-test` lock are pinned on a networked KVM host, not in the sandbox.
- **Concurrency.** Every label added to a pull request to `main` or `next` starts a run, but only a run for the `distro-e2e` label tests anything. Any other pull request run skips `plan` and the VM jobs and gets a concurrency group of its own, so it can neither cancel the suite nor be cancelled. Adding `distro-e2e` again cancels the pull request's run in progress, and the cancelled run reports nothing: `distro-result` runs only in a run that was not cancelled. A scheduled or dispatched run never cancels a run in progress: it waits for an earlier run of the same event and ref, and since GitHub keeps only one waiting run per group, a newer run replaces one that has not started. A call counts as its caller's event, so call the workflow from a scheduled, dispatched or push-triggered workflow, not from a pull request one.

### Post-merge contract and the red-main rule

Merge queues are not available for a repository owned by a personal account, so the full E2E suite cannot gate the merge itself. A post-merge contract stands in for it:

- Every pull request runs the **affected** E2E selection; the `full-e2e` label forces the whole suite on a pull request before merge when a change is broad.
- Push to `main` runs the whole suite (`all`), substituting unchanged tests from the cache, and the **nightly** run executes every driver from scratch.
- A failed `main` or nightly run opens a `ci-red` tracking issue. **Red-main rule:** revert or quarantine the cause within 24 hours; a failure that is an advisory rather than a regression gets an `advisory` issue triaged within 7 days.

### The integration branch `next`

`next` collects the work for the coming release before it reaches `main`: it starts from `main`, takes pull requests of its own, and returns to `main` in one pull request. Its CI is that of `main`:

- **Pull requests into `next`** run what pull requests into `main` run: `ci.yml` (`gate`), `e2e.yml` (`e2e-result`: the affected selection, or every test with the `full-e2e` label), `pr-title.yml`, the `fuzz` job of `fuzz.yml` when fuzzed code changes, and `distro-e2e.yml` when the `distro-e2e` label is added. The path filters and the affected selection compare a pull request with `next`, its base.
- **Pushes to `next`** run every `ci.yml` job and the whole E2E suite (`all`), as pushes to `main` do. The `rust` job saves the Rust cache for `next`, which the pull requests into it restore, and the E2E jobs push to the binary cache (see [Cache trust rules](#cache-trust-rules)).
- **Nightly.** GitHub runs a schedule only on the default branch, so `next-nightly.yml` on `main` starts the nightly runs of `next`, at 01:23 UTC, ahead of those of `main`: it dispatches `e2e.yml` in `execute` mode with the `report-status` input set, and `distro-e2e.yml`, on `next`. Both run with the workflow files and the code of `next`. Without a branch `next` it starts nothing and passes.
- **Tracking issues.** The unattended runs of `next` keep issues of their own: `CI red: next` for its pushes in `ci.yml`, and `CI red: E2E (next)` for its pushes and nightly runs in `e2e.yml`. `next-nightly.yml` reports a night whose runs it could not start in `CI red: Next nightly`.
- **Not on `next`.** The weekly and monthly tasks of `scheduled.yml`, batch fuzzing and the Scorecard analysis run on `main` only.

## Fuzzing

`fuzz.yml` runs the cargo-fuzz targets in `fuzz/` with [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/): `.clusterfuzzlite/` builds them in OSS-Fuzz's Rust builder image with libFuzzer and the address sanitizer. [testing-strategy.md](testing-strategy.md#fuzzing) lists the targets and what each checks, and how to run one locally.

| Job | Runs on | What it does |
|---|---|---|
| `fuzz` | Pull requests to `main` or `next` that change a crate, `fuzz/`, `.clusterfuzzlite/`, `.dockerignore`, `Cargo.toml`, `rust-toolchain.toml` or the workflow | Builds the targets and fuzzes every one for 300 seconds in all, on every core of the runner (`code-change` mode). A crash or a hang fails the job; its input is in the run's `fuzz-crashes` artifact. |
| `Batch fuzzing` | Daily, and by dispatch | An hour over every target (`batch` mode). A crash or a hang fails the job once every target has had its turn; the inputs are in the run's `fuzz-crashes` artifact. |
| `Report status` | Scheduled and dispatched runs | Keeps the `CI red: Fuzz` issue in step (see [Tracking issues for unattended runs](#tracking-issues-for-unattended-runs)). A red run opens or comments on it. A green run proves little, as every run fuzzes afresh from the seeds, so only the Sunday run and a dispatched one close it. |

- **Not a gate.** `fuzz` is informational, not a required check. ClusterFuzzLite would report only crashes that a build of `main` does not have, but that needs a stored build of `main`, which this workflow does not keep; a crash `main` already has fails a pull request too. The batch run finds those first.
- **From the seeds, every target.** Every run starts from the seed corpora in `fuzz/seeds/` and keeps nothing for the next one: `NO_CLUSTERFUZZ_DEPLOYMENT` turns off ClusterFuzzLite's store, so no job downloads or uploads a corpus, a coverage report or a build. What a run finds beyond the seeds goes with it; a crash's input joins the seeds with its fix ([testing-strategy.md](testing-strategy.md#fuzzing)). In `code-change` mode ClusterFuzzLite skips the targets a change cannot reach, but only with a stored coverage report; `KEEP_UNAFFECTED_FUZZ_TARGETS` has the pull request fuzz every target without looking for one.
- **Trust boundary.** The store is off because it trusts every run in the repository. ClusterFuzzLite's GitHub store picks an artifact by its name alone (`cifuzz-corpus-<target>`, `cifuzz-coverage-latest`, `cifuzz-build-address-<commit>`) from the artifacts of all workflow runs, and a fork's pull request can upload one under such a name from any workflow it changes; under GitHub's default setting only a first-time contributor's run waits for approval. ClusterFuzzLite unpacks the artifact unchecked, as root, in a container that has the Docker socket and the job's runtime token, so a planted file would run in the next scheduled run on `main`, with that run's permissions, and could write to the caches `ci.yml` restores. Keeping a corpus again takes a store that only `main` can write, such as a storage repository (the `storage-repo` input of ClusterFuzzLite's actions) with a fine-grained token held in an environment restricted to `main` and used by the batch run alone.
- **Hangs.** An input that runs past libFuzzer's 25-second timeout, which OSS-Fuzz's images set, fails the job like a crash: `REPORT_TIMEOUTS` makes ClusterFuzzLite report the `timeout-` input it would otherwise drop, once a second run of the input times out too.
- **Results.** A failed run uploads each crashing input, with its stack trace in a `.summary` file beside it, as the `fuzz-crashes` artifact (kept 30 days). `fuzz` also uploads the SARIF of its run to code scanning (category `clusterfuzzlite`, `security-events: write`), where a crash is an alert at the line that crashed; a fork's pull request cannot, as its token is read-only, and its job still fails on a crash or a hang. `Batch fuzzing` uploads none: in `batch` mode ClusterFuzzLite fuzzes on after a crash and writes the SARIF of the last target only, which leaves out a crash in any other target and, uploaded from `main`, would close the alerts of an earlier run.
- **No token.** No step gives ClusterFuzzLite the job's token, which it needs only for its store. It clones the public repository without one, so no token lands in the source that the build and every dependency's build script run in. The runner still gives each container step the job's runtime token, which can write caches.
- **The build.** `.clusterfuzzlite/Dockerfile` starts from `base-builder-rust`, pinned by digest, whose nightly Rust is older than the workspace's Rust version, so it adds the toolchain `rust-toolchain.toml` pins. `build.sh` builds every target with that stable compiler under `RUSTC_BOOTSTRAP=1`, which lets it accept the sanitizer flag, as in `just shuffle`. The targets are release builds with debug assertions and overflow checks, so an arithmetic overflow is a crash. Each one goes to `$OUT` with its seed corpus, its dictionary (`fuzz/dicts/`) and its libFuzzer options (`fuzz/options/`). `.dockerignore` lets only what the build reads into the image: the manifests and `Cargo.lock`, the toolchain pin, `.cargo/`, the crates, `fuzz/` without its working directories and `.clusterfuzzlite/`; no `.git` and no `target/`.
- **Pins.** The steps run ClusterFuzzLite's images, `clusterfuzzlite-build-fuzzers` and `clusterfuzzlite-run-fuzzers`, pinned by digest, and set the environment that its `build_fuzzers` and `run_fuzzers` actions set from their inputs. The actions themselves are not used: even pinned to the commit of their `v1` tag, ClusterFuzzLite's only release, they run whatever image Google last built from OSS-Fuzz under the `v1` tag. Dependabot does not read `docker://` references, so the digests change by hand: `docker pull gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1` (and `-run-fuzzers`) prints the current digest; read what changed in OSS-Fuzz's `infra/` since the pinned image was built, then replace both digests in `fuzz.yml`.
- **Settings.** None. Code scanning takes the SARIF of a public repository without setup, and each job asks for the permissions it needs.

## Pinned-input and dependency automation

Dependabot (`.github/dependabot.yml`) keeps the Cargo workspace, the GitHub Actions in the workflows, the Nix inputs in `flake.lock`, the pre-commit hook revisions, `rust-toolchain.toml`, the fuzz crate's `fuzz/Cargo.lock` and the digest of the fuzzing build image in `.clusterfuzzlite/Dockerfile` current (but not the two ClusterFuzzLite images in `fuzz.yml`, which are `docker://` references; see [Fuzzing](#fuzzing)): monthly, after a 7-day cooldown, grouped into one pull request per ecosystem with the security updates kept separate, titled `build(deps):` / `ci(deps):` so the commit-msg hook and `pr-title.yml` accept them. `rust-toolchain.toml` and the `rust-overlay` input share one pull request (a multi-ecosystem group), because the flake builds the pinned toolchain from `rust-overlay`: a new channel only evaluates with an overlay that knows it. The cooldown holds back only the overlay, since Dependabot finds no publication date for a Rust release, so a release from the last seven days can arrive without the overlay commit that added it. Every Nix job of that pull request then stops at evaluation with `attribute '"<version>"' missing`; `nix flake update rust-overlay` on its branch fixes it.

`fuzz/Cargo.lock` should hold the versions of `Cargo.lock` for the crates the fuzz crate shares with the workspace, so that the fuzzers test what ships. Dependabot's monthly update can move them apart; `just fuzz-lock` rewrites the fuzz lock from `Cargo.lock`, and every version bump runs it ([RELEASING.md](../RELEASING.md)).

Cargo.lock's transitive dependencies, which no Dependabot update touches, are refreshed by the `lockfile` task of `scheduled.yml` on the first of the month: `cargo update` moves every dependency to its newest allowed version. A pull request opened under the default `GITHUB_TOKEN` does not start CI, so the task opens it under the `DEPENDENCY_UPDATE_TOKEN` secret (scoped to the `dependency-updates` environment) when it is set and prints the diff otherwise.

## OpenSSF Scorecard

`scorecard.yml` runs [OpenSSF Scorecard](https://scorecard.dev), which grades the repository's supply-chain practices from 0 to 10 per check: pinned dependencies, token permissions, dangerous workflow patterns, branch protection, code review, dependency update tooling, signed releases and known vulnerabilities, among others. It reads `main` through the GitHub API, builds and runs nothing, and gates no merge.

- **Triggers.** Every push to `main`, weekly, a change to a branch protection rule, and manual dispatch. GitHub has no workflow trigger for rulesets, which protect `main` here, so a ruleset change shows in the next run. Only the default branch can publish, and the action fails a run on any other branch, so dispatch it from `main`.
- **Results.** Each run publishes its signed result to the Scorecard API (`api.scorecard.dev`), and the README badge and the [scorecard.dev viewer](https://scorecard.dev/viewer/?uri=github.com/WitteShadovv/nails) show the latest one to everyone. The SARIF goes to code scanning (the Security and quality tab, then Code scanning), where a check that scores below the action's default policy, 10 for most checks, is an alert with its remediation; only people with write access see those alerts. The `scorecard-sarif` artifact keeps the SARIF of a run for 5 days.
- **Permissions.** The top level stays at `contents: read`, and the Scorecard job adds two write permissions. `id-token: write` lets it sign the result through Sigstore with its OIDC identity: the Scorecard API accepts a result only with that signature, whose certificate names the repository, branch, commit and workflow file of the run. `security-events: write` lets it upload the SARIF to code scanning. No secret is needed; the default token reads a public repository, rulesets included.
- **Publishing rules.** Before it stores a result, the Scorecard API reads the workflow file at the analysed commit and rejects the result unless the file keeps to the [workflow restrictions](https://github.com/ossf/scorecard-action#workflow-restrictions): no top-level `env`, `defaults` or write permission, and `id-token: write` only in the Scorecard job; in that job no `env`, `defaults`, container or services, an Ubuntu hosted runner, and only steps that use `actions/checkout`, `actions/upload-artifact`, `github/codeql-action/upload-sarif`, `ossf/scorecard-action` or `step-security/harden-runner`, where a pinned SHA must be a commit of the action's own repository. This is why `scorecard.yml` has no top-level `defaults: run: shell: bash`, unlike the workflows with `run:` steps, and its Scorecard job must not gain a `run:` step. A result the API rejects does not fail the run: the action logs a warning annotation, `Unable to POST scorecard results to webapp`, with the API's reason, and the badge keeps the last accepted score. After a change to `scorecard.yml`, check the next run's annotations and the badge.
- **Unattended runs.** Every run on `main` ends in a `report-status` job, which keeps the `CI red: Scorecard` issue in step with the latest run (see [Tracking issues for unattended runs](#tracking-issues-for-unattended-runs)): a failed analysis, signature or upload opens it; a rejected result does not. A dispatch from another branch fails by design and reports nothing. Of the publishing rules, only one applies to this job: it must never get `id-token: write`.

## Nix setup and binary cache

Every workflow that needs Nix uses the composite action `.github/actions/setup-nix`. The installer (`cachix/install-nix-action`) is pinned there once, Dependabot keeps that pin current, and every job gets the same `nix.conf`: KVM, `system-features = nixos-test benchmark big-parallel kvm`, `always-allow-substitutes = true` and `accept-flake-config = false`.

The action also connects the project's public Cachix cache, [`nails`](https://nails.cachix.org).

### Cache trust rules

- **Reads.** The cache is added as an extra substituter next to cache.nixos.org. Its signing key is pinned in `action.yml`, so no substitute is trusted on first use. Every job reads it unless it sets `cache: 'false'`, including fork pull requests.
- **Pushes.** A job pushes only when it runs for a trusted event and receives `CACHIX_AUTH_TOKEN`. The trusted events are pushes to `main` and `next`, scheduled runs, manual dispatches and pull requests from a branch of this repository. Fork pull requests and every other event stay read-only. The decision lives in `.github/actions/setup-nix/cache_plan.py` and is tested in `scripts/tests/test_setup_nix_cache_plan.py`.
- **What is pushed.** The cachix daemon uploads each path as soon as Nix builds it, so a cancelled run keeps its finished work. A push filter limits uploads to three name prefixes:
  - `nails-*`: the binary that every VM test embeds;
  - `rust-default-*`: the Rust toolchain, whose closure holds its components;
  - `vm-test-run-*`: passed VM tests, which later runs fetch instead of booting the test again.

  `nails-release-*` is never pushed. Each path goes up with its closure, except what cache.nixos.org already serves. To push more, add a prefix to `PUSH_ALLOW` in `cache_plan.py`.
- **Who gets the token.** Only `e2e.yml` (also when `release.yml` calls it), the `plan` and `distro` jobs of `distro-e2e.yml` and the `nix-build` job of `ci.yml` pass it. GitHub withholds secrets from fork pull requests and from the runs Dependabot starts itself, so those stay read-only too. A run that a person starts on a Dependabot pull request, by adding a label or pushing to it, does get the token and may push, because the branch is in this repository; review the bumped versions before doing either.
- **Release builds.** The `build` job of `release.yml` and `reproducibility.yml` set `cache: 'false'` and never read the project cache. `nails` is therefore compiled from source in every release and rebuild job, and nothing from the cache can end up in a release. The release's E2E run reads the cache like any other E2E run; it gates the release but produces none of its files.
- **Trust boundary.** Anyone who can push a branch to this repository can push to the cache: once a run has configured the token, the code under test can read it. Write access already implies that trust, and release artifacts never come from the cache.

Workflows load the action from the checked-out tree, so a run needs a revision that already contains it; rebase older pull requests before running them.

### Setting up the cache

The cache is set up. With an empty `CACHIX_NAME` and `CACHIX_PUBLIC_KEY`, the action logs `no project cache is configured` and jobs use cache.nixos.org only. To set up a cache again, for example for a fork:

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
| `sbom` | `version` | `cargo cyclonedx` (a checked binary from `taiki-e/install-action`) describes the `nails` binary for `x86_64-unknown-linux-musl`, without build-time dependencies. `python3 -m ci.release sbom-libc` adds the statically linked musl, `python3 -m ci.release sbom-check` checks that `actions/attest` accepts the result (at most 16 MiB, with a `bomFormat`, a `serialNumber` and a `specVersion`), and `cyclonedx validate --fail-on-errors` checks it against CycloneDX 1.5. The job needs no build and the E2E suite waits for it, so an SBOM that the `attest` job would refuse stops the run within minutes, before the suite and before anything is attested. The commit time as `SOURCE_DATE_EPOCH` keeps the SBOM reproducible, and with it cargo-cyclonedx leaves out its random serial number, which `actions/attest` requires; `sbom-libc` sets a UUIDv5 of the SBOM's download URL on the release instead, the same on every run for the tag. The job reads the musl version from `.#nails.libc`, the musl of the pinned nixpkgs: the release build links it instead of the copy that ships with the Rust toolchain, and fails if its linker map shows libc.a or one of musl's crt files (crt1.o, rcrt1.o, Scrt1.o, crti.o, crtn.o) from anywhere else. The link's crtbeginS.o and crtendS.o are GCC's own, from the musl C toolchain of nixpkgs that links the release build. It also collects the CVE IDs in the names of nixpkgs' musl patches, and `sbom-libc --musl-cve` records each as a backported fix in the musl component's `pedigree`. The musl component carries a CPE, so scanners match it; they ignore `pedigree`, so `python3 -m ci.release musl-vex` also writes `musl.openvex.json`, which marks those CVEs as fixed in musl (`grype --vex`). |
| `e2e` | `sbom` | Calls `e2e.yml` with mode `all` on the tagged commit. A dispatch can pick the runner with `e2e-runner` and `e2e-max-shards`. |
| `attest` | all of the above | `actions/attest` signs build provenance for the subjects of `checksums.txt` (the archive and the binary), a second attestation binds the SBOM to them, and a third the VEX document. Nothing is attested before every gate passed. |
| `draft-release` | `attest` | `gh release create --draft --verify-tag` with the five assets, marked as a prerelease for an `X.Y.Z-rc.N` version. An existing release is never modified. |
| `report-status` | every job | Keeps the `CI red: Release` issue in step (see [Tracking issues for unattended runs](#tracking-issues-for-unattended-runs)). |

- **Provenance level.** GitHub artifact attestations are SLSA v1.0 Build Level 2: signed provenance from a hosted build platform. The build does not run in an isolated reusable workflow, so the project does not claim Build Level 3. There is no provenance file among the assets; `gh attestation verify` fetches the attestation from GitHub.
- **Reproducibility.** The cross-runner comparison of `rebuild` is the evidence that the binary is reproducible. `nix-store --realise --check` is not used: it repeats only the archive packaging, on the same runner and with the same compiled binary. `scheduled.yml` runs `reproducibility.yml` every week on `main` with two independent builds, so a regression shows up before a release does.
- **Concurrency.** Runs for the same tag queue in the group `release-<tag>`; none cancels another.
- **Assets.** `nails`, `nails-<version>-x86_64-unknown-linux-musl.tar.gz`, `checksums.txt`, `sbom.cdx.json` and `musl.openvex.json`.

## Verifying a release

[verify-release.md](verify-release.md) is the single description of how users check a release: `sha256sum --check --ignore-missing checksums.txt`, `gh attestation verify`, and where to do it. [release-artifact-reproducibility.md](release-artifact-reproducibility.md) explains how to rebuild the bundle and compare it with a release.

## Where every old job went

The pre-overhaul layout had 14 workflows and about 38 jobs; the mapping below says where each went.

| Old workflow or job | Now |
|---|---|
| `ci.yml` with a `schedule:` and a `CI Success` aggregate | `ci.yml` is PR/push only, summarised by `gate`; the schedule moved to `scheduled.yml`. |
| `nix-pr-verify.yml` | Folded into the `nix-build` and `lint-misc` jobs of `ci.yml`. |
| `e2e-tests.yml` (dev-branch smoke) | `e2e.yml` in `affected` mode on every pull request. |
| `e2e-tests-full.yml`, `e2e-tests-full-shard.yml` (`pull_request_target` + `hetzner-pr`) | `e2e.yml` in `all` mode (push, label, nightly). The Hetzner runners are gone: Hetzner Cloud servers offer no KVM, which the VM tests need. |
| The five standalone disk-forensics workflows | Removed; the decoy disk-image checks are now ordinary tests in the E2E suite's `forensic` group. |
| `release.yml` (verify) + `publish-release.yml` + `release-core.yml` | One `release.yml` on the tag: build, rebuild, E2E, SBOM, attest, draft. |
| `reproducibility.yml` with duplicated inputs | `reproducibility.yml` declares its inputs once (`workflow_call`) and also runs weekly from `scheduled.yml`. |
| `update-flake-lock.yml` | Dependabot's `nix` and `pre-commit` ecosystems (`.github/dependabot.yml`). |
| Benchmarks and cargo-geiger in a PR job | `scheduled.yml` benchmarks (alerts, not budgets); geiger replaced by the compile-time `unsafe_code = "deny"` lint. |

## Local commands that mirror CI

The `justfile` is the single source of these commands; `just --list` shows them all. The `nix develop` shell provides every tool they need and installs the git hooks on first entry.

```bash
just check        # formatting, clippy, file sizes and the tests (the pre-push gate)
just ci-rust      # everything the ci.yml Rust jobs run, including coverage
just coverage     # line coverage; the threshold is defined only in .config/coverage.toml
just line-count   # the Rust file size check alone
just deny         # dependency policy over the shipped graph
just deny-full    # the full-graph policy scan scheduled.yml runs weekly
just nix-lint     # nixfmt, deadnix and statix over the tracked Nix files
just docs-check   # docs/ci.md lists every workflow
just kernel-tests # the real-kernel tests in a user namespace; fails instead of skipping
just shuffle      # the unit tests threaded and shuffled over twenty seeds
just stress       # threaded, single-thread and shuffled runs to surface flaky tests
just e2e ci       # build one E2E target or group
nix flake check   # what the lint-misc job runs: the Nix, shell and workflow linters
nix build -L .#nails-release -o result --option accept-flake-config false
```

A commit runs only the fast, offline pre-commit hooks (formatting, Rust file sizes, file and secret checks); `just check` runs on push through the pre-push hook. See [CONTRIBUTING.md](../CONTRIBUTING.md#testing) for the per-tier test commands, runtimes and prerequisites.

## Maintainer settings checklist

GitHub settings that the workflows assume but cannot set themselves:

- **Required checks.** The `main` branch ruleset requires `gate` (from `ci.yml`), `e2e-result` (from `e2e.yml`) and `pr-title` (from `pr-title.yml`). Make `e2e-result` required only after it has been green for about two weeks.
- **`next`.** While the integration branch exists, a ruleset of its own targets `next`: it requires the same checks as the ruleset for `main` and blocks deletion, and only maintainers may force-push, to rebase `next` onto `main`.
- **Tag ruleset.** Protect `v*` tags to annotated tags only, and enable immutable releases.
- **Environments.** `dependency-updates` holds `DEPENDENCY_UPDATE_TOKEN` and needs no required reviewers. The `hetzner-pr` and `hetzner` environments are no longer used: delete them, with the `hetzner` environment's secrets `HCLOUD_TOKEN`, `HCLOUD_SSH_KEY_ID` and `RUNNER_REGISTRATION`.
- **Secrets.** `CACHIX_AUTH_TOKEN` as an Actions secret (see [Setting up the cache](#setting-up-the-cache)); never add it as a Dependabot secret.
- **Schedules.** GitHub disables a workflow's schedule after 60 days without repository activity; a quiet period needs a manual dispatch of `scheduled.yml` (or any push) to re-arm it.

## Secrets and permissions

- `CACHIX_AUTH_TOKEN` is optional. With it, `e2e.yml`, the `plan` and `distro` jobs of `distro-e2e.yml` and the `nix-build` job of `ci.yml` push build results to the project binary cache for trusted events (see [Nix setup and binary cache](#nix-setup-and-binary-cache)). Store it as an Actions secret only.
- `DEPENDENCY_UPDATE_TOKEN` is optional and used only by the Cargo.lock refresh in `scheduled.yml`, so the pull request it opens starts CI. Without it the job prints the diff to the run summary.
- No E2E lane needs any other secret. The retired `hetzner-pr` approval environment and the `hetzner` environment with its secrets (`HCLOUD_TOKEN`, `HCLOUD_SSH_KEY_ID`, `RUNNER_REGISTRATION`) are no longer used and can be deleted.
- `next-nightly.yml` needs no secret: its `dispatch` job starts the runs of `next` with the job's own token, which gets `actions: write` for that.
- Release attestations are signed with the `attest` job's OIDC identity (`id-token: write`); no long-lived signing secret exists.
- `scorecard.yml` needs no secret either: its Scorecard job signs the result it publishes with its OIDC identity (`id-token: write`) and uploads the SARIF to code scanning with `security-events: write` (see [OpenSSF Scorecard](#openssf-scorecard)).

## Operational caveats

- Workflow artifacts are useful for maintainers and contributors, but the **public distribution channel is the published GitHub release**, drafted by `release.yml` from a validated tag.
- A release run only drafts; a maintainer publishes the draft after reviewing it.
- E2E validation is a separate workflow with its own required check, `e2e-result`; it is not aggregated into `gate`.

## Related documents

- [CONTRIBUTING.md](../CONTRIBUTING.md#testing)
- [SECURITY.md](../SECURITY.md)
- [docs/security-validation.md](security-validation.md)
- [docs/verify-release.md](verify-release.md)
- [docs/release-artifact-reproducibility.md](release-artifact-reproducibility.md)
