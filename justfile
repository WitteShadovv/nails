# Task runner shared by local development and CI; `just` lists the recipes.
# The tools come from the flake dev shell (`nix develop`). Every cargo call
# passes `--locked` so a stale Cargo.lock fails here exactly as it does in CI.
# The line-coverage floor lives in `.config/coverage.toml` and nowhere else, and
# that of the gui/ workspace in gui/.config/coverage.toml: the `coverage` recipe
# reads the number from there, CI calls `just coverage` and `just side-tests`,
# and local runs reach the same numbers through `ci-rust`.

[private]
default:
    @{{ just_executable() }} --list --justfile {{ justfile() }}

# The crates that can end up in a release binary: the x86_64 Linux targets
# without dev-dependencies. Crates that only build for other platforms (wasm,
# Windows, macOS) or only for tests and benchmarks never ship.

shipped_targets := "x86_64-unknown-linux-musl x86_64-unknown-linux-gnu"

# The gui/ workspace's cargo-deny policy, which the recipes name with --config:
# without it, cargo-deny takes the deny.toml nearest to gui/Cargo.toml, which
# is the main one if this file goes missing, and the gui/ graph would pass the
# main policy unnoticed. The path is absolute, so it does not depend on what
# cargo-deny resolves a relative one against.

gui_deny_config := justfile_directory() / "gui" / "deny.toml"

# --- Rust quality gate ---

# Check formatting without rewriting files: the workspace, then the fuzz, setup
# and gui crates, each a workspace of its own.
fmt-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path fuzz/Cargo.toml -- --check
    cargo fmt --manifest-path setup/Cargo.toml -- --check
    cargo fmt --manifest-path gui/Cargo.toml -- --check

# Clippy over every target and feature, with warnings denied; the setup and gui
# crates, workspaces of their own, too.
lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo clippy --manifest-path setup/Cargo.toml --all-targets --all-features --locked -- -D warnings
    cargo clippy --manifest-path gui/Cargo.toml --all-targets --all-features --locked -- -D warnings

# Rust file size limits; the pre-commit hook and CI run the same script.
line-count:
    ./scripts/check-line-count.sh

# Every Rust file of the crates, the side workspaces and the fuzz crate is a
# crate root or declared as a module: a file that is neither compiles for
# nobody and escapes clippy and the tests unseen.
orphan-modules:
    ./scripts/check-orphan-modules.sh

# Fail on a Cargo.lock or fuzz/Cargo.lock that does not match the manifests,
# before anything is built. No other check builds the fuzz crate, a workspace
# of its own, so none of them would see its lock go stale; `just fuzz-lock`
# rewrites it.
lock-check:
    cargo metadata --locked --format-version 1 > /dev/null
    cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null

# Run the unit and integration suite through nextest; the setup and gui crates
# too.
test:
    cargo nextest run --workspace --all-features --locked --no-fail-fast
    cargo nextest run --manifest-path setup/Cargo.toml --all-features --locked --no-fail-fast
    cargo nextest run --manifest-path gui/Cargo.toml --all-features --locked --no-fail-fast

# Long property-based run of the parser tests (the `fuzz_` proptests): the
# same properties `test` runs with the default case count, here with `cases`
# generated inputs each. A failure prints the minimal input that breaks it.
fuzz cases="100000":
    PROPTEST_CASES={{ cases }} cargo test -p nails-core --lib --locked --release -- fuzz_

# Run one cargo-fuzz target of fuzz/ (`just fuzz-run mountinfo 600`) built as
# CI builds it: release, with debug assertions, overflow checks and the address
# sanitizer. The pinned stable compiler accepts cargo-fuzz's sanitizer flag under
# RUSTC_BOOTSTRAP. It starts from the target's seeds and dictionary; new inputs
# collect in fuzz/corpus/, a crash in fuzz/artifacts/. An input that runs longer
# than 25 seconds is a hang, as in CI.
fuzz-run target seconds="60":
    #!/usr/bin/env bash
    set -euo pipefail
    # cargo fuzz has no --locked: refuse a stale fuzz/Cargo.lock instead of
    # letting the build rewrite it (`just fuzz-lock` does that on purpose).
    cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null
    mkdir -p fuzz/corpus/{{ target }}
    args=(-max_total_time={{ seconds }} -timeout=25)
    if [ -f fuzz/dicts/{{ target }}.dict ]; then
        args+=(-dict=fuzz/dicts/{{ target }}.dict)
    fi
    options=fuzz/options/{{ target }}.options
    if [ -f "$options" ]; then
        args+=("-max_len=$(sed -n 's/^max_len = //p' "$options")")
    fi
    RUSTC_BOOTSTRAP=1 cargo fuzz run --release --debug-assertions {{ target }} \
        fuzz/corpus/{{ target }} fuzz/seeds/{{ target }} -- "${args[@]}"

# Rewrite fuzz/Cargo.lock from Cargo.lock. The fuzz crate is a workspace of its
# own with its own lock, but the crates it shares with NAILS should be the
# versions that ship: cargo keeps those, adds what only the fuzz crate uses and
# drops the rest. A version bump leaves fuzz/Cargo.lock stale, so RELEASING.md
# runs this with every bump; CI fails on a stale one.
fuzz-lock:
    cp Cargo.lock fuzz/Cargo.lock
    cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null

# The mechanical half of the rule that every parser of bytes NAILS does not
# control gets a fuzz target (docs/testing-strategy.md), part of `just check`
# and of CI's lint job: every fuzz target is wired into fuzz/Cargo.toml, is
# more than the stub `new-fuzz-target` writes and has a non-empty seed.
fuzz-targets:
    ./scripts/check-fuzz-targets.sh

# Scaffold a new fuzz target: a stub under fuzz/fuzz_targets/, an empty starter
# seed and the [[bin]] entry in fuzz/Cargo.toml, so adding one for a new parser
# is mechanical. Fill in the target, replace the starter seed with inputs from
# the parser's fixtures and tests, and run `just fuzz-lock`; `fuzz-targets`
# fails until the stub and the starter seed are replaced.
new-fuzz-target name:
    #!/usr/bin/env bash
    set -euo pipefail
    target="fuzz/fuzz_targets/{{ name }}.rs"
    if [ -e "$target" ]; then
        echo "$target already exists" >&2
        exit 1
    fi
    cat > "$target" <<'EOF'
    // SPDX-FileCopyrightText: 2025-2026 WitteShadovv
    // SPDX-License-Identifier: GPL-3.0-or-later

    //! TODO: the parser this drives, and the property it checks beyond that
    //! the code neither panics nor hangs on hostile input.

    #![no_main]

    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        // TODO: drive the parser with `data` and assert its invariants.
        let _ = data;
    });
    EOF
    mkdir -p "fuzz/seeds/{{ name }}"
    printf '' > "fuzz/seeds/{{ name }}/empty"
    {
        echo
        echo '[[bin]]'
        echo 'name = "{{ name }}"'
        echo 'path = "fuzz_targets/{{ name }}.rs"'
        echo 'test = false'
        echo 'doc = false'
        echo 'bench = false'
    } >> fuzz/Cargo.toml
    echo "Scaffolded the fuzz target '{{ name }}'. Next: implement it, replace"
    echo "fuzz/seeds/{{ name }}/empty with real inputs, and run 'just fuzz-lock'."

# Run the documentation tests, which nextest does not execute.
doctest:
    cargo test --doc --workspace --all-features --locked

# Run the tests of the side workspaces alone, each a workspace of its own whose
# tests `test` runs too: those of setup/, and those of gui/ under line coverage,
# held to the floor in gui/.config/coverage.toml (`coverage gui`). CI's
# side-tests job runs this. Only the root workspace has a .config/nextest.toml,
# so these runs name nextest's default profile, also where NEXTEST_PROFILE
# selects `ci`.
side-tests: (coverage "gui")
    cargo nextest run --manifest-path setup/Cargo.toml --profile default --all-features --locked --no-fail-fast

# Prove the unit tests do not depend on execution order. No test mutates the
# shared process environment (they inject a RuntimeEnv instead), and a leak
# through any remaining shared state surfaces only under a threaded, shuffled
# run; nextest isolates each test in its own process and would hide it. Hence
# libtest, not nextest, and `--lib`, where most unit tests live. The
# `--shuffle-seed` flag is unstable, so the stable test harness is told to
# accept it with RUSTC_BOOTSTRAP rather than adding a nightly toolchain. A
# cargo runner sets it for the test binaries alone: the build scripts of
# proc-macro2 and others look for nightly features when it is set, so a build
# that saw it would rebuild them and every crate above them, here and again in
# the next build without it, such as `just test`.
shuffle seeds="20":
    #!/usr/bin/env bash
    set -euo pipefail
    runner="target.'cfg(all())'.runner = ['env', 'RUSTC_BOOTSTRAP=1']"
    for seed in $(seq 1 {{ seeds }}); do
        echo "shuffle seed $seed"
        cargo test --config "$runner" --workspace --all-features --locked --lib \
            -- -Z unstable-options --shuffle-seed "$seed"
    done

# Line coverage over nextest, measuring production code only; fails below the
# floor in the measured workspace's .config/coverage.toml. `just coverage`
# measures the root workspace against .config/coverage.toml, `just coverage
# gui` the gui/ workspace against gui/.config/coverage.toml.
coverage workspace=".":
    #!/usr/bin/env bash
    set -euo pipefail
    # The floor, the profile data and the reports are the measured workspace's,
    # and the messages name it from the repository root.
    cd '{{ workspace }}'
    name='{{ if workspace == "." { "" } else { workspace + "/" } }}'
    # The single source of truth for the floor: read it here and nowhere else.
    threshold=$(sed -n 's/^[[:space:]]*line_threshold[[:space:]]*=[[:space:]]*//p' \
        .config/coverage.toml | tr -d ' "')
    if [ -z "$threshold" ]; then
        echo "No line_threshold in ${name}.config/coverage.toml" >&2
        exit 1
    fi
    # Only the root workspace has a .config/nextest.toml; another one runs
    # nextest's default profile, also where NEXTEST_PROFILE selects `ci`.
    if [ ! -f .config/nextest.toml ]; then
        export NEXTEST_PROFILE=default
    fi
    # Test infrastructure never ships, so it must not count toward the figure:
    # every test file (inline `tests.rs`, `*_tests.rs`, the `tests/`
    # integration trees and the benches) and, in the root workspace, the
    # in-memory filesystem mock, the shared test fixtures and the platform test
    # doubles. Keeping them out of the report is what makes this number
    # production-only; the names of the root's test doubles are left out only
    # there, so a production file of another workspace that bears one counts.
    ignore='/tests/|/tests\.rs$|_tests\.rs$|/benches/'
    if [ '{{ workspace }}' = . ]; then
        ignore+='|/mock/|/test_support|/fake\.rs$|/contract\.rs$|/config/testing\.rs$'
    fi
    ignore="($ignore)"
    # Every report lands under target/coverage, so nothing is written outside
    # the build directory. In CI the percentage also goes to the job summary.
    out=target/coverage
    mkdir -p "$out"
    # Start from no profile data: old runs leave profiles behind (some of files
    # since deleted) that would shift a local figure away from CI's clean one.
    cargo llvm-cov clean --workspace
    cargo llvm-cov --no-report nextest --workspace --all-features --locked
    cargo llvm-cov report --ignore-filename-regex "$ignore" --cobertura --output-path "$out/cobertura.xml"
    cargo llvm-cov report --ignore-filename-regex "$ignore" --lcov --output-path "$out/lcov.info"
    cargo llvm-cov report --ignore-filename-regex "$ignore" --html --output-dir "$out/html"
    # The root <coverage> element carries the overall rate. -m1 stops at it:
    # piping thousands of per-file matches into `head` kills grep with SIGPIPE,
    # which pipefail turns into a failed recipe.
    rate=$(grep -m1 -oP '<coverage [^>]*line-rate="\K[0-9.]+' "$out/cobertura.xml") || {
        echo "No line-rate in ${name}$out/cobertura.xml" >&2
        exit 1
    }
    pct=$(awk "BEGIN { printf \"%.2f\", ${rate} * 100 }")
    summary="Line coverage${name:+ of $name}: ${pct}% (threshold ${threshold}%)"
    echo "$summary"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "$summary" >> "$GITHUB_STEP_SUMMARY"
    fi
    awk "BEGIN { exit !(${pct} >= ${threshold}) }" || {
        echo "Coverage ${pct}% is below the ${threshold}% threshold${name:+ of $name}" >&2
        exit 1
    }

# --- Real-kernel tests ---

# The tests that ask the kernel directly from an unprivileged user + mount
# namespace (overlay mount ids and st_dev, live mountinfo, fdinfo, strictatime,
# a real broken pipe, the mount contract, the rootless privileged_mounts tests,
# the CLI's write paths on a tmpfs hidden root and the way back's network
# restore in a network namespace; see docs/testing-strategy.md). They run in
# `just test` too, where a host without user namespaces skips them; here a skip
# fails.
kernel-tests:
    NAILS_REQUIRE_USERNS=1 cargo nextest run --workspace --all-features --locked \
        -E 'test(/kernel_tests::|test_support::/) | binary(kernel_semantics) | binary(broken_pipe) | binary(filesystem_contract) | binary(privileged_mounts) | binary(maintenance_cli) | binary(network_way_back_kernel)'

# The pre-push gate: formatting, lints, file sizes, fuzz-target wiring, the
# test suite and a three-seed shuffle sweep, which runs the build `test` made.
check: fmt-check lint line-count fuzz-targets test (shuffle "3")

# The commands of the ci.yml jobs lint, rust, shuffle and side-tests, for
# reproducing them locally, with three shuffle seeds where CI runs twenty. Left
# out are the privileged-mounts job, whose tests need root, and what the jobs
# set around the commands: CI fails a real-kernel test that would skip, as
# `just kernel-tests` does, and a test run that leaves a file in TMPDIR. The
# deps and gui-vet jobs run `just deny` and `just vet gui`.
ci-rust: lock-check fmt-check lint line-count fuzz-targets orphan-modules coverage doctest side-tests (shuffle "3")

# --- Dependency policy ---

# Check the shipped dependency graph against deny.toml (the CI merge gate), and
# the gui/ workspace's graph at the same scope against gui/deny.toml. One run
# per target: cargo-deny 0.20 accepts `--target` only once (fixed upstream
# after 0.20.2), and the targets' graphs together are the shipped one.
deny *checks="advisories bans licenses sources":
    #!/usr/bin/env bash
    set -euo pipefail
    for target in {{ shipped_targets }}; do
        cargo deny --locked --exclude-dev --target "$target" check {{ checks }}
        cargo deny --manifest-path gui/Cargo.toml --config '{{ gui_deny_config }}' \
            --locked --exclude-dev --target "$target" check {{ checks }}
    done

# Check every target and dev-dependency against deny.toml, and those of the
# gui/ workspace against gui/deny.toml (weekly, never gates).
deny-full *checks="advisories bans licenses sources":
    cargo deny --locked check {{ checks }}
    cargo deny --manifest-path gui/Cargo.toml --config '{{ gui_deny_config }}' --locked check {{ checks }}

# Audit a workspace's dependency graph against its recorded supply-chain
# reviews (cargo-vet): every third-party crate must be covered by an imported
# public audit or a recorded exemption under the workspace's supply-chain/.
# --locked uses the committed supply-chain/imports.lock, so the result does not
# drift with an upstream audit update between runs. `just vet` audits the root
# workspace, advisory only: it runs in its own lane (vet.yml) and never gates a
# merge. `just vet gui` audits the gui/ workspace against gui/supply-chain/,
# and the gui-vet job of ci.yml gates the merge on it.
vet workspace=".":
    cargo vet --locked --manifest-path '{{ workspace }}/Cargo.toml'

# --- Nix ---

# Format-check and lint every tracked Nix file, the way the hooks and flake do.
nix-lint:
    #!/usr/bin/env bash
    set -euo pipefail
    mapfile -t files < <(git ls-files '*.nix' ':!:*hardware-configuration.nix')
    if [ ${#files[@]} -eq 0 ]; then
        echo "no Nix files to check"
        exit 0
    fi
    nixfmt --check "${files[@]}"
    deadnix --fail "${files[@]}"
    for file in "${files[@]}"; do
        statix check "$file"
    done

# --- End-to-end ---

# Build one E2E target: a leaf test or a group (defaults to the CI group).
e2e target="ci":
    ./scripts/run-e2e-tests.sh run {{ target }}

# Run E2E tests locally with bounded parallelism: evaluate 4 tests per nix eval
# process (caps evaluation memory), then build by derivation with as many VMs
# as the host's RAM allows (3 on a 15 GiB host). Failed logs go to ./e2e-logs.
e2e-local target="all" jobs="auto":
    ./scripts/run-e2e-tests.sh run --jobs {{ jobs }} --eval-batch 4 --log-dir e2e-logs --durations-out e2e-logs/durations.jsonl {{ target }}

# Flag fixed sleeps, console-regex waits, /tmp captures and unbounded
# power-off waits in the E2E tests (CI's lint-misc runs the same check).
e2e-sync-lint:
    python3 -m ci.e2e_sync_lint

# Open the interactive driver of one E2E leaf test.
e2e-debug name:
    ./scripts/run-e2e-tests.sh interactive {{ name }}

# --- Python ---

# The ci/ package's unittest suite, ruff and mypy (CI's `ci-python` check).
ci-python:
    python3 -m unittest discover -s ci/tests -t .
    ruff check ci
    mypy ci

# The host-side disk-image forensics parsers and their unit tests (CI's
# `e2e-disk-forensics` check). No VM, no root; runs against captured fixtures.
e2e-disk-forensics:
    python3 -m unittest discover -s nix/e2e-tests/lib/tests -t nix/e2e-tests/lib
    ruff check nix/e2e-tests/lib
    mypy nix/e2e-tests/lib/disk_forensics.py nix/e2e-tests/lib/tests/test_disk_forensics.py

# --- Docs ---

# Fail when docs/ci.md does not list every workflow (and no stale one).
docs-check:
    python3 ci/docs_check.py

# --- Flaky-test detection ---

# Surface flaky, order- or timing-dependent tests (set SHUFFLE_SEED to replay).
stress iterations="10":
    #!/usr/bin/env bash
    set -euo pipefail

    # Run the suite threaded, then single-threaded, then shuffled with a printed
    # seed, then repeated through nextest with no retries so one failure in any
    # pass fails the run. SHUFFLE_SEED reproduces a reported ordering.
    echo "== threaded run =="
    cargo test --workspace --all-features --locked

    echo "== single-thread run =="
    cargo test --workspace --all-features --locked -- --test-threads=1

    seed="${SHUFFLE_SEED:-$(( (RANDOM << 15) | RANDOM ))}"
    echo "== shuffled run (seed ${seed}) =="
    # The stable harness accepts the unstable shuffle options under
    # RUSTC_BOOTSTRAP; the explicit seed lets a failure be replayed.
    RUSTC_BOOTSTRAP=1 cargo test --workspace --all-features --locked -- \
        -Z unstable-options --shuffle-seed "${seed}"

    echo "== nextest repeat loop ({{ iterations }}x, no retries) =="
    # With no retries, a single failure in any iteration fails the run.
    for i in $(seq 1 {{ iterations }}); do
        echo "stress iteration ${i}/{{ iterations }}"
        cargo nextest run --workspace --all-features --locked --no-fail-fast --retries 0
    done
    echo "no flaky tests across {{ iterations }} iterations"

# --- Mutation testing ---

# The code the sweep mutates: the state machine and the teardown and session
# decision cores, where a wrong branch is silent (a mutant the suite still
# passes is a test gap no coverage percentage reveals). Kept here, not in the
# workflow, so a local run and the weekly lane mutate the same code. The sweep
# takes these directories whole, less the files that mutants_skipped names. Code
# that a split moves out of a swept file into a new file beside it therefore
# stays in the sweep, and a new file is swept until it is listed there. The
# skipped files are the ones the sweep has not covered so far, not files that
# decide nothing: several make safety decisions too (the switch transition, the
# init check before a switch, the /run scrub, the disk guard and the teardown
# side of the way back), and widening the sweep to them is a budget decision.
# The single mutants that no test can kill are another list: .cargo/mutants.toml
# excludes them, with their reasons, from every cargo-mutants run, the in-diff
# lane's too.
mutants_dirs := "nails-base/src/state " + \
    "nails-teardown/src/whole_root " + \
    "nails-session/src/session"
mutants_skipped := "nails-teardown/src/whole_root/boot_records.rs " + \
    "nails-teardown/src/whole_root/carry.rs " + \
    "nails-teardown/src/whole_root/decoy_mounts.rs " + \
    "nails-teardown/src/whole_root/disk_guard.rs " + \
    "nails-teardown/src/whole_root/kernel_helpers.rs " + \
    "nails-teardown/src/whole_root/kill.rs " + \
    "nails-teardown/src/whole_root/network.rs " + \
    "nails-teardown/src/whole_root/nextroot.rs " + \
    "nails-teardown/src/whole_root/ret.rs " + \
    "nails-teardown/src/whole_root/run_records.rs " + \
    "nails-teardown/src/whole_root/run_scrub.rs " + \
    "nails-teardown/src/whole_root/runtime_units.rs " + \
    "nails-teardown/src/whole_root/switch_refusal.rs " + \
    "nails-teardown/src/whole_root/tools.rs " + \
    "nails-teardown/src/whole_root/transition.rs " + \
    "nails-session/src/session/checks.rs " + \
    "nails-session/src/session/layout.rs " + \
    "nails-session/src/session/leave.rs " + \
    "nails-session/src/session/network_state.rs " + \
    "nails-session/src/session/nixos.rs " + \
    "nails-session/src/session/persona.rs " + \
    "nails-session/src/session/store.rs " + \
    "nails-session/src/session/systemd.rs " + \
    "nails-session/src/session/units.rs"

# Mutate the state machine and the teardown/session decision cores and check
# the tests catch each mutation. Heavy, so it runs weekly in scheduled.yml
# rather than on the gate. The report goes to target/mutants/mutants.out, and in
# CI the counts and every mutant that survived or timed out also go to the job
# summary. Such mutants (exit codes 2 and 3) are findings to triage, not a
# failed run. The recipe fails when cargo-mutants does, as on tests that fail
# without a mutation, and when the run proves less than its counts say: a
# directory of the sweep holds no mutant, the run caught no mutant, or a
# mutant's build failed for want of disk, memory or I/O, which cargo-mutants
# counts as unviable (ci/mutants_report.py). `shard`/`shards` split the sweep
# across a matrix (`just mutants 0 4`); the default is the whole sweep.
mutants shard="" shards="":
    #!/usr/bin/env bash
    set -euo pipefail
    # cargo-mutants creates the --output directory but not its parents, and a
    # fresh checkout has no target/ yet.
    mkdir -p target/mutants
    scope=(--package nails-base --package nails-teardown --package nails-session)
    for dir in {{ mutants_dirs }}; do
        scope+=(-f "$dir/**/*.rs")
    done
    for file in {{ mutants_skipped }}; do
        scope+=(-e "$file")
    done
    # A directory that was renamed or moved would leave the sweep without a
    # trace, so each one must still hold a mutant. Listing builds nothing.
    listed=$(cargo mutants --list "${scope[@]}")
    for dir in {{ mutants_dirs }}; do
        if ! grep -q "^$dir/" <<< "$listed"; then
            echo "No mutant under $dir: update mutants_dirs in the justfile" >&2
            exit 1
        fi
    done
    shard_args=()
    if [ -n '{{ shard }}' ]; then
        shard_args=(--shard '{{ shard }}/{{ shards }}')
    fi
    status=0
    cargo mutants "${scope[@]}" \
        --all-features --cargo-arg=--locked \
        "${shard_args[@]}" \
        --output target/mutants || status=$?
    case "$status" in
        0 | 2 | 3) ;;
        *) exit "$status" ;;
    esac
    # cargo-mutants also exits 0 when no mutant builds or the tests never fail
    # on one. The sweep holds several hundred mutants, and a quarter of them
    # is still over a hundred, so a shard that caught none proves nothing,
    # whole sweep or not.
    python3 -m ci.mutants_report --title "Mutation testing" --require-caught \
        target/mutants/mutants.out

# The cargo-mutants options of the in-diff lane, apart from the shard and the
# output: mutants-in-diff tests with them and mutants-in-diff-plan lists with
# them, so the plan counts exactly the mutants that the shards split between
# them. --timeout keeps one slow mutant from running away inside the lane's own
# time box.
mutants_in_diff_options := "--all-features --cargo-arg=--locked --timeout 120"

# Mutation testing restricted to the lines a diff changed (cargo-mutants
# --in-diff), for a non-blocking pull-request lane: it reports surviving mutants
# without failing, and a diff that changes no mutable code is a clean pass. A
# mutant whose build failed for want of disk, memory or I/O was never tested,
# so it fails the lane although cargo-mutants counts it as unviable
# (ci/mutants_report.py). `diff` is a unified `git diff` of the change;
# `shard`/`shards` split the work across a matrix (mutants-in-diff-plan sizes
# it). `minutes`, when given, is the shard's time box: cargo-mutants is stopped
# when it runs out, the mutants tested by then are still reported, and the
# recipe fails, since the rest were never tested. The report goes to
# target/mutants/mutants.out, with the survivors in the job summary. Each test
# binary runs through ci/mutants_guard.py: each process of the test run may
# allocate 4 GiB at most, the binary's process group gets the signal that ends
# the run, and once the binary has ended every process it started is killed,
# one that left the group for one or a session of its own too (the workspace's
# process runner starts its children so), although such a process gets no
# signal before. A mutant that makes a loop endless thus does not outlive its
# test run, nor fill the runner's memory alone.
mutants-in-diff diff shard="0" shards="1" minutes="":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/mutants
    # cargo runs each test binary through its target runner: the guard caps
    # what each process may allocate, kills the binary's process group when
    # it outlives the signal that ends its test run, and kills what the
    # binary started once it has ended.
    host=$(rustc --print host-tuple)
    host=${host^^}
    export "CARGO_TARGET_${host//-/_}_RUNNER=python3 -I {{ justfile_directory() }}/ci/mutants_guard.py"
    # On SIGTERM cargo-mutants ends the build or test it runs and exits,
    # keeping the outcome of every mutant it finished. --foreground leaves it
    # in this shell's process group, so a Ctrl-C still reaches it.
    limit=()
    if [ -n '{{ minutes }}' ]; then
        limit=(timeout --foreground --kill-after=1m '{{ minutes }}m')
    fi
    status=0
    "${limit[@]}" cargo mutants --in-diff '{{ diff }}' {{ mutants_in_diff_options }} \
        --shard '{{ shard }}/{{ shards }}' --output target/mutants || status=$?
    # Survivors (2) and timeouts (3) are reported, never a failure; a diff with
    # no mutable code (0, no mutants) is a clean pass. A run stopped at its time
    # box (124) is reported as far as it got and then fails. Anything else, such
    # as a baseline that fails without a mutation, still fails the lane.
    case "$status" in
        0 | 2 | 3 | 124) ;;
        *) exit "$status" ;;
    esac
    # A shard of a small diff may hold a single mutant that does not compile,
    # so catching none is no failure here.
    report=0
    python3 -m ci.mutants_report --title "Mutation testing on the diff" \
        target/mutants/mutants.out || report=$?
    if [ "$status" = 124 ]; then
        echo "The shard ran out of its {{ minutes }}-minute time box." >&2
        exit 1
    fi
    exit "$report"

# Plan the shards of the in-diff lane for `diff`: list the diff's mutants with
# the options mutants-in-diff tests with, which builds nothing, and split them
# over as many shards as keep each inside its time box (ci/mutants_plan.py). The
# plan goes to stdout as `name=value` lines for $GITHUB_OUTPUT, the reasoning to
# stderr and the job summary.
mutants-in-diff-plan diff:
    #!/usr/bin/env bash
    set -euo pipefail
    listed=$(mktemp)
    trap 'rm -f "$listed"' EXIT
    # cargo-mutants prints nothing, and exits 0, for a diff that touches no
    # mutant; a diff that does not match the tree fails here.
    cargo mutants --list --json \
        --in-diff '{{ diff }}' {{ mutants_in_diff_options }} > "$listed"
    python3 -m ci.mutants_plan "$listed"
