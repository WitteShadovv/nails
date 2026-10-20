# Task runner shared by local development and CI; `just` lists the recipes.
# The tools come from the flake dev shell (`nix develop`). Every cargo call
# passes `--locked` so a stale Cargo.lock fails here exactly as it does in CI.
# The line-coverage floor lives in `.config/coverage.toml` and nowhere else: the
# `coverage` recipe reads the number from there, CI calls `just coverage`, and
# local runs reach the same number through `ci-rust`.

[private]
default:
    @{{ just_executable() }} --list --justfile {{ justfile() }}

# The crates that can end up in a release binary: the x86_64 Linux targets
# without dev-dependencies. Crates that only build for other platforms (wasm,
# Windows, macOS) or only for tests and benchmarks never ship.

shipped_targets := "x86_64-unknown-linux-musl x86_64-unknown-linux-gnu"

# --- Rust quality gate ---

# Check formatting without rewriting files: the workspace, then the fuzz crate,
# a workspace of its own.
fmt-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path fuzz/Cargo.toml -- --check

# Clippy over every target and feature, with warnings denied.
lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Rust file size limits; the pre-commit hook and CI run the same script.
line-count:
    ./scripts/check-line-count.sh

# Run the unit and integration suite through nextest.
test:
    cargo nextest run --workspace --all-features --locked --no-fail-fast

# Long property-based run of the parser tests (the `fuzz_` proptests): the
# same properties `test` runs with the default case count, here with `cases`
# generated inputs each. A failure prints the minimal input that breaks it.
fuzz cases="100000":
    PROPTEST_CASES={{ cases }} cargo test -p nails-core --lib --locked --release -- fuzz_

# Run one cargo-fuzz target of fuzz/ (`just fuzz-run mountinfo 600`) built as
# CI builds it: release, with debug assertions, overflow checks and the address
# sanitizer. The pinned stable compiler accepts cargo-fuzz's sanitizer flag under
# RUSTC_BOOTSTRAP, as in `shuffle`. It starts from the target's seeds and
# dictionary; new inputs collect in fuzz/corpus/, a crash in fuzz/artifacts/. An
# input that runs longer than 25 seconds is a hang, as in CI.
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

# Run the documentation tests, which nextest does not execute.
doctest:
    cargo test --doc --workspace --all-features --locked

# Prove the unit tests do not depend on execution order. No test mutates the
# shared process environment (they inject a RuntimeEnv instead), and a leak
# through any remaining shared state surfaces only under a threaded, shuffled
# run; nextest isolates each test in its own process and would hide it. Hence
# libtest, not nextest, and `--lib`, where most unit tests live. The `--shuffle-seed` flag is unstable, so the pinned stable
# compiler is told to accept it with RUSTC_BOOTSTRAP rather than adding a
# nightly toolchain.
shuffle seeds="20":
    #!/usr/bin/env bash
    set -euo pipefail
    for seed in $(seq 1 {{ seeds }}); do
        echo "shuffle seed $seed"
        RUSTC_BOOTSTRAP=1 cargo test --workspace --all-features --locked --lib \
            -- -Z unstable-options --shuffle-seed "$seed"
    done

# Line coverage over nextest, measuring production code only; fails below the
# floor in .config/coverage.toml.
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    # The single source of truth for the floor: read it here and nowhere else.
    threshold=$(sed -n 's/^[[:space:]]*line_threshold[[:space:]]*=[[:space:]]*//p' \
        .config/coverage.toml | tr -d ' "')
    if [ -z "$threshold" ]; then
        echo "No line_threshold in .config/coverage.toml" >&2
        exit 1
    fi
    # Test infrastructure never ships, so it must not count toward the figure:
    # the in-memory filesystem mock, the shared test fixtures and the platform
    # test doubles, plus every test file (inline `tests.rs`, `*_tests.rs`, the
    # `tests/` integration trees and the benches). Keeping them out of the
    # report is what makes this number production-only.
    ignore='(/tests/|/tests\.rs$|_tests\.rs$|/mock/|/test_support|/fake\.rs$|/contract\.rs$|/config/testing\.rs$|/benches/)'
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
        echo "No line-rate in $out/cobertura.xml" >&2
        exit 1
    }
    pct=$(awk "BEGIN { printf \"%.2f\", ${rate} * 100 }")
    echo "Line coverage: ${pct}% (threshold ${threshold}%)"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "Line coverage: ${pct}% (threshold ${threshold}%)" >> "$GITHUB_STEP_SUMMARY"
    fi
    awk "BEGIN { exit !(${pct} >= ${threshold}) }" || {
        echo "Coverage ${pct}% is below the ${threshold}% threshold" >&2
        exit 1
    }

# --- Real-kernel tests ---

# The tests that ask the kernel directly from an unprivileged user + mount
# namespace (overlay mount ids and st_dev, live mountinfo, fdinfo, strictatime,
# a real broken pipe, the mount contract, the rootless privileged_mounts tests
# and the CLI's write paths on a tmpfs hidden root; see
# docs/testing-strategy.md). They run in `just test` too, where a host without
# user namespaces skips them; here a skip fails.
kernel-tests:
    NAILS_REQUIRE_USERNS=1 cargo nextest run --workspace --all-features --locked \
        -E 'test(/kernel_tests::|test_support::/) | binary(kernel_semantics) | binary(broken_pipe) | binary(filesystem_contract) | binary(privileged_mounts) | binary(maintenance_cli)'

# The pre-push gate: formatting, lints, file sizes and the test suite.
check: fmt-check lint line-count test

# Everything the ci.yml Rust jobs run, for reproducing the gate locally.
ci-rust: fmt-check lint line-count coverage doctest

# --- Dependency policy ---

# Check the shipped dependency graph against deny.toml (the CI merge gate).
# One run per target: cargo-deny 0.20 accepts `--target` only once (fixed
# upstream after 0.20.2), and the targets' graphs together are the shipped one.
deny *checks="advisories bans licenses sources":
    #!/usr/bin/env bash
    set -euo pipefail
    for target in {{ shipped_targets }}; do
        cargo deny --locked --exclude-dev --target "$target" check {{ checks }}
    done

# Check every target and dev-dependency against deny.toml (weekly, never gates).
deny-full *checks="advisories bans licenses sources":
    cargo deny --locked check {{ checks }}

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

# The files the sweep mutates: the state machine and the teardown and session
# decision cores, where a wrong branch is silent (a mutant the suite still
# passes is a test gap no coverage percentage reveals). Kept here, not in the
# workflow, so a local run and the weekly lane mutate the same code.
mutants_files := "-f 'nails-base/src/state/**/*.rs' " + \
    "-f 'nails-teardown/src/whole_root/plan.rs' " + \
    "-f 'nails-teardown/src/whole_root/emergency.rs' " + \
    "-f 'nails-teardown/src/whole_root/utab.rs' " + \
    "-f 'nails-session/src/session/entry.rs' " + \
    "-f 'nails-session/src/session/policy.rs' " + \
    "-f 'nails-session/src/session/fstab.rs' " + \
    "-f 'nails-session/src/session/probe.rs' " + \
    "-f 'nails-session/src/session/way_back.rs'"

# Mutate the state machine and the teardown/session decision cores and check
# the tests catch each mutation. Heavy, so it runs weekly in scheduled.yml
# rather than on the gate. The report goes to target/mutants/mutants.out, and in
# CI the counts and every mutant that survived or timed out also go to the job
# summary. Such mutants (exit codes 2 and 3) are findings to triage, not a
# failed run, so the recipe succeeds. Any other failure of cargo-mutants, such
# as tests that already fail without a mutation, still fails it, and so does a
# full run that caught no mutant at all. `shard`/`shards` split the sweep across
# a matrix (`just mutants 0 4`); the default is the whole sweep.
mutants shard="" shards="":
    #!/usr/bin/env bash
    set -euo pipefail
    # cargo-mutants creates the --output directory but not its parents, and a
    # fresh checkout has no target/ yet.
    mkdir -p target/mutants
    shard_args=()
    if [ -n '{{ shard }}' ]; then
        shard_args=(--shard '{{ shard }}/{{ shards }}')
    fi
    status=0
    cargo mutants \
        --package nails-base --package nails-teardown --package nails-session \
        --all-features --cargo-arg=--locked \
        {{ mutants_files }} \
        "${shard_args[@]}" \
        --output target/mutants || status=$?
    case "$status" in
        0 | 2 | 3) ;;
        *) exit "$status" ;;
    esac
    out=target/mutants/mutants.out
    caught=$(wc -l < "$out/caught.txt")
    missed=$(wc -l < "$out/missed.txt")
    timed_out=$(wc -l < "$out/timeout.txt")
    unviable=$(wc -l < "$out/unviable.txt")
    result="$caught caught, $missed missed, $timed_out timed out, $unviable unviable"
    echo "Mutants: $result (report in $out)"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        # cargo-mutants flags missed mutants as warning annotations, but GitHub
        # shows only a limited number per step, so the summary lists them all.
        section() {
            if [ -s "$out/$2.txt" ]; then
                printf '\n### %s\n\n```text\n' "$1"
                cat "$out/$2.txt"
                printf '```\n'
            fi
        }
        {
            printf '## Mutation testing\n\n%s.\n' "$result"
            section "Missed" missed
            section "Timed out" timeout
        } >> "$GITHUB_STEP_SUMMARY"
    fi
    # cargo-mutants also exits 0 when the package or file filter matches no
    # code and when no mutant builds. A full run that caught no mutant, for
    # those reasons or because the tests never fail on one, proves nothing; a
    # single shard may legitimately catch none, so this guards the full run.
    if [ -z '{{ shard }}' ] && [ "$caught" -eq 0 ]; then
        echo "No mutant was caught, so this run proves nothing; see $out" >&2
        exit 1
    fi

# Mutation testing restricted to the lines a diff changed (cargo-mutants
# --in-diff), for a non-blocking pull-request lane: it reports surviving mutants
# without failing, and a diff that changes no mutable code is a clean pass.
# `diff` is a unified `git diff` of the change; `shard`/`shards` split the work
# across a matrix, and --timeout keeps one slow mutant from running away inside
# the lane's own time box. The report goes to target/mutants/mutants.out, with
# the survivors in the job summary for the integration log.
mutants-in-diff diff shard="0" shards="1":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/mutants
    status=0
    cargo mutants --in-diff '{{ diff }}' --shard '{{ shard }}/{{ shards }}' \
        --all-features --cargo-arg=--locked \
        --timeout 120 \
        --output target/mutants || status=$?
    # Survivors (2) and timeouts (3) are reported, never a failure; a diff with
    # no mutable code (0, no mutants) is a clean pass. Anything else, such as a
    # baseline that fails without a mutation, still fails the lane.
    case "$status" in
        0 | 2 | 3) ;;
        *) exit "$status" ;;
    esac
    out=target/mutants/mutants.out
    if [ ! -f "$out/caught.txt" ]; then
        echo "No mutable code in this diff shard."
        exit 0
    fi
    caught=$(wc -l < "$out/caught.txt")
    missed=$(wc -l < "$out/missed.txt")
    timed_out=$(wc -l < "$out/timeout.txt")
    unviable=$(wc -l < "$out/unviable.txt")
    result="$caught caught, $missed missed, $timed_out timed out, $unviable unviable"
    echo "Mutants (in diff): $result (report in $out)"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        section() {
            if [ -s "$out/$2.txt" ]; then
                printf '\n### %s\n\n```text\n' "$1"
                cat "$out/$2.txt"
                printf '```\n'
            fi
        }
        {
            printf '## Mutation testing on the diff\n\n%s.\n' "$result"
            section "Missed" missed
            section "Timed out" timeout
        } >> "$GITHUB_STEP_SUMMARY"
    fi
