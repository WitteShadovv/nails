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

shipped_graph := "--exclude-dev --target x86_64-unknown-linux-musl --target x86_64-unknown-linux-gnu"

# --- Rust quality gate ---

# Check formatting without rewriting files.
fmt-check:
    cargo fmt --all -- --check

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
# a real broken pipe; see docs/testing-strategy.md). They run in `just test`
# too, where a host without user namespaces skips them; here a skip fails.
kernel-tests:
    NAILS_REQUIRE_USERNS=1 cargo nextest run --workspace --all-features --locked \
        -E 'test(/kernel_tests::|test_support::/) | binary(kernel_semantics) | binary(broken_pipe) | binary(filesystem_contract)'

# The root-only privileged_mounts suite, rootless in a user + mount namespace.
# The whiteout test needs trusted.* xattrs, which a user namespace cannot set,
# so it stays with the privileged-mounts CI job.
privileged-rootless:
    unshare -Urm --propagation private cargo test -p nails-core --locked \
        --test privileged_mounts -- --ignored --skip whiteout

# The pre-push gate: formatting, lints, file sizes and the test suite.
check: fmt-check lint line-count test

# Everything the ci.yml Rust jobs run, for reproducing the gate locally.
ci-rust: fmt-check lint line-count coverage doctest

# --- Dependency policy ---

# Check the shipped dependency graph against deny.toml (the CI merge gate).
deny *checks="advisories bans licenses sources":
    cargo deny --locked {{ shipped_graph }} check {{ checks }}

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

# Mutate the core teardown, overlay and state machine modules and check the
# tests catch each mutation. Heavy, so it runs weekly in scheduled.yml rather
# than on the gate; a surviving mutant means a test gap, never a build failure.
mutants:
    cargo mutants --package nails-core --all-features \
        -f 'nails-core/src/state/**/*.rs' \
        -f 'nails-core/src/overlay/**/*.rs' \
        -f 'nails-core/src/cleanup/**/*.rs' \
        --output target/mutants
