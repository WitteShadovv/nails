# Task runner shared by local development and CI; `just` lists the recipes.
# The tools come from the flake dev shell (`nix develop`). Every cargo call
# passes `--locked` so a stale Cargo.lock fails here exactly as it does in CI.
# The line-coverage floor lives in `coverage_threshold` and nowhere else: CI
# calls `just coverage`, and local runs reach the same number through `ci-rust`.

coverage_threshold := "85"

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

# Run the documentation tests, which nextest does not execute.
doctest:
    cargo test --doc --workspace --all-features --locked

# Line coverage over nextest; fails below coverage_threshold.
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    # Every report lands under target/coverage, so nothing is written outside
    # the build directory. In CI the percentage also goes to the job summary.
    out=target/coverage
    mkdir -p "$out"
    cargo llvm-cov --no-report nextest --workspace --all-features --locked
    cargo llvm-cov report --cobertura --output-path "$out/cobertura.xml"
    cargo llvm-cov report --lcov --output-path "$out/lcov.info"
    cargo llvm-cov report --html --output-dir "$out/html"
    # The root <coverage> element carries the overall rate. -m1 stops at it:
    # piping thousands of per-file matches into `head` kills grep with SIGPIPE,
    # which pipefail turns into a failed recipe.
    rate=$(grep -m1 -oP '<coverage [^>]*line-rate="\K[0-9.]+' "$out/cobertura.xml") || {
        echo "No line-rate in $out/cobertura.xml" >&2
        exit 1
    }
    pct=$(awk "BEGIN { printf \"%.2f\", ${rate} * 100 }")
    echo "Line coverage: ${pct}% (threshold {{ coverage_threshold }}%)"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "Line coverage: ${pct}% (threshold {{ coverage_threshold }}%)" >> "$GITHUB_STEP_SUMMARY"
    fi
    awk "BEGIN { exit !(${pct} >= {{ coverage_threshold }}) }" || {
        echo "Coverage ${pct}% is below the {{ coverage_threshold }}% threshold" >&2
        exit 1
    }

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

# Open the interactive driver of one E2E leaf test.
e2e-debug name:
    ./scripts/run-e2e-tests.sh interactive {{ name }}

# --- Python ---

# The ci/ package's unittest suite, ruff and mypy (CI's `ci-python` check).
ci-python:
    python3 -m unittest discover -s ci/tests -t .
    ruff check ci
    mypy ci

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
