# Contributing to NAILS

Thank you for your interest in contributing to NAILS. This document covers everything you need to get started.

For security vulnerabilities, **do not** open a public issue — see [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Code Style and Quality](#code-style-and-quality)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Commit Conventions](#commit-conventions)
- [Security Considerations](#security-considerations)

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| **Rust** | 1.93+ stable | `rustup update stable` |
| **NixOS** | Any recent version | Required runtime target; development builds work on any Linux |
| **pre-commit** | Latest | `pip install pre-commit` |
| **cargo-nextest** | Latest | `cargo install cargo-nextest --locked` |
| **cargo-llvm-cov** | 0.8.4+ | `cargo install cargo-llvm-cov --locked` |
| **cargo-audit** | Latest | `cargo install cargo-audit --locked` |

Optional but recommended:

- **Nix** with flakes enabled — for reproducible dev shells (`nix develop`)
- **cargo-deny** — for license and dependency policy checks

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/WitteShadovv/nails.git
cd nails

# Option A: Use the Nix dev shell (pinned toolchain)
nix develop

# Option B: Use your system Rust toolchain
rustup update stable
rustc --version  # must be 1.93+

# Install pre-commit hooks
pre-commit install

# Verify everything works
cargo build
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

---

## Code Style and Quality

### Formatting

All Rust code must pass `cargo fmt --check`. The repository uses default `rustfmt` settings.

### Linting

Zero `clippy` warnings are allowed. CI runs:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Architecture

NAILS uses a strict **thin-CLI / thick-library** separation:

- **`nails-cli/`** — Binary crate with CLI argument parsing and terminal output only.
- **`nails-core/`** — Library crate containing all business logic, testable without root.

All new business logic belongs in `nails-core`. The CLI layer should remain a thin adapter.

### Dependency Policy

- Minimize new dependencies. Every transitive dependency increases audit surface.
- All dependencies must pass `cargo audit` (no high/critical advisories).
- All dependencies must pass `cargo deny` checks (license compatibility, source restrictions).
- Prefer well-established crates with active maintenance.

---

## Testing Requirements

### Coverage Threshold

**Minimum 85% line coverage** is enforced in CI and pre-commit hooks.

Coverage is measured with `cargo-llvm-cov`:

```bash
# Generate HTML coverage report
cargo llvm-cov --all-features --workspace --html --output-dir coverage/html

# Check coverage percentage
cargo llvm-cov --all-features --workspace --all-targets
```

### Test Guidelines

- All new features must include unit tests.
- Use `MockFilesystem` for filesystem operations — most tests run without root.
- Integration tests go in `tests/` directories within each crate.
- E2E tests (NixOS VM) are in `tests/e2e/` and run via `./scripts/run-e2e-tests.sh`.

### Running Tests

```bash
# All tests
cargo test

# With nextest (parallel, better output)
cargo nextest run

# Specific test
cargo test test_state_transitions

# E2E suite (requires NixOS/Nix)
./scripts/run-e2e-tests.sh
```

---

## Pull Request Process

1. **Branch from `main`** using the naming convention:
   ```
   feature/story-NNN-short-description
   bugfix/issue-NNN-short-description
   docs/topic-name
   ```

2. **Ensure all checks pass locally** before pushing:
   - `cargo fmt --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo test`
   - `cargo audit`
   - Coverage >= 85%

3. **Push and open a PR** against `main` (or `dev` for in-progress work).

4. **CI must pass.** The CI pipeline runs formatting, linting, sharded tests, coverage enforcement, security audit, SBOM generation, and burn-in flaky detection.

5. **Review.** All PRs require review from a code owner before merge.

### Definition of Done

A PR is ready to merge when:

- All CI checks pass (green status on `ci-success`)
- Coverage meets or exceeds 85%
- Zero clippy warnings
- Clean cargo audit (no high/critical vulnerabilities)
- Code follows the architectural patterns (RAII guards, trait abstractions, etc.)
- Documentation is updated if behavior changes

---

## Commit Conventions

NAILS uses [Conventional Commits](https://www.conventionalcommits.org/). The `commit-msg` pre-commit hook enforces this.

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Use For |
|------|---------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `ci` | CI/CD changes |
| `chore` | Build process, tooling, or auxiliary changes |

### Examples

```
feat(activate): add --dry-run flag for safe testing
fix(overlay): handle EBUSY on forced unmount
docs(readme): add systemd service example
test(state): add property-based tests for emergency transitions
ci(coverage): increase threshold to 90%
```

---

## Security Considerations

NAILS is security-critical software. When contributing, keep in mind:

- **No custom cryptography.** Use well-established libraries.
- **No unsafe code** without thorough justification and review.
- **Deterministic cleanup.** Use RAII guards for any resource that must be cleaned up on failure or panic.
- **No interpreter dependencies.** NAILS avoids runtime interpreters (Python, shell scripts in production paths) to prevent artifact leakage.
- **Secret handling.** Never log, print, or persist secrets. Never commit test fixtures containing real credentials.
- **Dependency hygiene.** `cargo audit` runs on every commit. New dependencies with known advisories will block the PR.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## Questions?

- Open a [GitHub Discussion](https://github.com/WitteShadovv/nails/discussions) for general questions.
- Email security@nails.run for security-sensitive topics.
