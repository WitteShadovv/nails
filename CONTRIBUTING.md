# Contributing to NAILS

Thanks for your interest in contributing to NAILS.

NAILS is security-sensitive alpha software. We value contributions that are clear, testable, and consistent with the project's safety goals.

Maintainers may decline changes that weaken the documented safety posture, broaden security claims beyond the documented threat model, or add public-facing language that is more certain than the implementation supports.

> If you are reporting a security vulnerability, do **not** open a public issue. Follow [SECURITY.md](SECURITY.md) instead.

## Ways to Contribute

- fix bugs
- improve documentation
- propose focused features
- add or strengthen tests
- review open issues and pull requests

## Before You Start

Before investing significant work:

1. Search for an existing issue or pull request.
2. For non-trivial changes, open an issue first so maintainers can confirm scope and fit.
3. Keep proposals grounded in the current alpha status of the project.
4. Make sure the change belongs in **NAILS** rather than the separate `nails-os` installable-distribution repository.

## Development Setup

### Prerequisites

| Tool | Notes |
| --- | --- |
| Rust stable | See repository toolchain requirements |
| Nix / NixOS | Recommended for reproducible development and runtime validation |
| `pre-commit` | Recommended for running the repository's local validation hooks |

Additional tools may be required for specific CI-parity or release-parity checks.

### Basic setup

```bash
git clone https://github.com/WitteShadovv/nails.git
cd nails

# Recommended: use the pinned development environment
nix develop

# Install local hooks if you use pre-commit
pre-commit install

# Baseline validation (the justfile is the single source of these commands)
just check        # formatting, clippy, Rust file sizes, the fuzz targets and the tests
nix flake check   # Nix, shell and workflow linters; builds no VM test
```

`nix develop` is the only supported development shell: it pins the toolchain and provides every tool the checks and hooks need. If you are not using it, make sure your local toolchain is compatible with the repository before opening a PR.

### About the pre-commit hooks

This repository's `pre-commit` configuration is intentionally heavier than a formatter-only setup. The hooks are designed to catch the same classes of problems that would otherwise fail later in review or CI.

In practice, that means some hooks may require tools provided by the Nix development shell or other repository-pinned tooling. If a hook fails because a command or dependency is missing, enter the dev shell and rerun the checks:

```bash
nix develop
pre-commit run --all-files
```

Running the full hook set before you open a pull request is the best way to reduce review churn.

## Testing

The suite runs in tiers, each with its own command, runtime and prerequisites. Everything runs inside `nix develop`. [docs/ci.md](docs/ci.md#test-and-ci-tiers) maps each tier to the workflow that enforces it; [docs/development-guide.md](docs/development-guide.md) covers the privileged tier and environment-sensitive tests in depth.

| Tier | Command | Runtime | Prerequisites |
|---|---|---|---|
| Format, lint and unit tests (pre-push gate) | `just check` | about 90 s | dev shell |
| CI parity, with coverage | `just ci-rust` | a few minutes | dev shell |
| One fuzz target (see [docs/testing-strategy.md](docs/testing-strategy.md#fuzzing)) | `just fuzz-run mountinfo` | a minute of fuzzing, after a first build of several minutes | dev shell |
| Real-kernel tests (rootless) | `just kernel-tests` | seconds | dev shell, unprivileged user namespaces |
| The one root-only overlay test | see `docs/development-guide.md` | seconds | root, an overlayfs-capable kernel |
| One E2E test | `just e2e session-lifecycle` | minutes | KVM (`/dev/kvm`), Nix |
| E2E smoke group | `just e2e smoke` | minutes | KVM, Nix |
| Full E2E suite | `just e2e all` | long (nightly in CI) | KVM, Nix |

- **Unprivileged by default.** `just test` (and `just check`) need no root. Most tests drive the logic through `MockFilesystem` and temporary directories; the real-kernel tests re-run themselves in an unprivileged user and mount namespace and skip, with a message, where user namespaces are unavailable (`just kernel-tests` fails instead).
- **Ignored tests.** Only one real-overlay test needs root: the whiteout and opaque-directory test in `nails-core/tests/privileged_mounts.rs`. It is `#[ignore]`d and runs in a private mount namespace in the `privileged-mounts` CI job (part of `gate`); `docs/development-guide.md` has the exact build-and-run commands. The other `#[ignore]`d tests regenerate a committed file or need a host state they cannot set up; each says why in its `#[ignore = "..."]` reason.
- **`NAILS_UNSAFE_REAL_OPS`.** CLI integration tests that would perform real host actions refuse to run unless `NAILS_UNSAFE_REAL_OPS=1` is set, so a normal `cargo test` skips them rather than touching the host. Set it only inside a disposable VM or container.
- **Environment-sensitive tests.** All tests in a binary share one process environment, so tests never mutate it: product code reads the environment once, in `main`, into a `RuntimeEnv`, and a test builds the `RuntimeEnv` it needs and injects it (see `docs/development-guide.md`). Never call `std::env::set_var`/`remove_var`.
- **Shared fixtures.** Build managers for a test through `nails_core::TestWorld` rather than re-deriving a `Config` and `NailsManager` by hand; it stages the mock filesystem, roots the config in a temporary directory and (via `.with_nixos`, `.with_state`/`.inactive`, `.with_filesystem`) covers the specialised cases. `Config::test_default()` gives a deterministic config on its own. Both live behind the `test-support` feature, so `nails-cli` and the integration tests share them.
- **Test-file layout.** A module keeps its tests in a sibling `tests/` directory wired with a single `mod tests;` declaration, not one giant `tests.rs`. `tests/mod.rs` holds the shared fixtures and the `mod <behaviour>;` declarations; each `tests/<behaviour>.rs` groups one behaviour (a pre-flight check, the entry, the way back, …) and starts with `use super::*;`. Keep each file under about 1,500 lines and split by behaviour when it grows past that.

## Contribution Guidelines

### Keep changes focused

- Prefer small, reviewable pull requests.
- Separate refactors from behavior changes when practical.
- Update docs when behavior, interfaces, or contributor workflows change.

### Code expectations

- New behavior should include tests when feasible.
- Avoid unnecessary dependencies.
- Unsafe code is denied workspace-wide. Prefer a safe wrapper (`nix`, `rustix`); where a raw call is unavoidable, put a scoped `#[allow(unsafe_code)]` on the smallest enclosing item and a `// SAFETY:` comment on each block (see the [lint policy](docs/ci.md#lint-policy)).
- Keep CLI code thin and business logic in library code where possible.
- Do not introduce custom cryptography or weak secret-handling patterns.

### Security expectations

Because NAILS is security-sensitive:

- avoid logging or persisting sensitive material
- fail safely when validation or cleanup cannot complete
- document tradeoffs clearly when a change affects safety assumptions
- call out threat-model implications in your PR description when relevant

## Pull Request Process

1. Create a topic branch from the repository's default branch.
2. Make the smallest change that solves the problem well.
3. Run the relevant local checks before opening a pull request.
4. Explain the motivation, approach, and any user-visible impact.
5. Link related issues when applicable.

If you skipped the Nix development shell during implementation, verify the final branch inside it before you submit the PR, especially when `pre-commit` reports missing tools or environment-sensitive failures.

Maintainers may request changes to scope, design, tests, or documentation before merge.

## Commit Messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/) for consistency.

Examples:

- `fix(session): detach a leftover next root on recover`
- `docs(security): clarify public vulnerability reporting`
- `test(state): cover rollback edge case`

## Communication

- Use issues for bugs, feature requests, and contributor questions.
- Use [SECURITY.md](SECURITY.md) for private vulnerability reports.

## Developer Certificate of Origin (sign-off)

Every commit must be signed off. The sign-off certifies that you wrote the
patch, or otherwise have the right to submit it under the project's licence,
per the [Developer Certificate of Origin](https://developercertificate.org/).

Add the sign-off trailer by committing with `-s`:

```bash
git commit -s -m "fix(session): detach a leftover next root on recover"
```

This appends a line to the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use the same name and email as your Git `user.name` and `user.email`. Pull
requests whose commits are missing the sign-off will be asked to amend them
(`git commit --amend -s` for the last commit, or an interactive rebase for
several).

New source files carry the two SPDX header lines

```
// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later
```

and the whole tree is kept REUSE-compliant; `reuse lint` runs in the
development shell, as a pre-commit hook and in CI.

The graphical interface in `gui/` is licensed GPL-3.0-only, so new files there
carry `GPL-3.0-only` in the licence line instead. It may use the
GPL-3.0-or-later crates, but no crate outside `gui/` may depend on it.

## Licensing

By contributing, you agree that your contributions will be licensed under the repository's existing license terms.
