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

# Baseline validation
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

If you are not using the Nix development environment, make sure your local toolchain is compatible with the repository before opening a PR.

### About the pre-commit hooks

This repository's `pre-commit` configuration is intentionally heavier than a formatter-only setup. The hooks are designed to catch the same classes of problems that would otherwise fail later in review or CI.

In practice, that means some hooks may require tools provided by the Nix development shell or other repository-pinned tooling. If a hook fails because a command or dependency is missing, enter the dev shell and rerun the checks:

```bash
nix develop
pre-commit run --all-files
```

Running the full hook set before you open a pull request is the best way to reduce review churn.

## Contribution Guidelines

### Keep changes focused

- Prefer small, reviewable pull requests.
- Separate refactors from behavior changes when practical.
- Update docs when behavior, interfaces, or contributor workflows change.

### Code expectations

- New behavior should include tests when feasible.
- Avoid unnecessary dependencies.
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

- `fix(overlay): handle cleanup failure on deactivation`
- `docs(security): clarify public vulnerability reporting`
- `test(state): cover rollback edge case`

## Communication

- Use issues for bugs, feature requests, and contributor questions.
- Use [SECURITY.md](SECURITY.md) for private vulnerability reports.

## Licensing

By contributing, you agree that your contributions will be licensed under the repository's existing license terms.
