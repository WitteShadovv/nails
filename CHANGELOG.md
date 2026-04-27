# Changelog

All notable changes to NAILS (NixOS Anti-forensics Isolation & Layering System) are documented in
this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project
uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit history.

GitHub Releases use immutable tag-based publication. Exact stable tags are verified automatically
and published later by a deliberate manual workflow; suffixed prerelease tags may publish immutable
GitHub prereleases directly. This changelog remains the source of truth for ongoing project changes
during the current alpha phase.

## [Unreleased]

### Added

- Established the Rust workspace split between `nails-cli` and `nails-core`, with shared
  workspace metadata and dependency management.
- Added core development infrastructure including custom error types, a filesystem abstraction for
  testing, pre-commit hooks, CI workflows, and release-path verification.
- Added contributor and release documentation covering development workflow, CI expectations, and
  reproducible artifact verification.

### Changed

- Improved the public-facing documentation surface, including README polish, better link hygiene,
  and contributor guidance that matches the current repository state more closely.
- Clarified that NAILS is alpha software and that its security claims are bounded by the documented
  threat model and operator procedure.
- Clarified release, install, and versioning language so public docs consistently describe the
  immutable stable/prerelease publication model.

### Fixed

- Corrected CI and hook documentation around dependency auditing, coverage expectations, and local
  contributor workflow.
- Improved CI performance and reliability through better caching and parallelized validation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for public contribution guidance.
