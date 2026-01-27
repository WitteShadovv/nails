# Changelog

All notable changes to NAILS (NixOS Anti-forensics Isolation & Layering System) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

---

## [Unreleased]

### Added

#### Foundation Infrastructure (Epic 1)
- **feat(story-1.7)**: Comprehensive Definition of Done document with 85% coverage threshold (Story 1.7)
  - Complete DoD checklist with Code Complete, Quality Gates, Documentation, Review, and Testability criteria
  - Tools & Commands Reference with Makefile shortcuts and CI/CD integration
  - Troubleshooting guide for 6 common failure scenarios
  - Meta-validation guidelines with self-review and peer-review checklists
  - Full requirements traceability linking DoD criteria to AR/NFR/TR IDs

- **feat(story-1.6)**: CI/CD pipeline with 6-job structure and 85% coverage enforcement (Story 1.6)
  - GitHub Actions workflow: format-check, lint, test, coverage, audit, benchmark
  - Swatinem/rust-cache@v2 for optimized build caching
  - Coverage reporting with PR comments and artifact uploads
  - Security audit with cargo-audit for dependency vulnerability scanning
  - Performance benchmark job with RQ2 target validation

- **feat(story-1.5)**: Pre-commit hooks with 85% coverage enforcement (Story 1.5)
  - 6 Rust quality hooks: cargo-audit, rust-fmt, rust-clippy, rust-test, rust-coverage, commit-msg
  - Nix-specific hooks: nixfmt, nix-syntax-check, deadnix, statix, nix-store-check
  - Conventional Commits validation enforcing AR20-AR21 format
  - Total hook execution time: 33-68 seconds (under 2-minute requirement)

- **feat(story-1.4)**: Filesystem trait abstraction for test mocking (Story 1.4)
  - FilesystemTrait with read_to_string, write, exists, create_dir_all methods
  - RealFilesystem implementation for production use
  - MockFilesystem implementation for testing without root privileges
  - Enables 99% of tests to run without elevated permissions (AR4, NFR37)

- **feat(story-1.3)**: Custom error types with thiserror (Story 1.3)
  - NailsError enum with 12 error variants covering all failure modes
  - Display and Error trait implementations via thiserror derive macros
  - Error context for debugging with source error propagation
  - Comprehensive error handling patterns documented in architecture.md

- **feat(story-1.2)**: Project dependencies and dependency security (Story 1.2)
  - Core dependencies: clap 4.5, thiserror 1.0, anyhow 1.0, tracing 0.1, serde 1.0
  - Development dependencies: cargo-tarpaulin, cargo-audit, criterion
  - Security auditing infrastructure with cargo-audit
  - Dependency version pinning for reproducible builds

- **feat(story-1.1)**: Cargo workspace with CLI and core crates (Story 1.1)
  - Workspace structure: nails-cli (binary) and nails-core (library)
  - Rust 1.91+ with 2021 edition
  - Project metadata: AGPL-3.0 license, author, repository links
  - Foundation for test-driven development from Day 1

### Fixed

- **fix(test)**: Increase test coverage to nearly 90% and lower acceptable limit to 85%
  - Pragmatic coverage threshold balancing rigor with development velocity
  - Coverage enforcement in pre-commit hooks and CI/CD pipeline
  - Comprehensive test suite for filesystem trait, state machine, and error handling

- **fix(ci)**: Correct cargo audit command syntax
  - Fixed cargo audit invocation in CI pipeline for proper dependency scanning

- **fix(pre-commit)**: Remove always_run from commit-msg hook
  - Optimized commit-msg hook to only run when commit message changes

- **fix(test)**: Resolve clippy warnings and deprecated API usage
  - Zero clippy warnings maintained across codebase
  - Updated to current Rust stable API patterns

### Performance

- **perf(ci)**: Optimize caching with Swatinem/rust-cache@v2
  - Intelligent Rust build caching reducing CI/CD execution time
  - Separate cache keys per job (lint, test, coverage, audit, benchmark)
  - Cache targets and all crates for maximum efficiency

- **feat(ci)**: Optimize pipeline performance with enhanced caching
  - Parallel job execution with dependency graph
  - Artifact uploads for coverage reports and benchmark results
  - 30-90 day retention policies for debugging and historical analysis

---

## Release Planning

### Milestone: Epic 1 Complete (Foundation) - Target: 2026-01-31
- ✅ Story 1.1: Cargo workspace initialization
- ✅ Story 1.2: Project dependencies and security
- ✅ Story 1.3: Custom error types
- ✅ Story 1.4: Filesystem trait for mocking
- ✅ Story 1.5: Pre-commit hooks with coverage enforcement
- ✅ Story 1.6: CI/CD pipeline with quality gates
- ✅ Story 1.7: Definition of Done documentation

### Milestone: v0.1.0 (Alpha Release) - Target: 2026-03-31
- Epic 2: State Machine & Core Domain Logic
- Epic 3: Pre-Flight Validation System
- Epic 4: Activation Command
- Basic functionality: activate, deactivate, status commands

### Milestone: v0.2.0 (Beta Release) - Target: 2026-05-31
- Epic 5: Deactivation Command
- Epic 6: Emergency Command
- Epic 7: Status Command & System Observability
- Complete command suite with emergency capabilities

### Milestone: v1.0.0 (Thesis Release) - Target: 2026-06-30
- Epic 8: Shell Prompt Integration & User Experience
- Epic 9: Logging & Operational Transparency
- Epic 10: Configuration Management & User Customization
- Epic 11: Documentation & Thesis Artifacts
- Epic 12: Performance & Binary Optimization
- Complete thesis implementation with forensic validation

---

## Contributing

See [docs/development-guide.md](./docs/development-guide.md) for contribution guidelines.

All changes must meet the Definition of Done criteria documented in [docs/definition-of-done.md](./docs/definition-of-done.md).

---

**Project:** NAILS - NixOS Anti-forensics Isolation & Layering System
**License:** AGPL-3.0
**Maintainer:** WitteShadovv
**Status:** Active Development (Thesis Project)
