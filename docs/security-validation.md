# Security validation

This guide documents the security validation mechanisms that are actually in use in this public repository: SBOM generation, dependency policy checks, static analysis with CodeQL, deterministic release verification and GitHub artifact attestations.

## Validation surfaces

### In CI (`.github/workflows/ci.yml`)

The primary CI workflow performs:

- the dependency policy over the shipped dependency graph (`just deny`): bans, licenses and sources on every run; RustSec advisories and the `deny.toml` ignore expiry check when `Cargo.toml`, `Cargo.lock` or `deny.toml` change
- the test suite with an enforced line-coverage threshold, the doctests and the privileged real-overlayfs tests, which support security-sensitive change control
- the canonical Nix build of `.#nails-release` with an archive smoke test
- the release SBOM and the VEX document, written and checked by `sbom.yml` as a release writes and checks them, on every push to `main` and on pull requests that change what they are made from; nothing is attested there

### Weekly (`.github/workflows/scheduled.yml`)

The scheduled workflow never gates a merge. It runs:

- the dependency policy over every target and dev-dependency (`just deny-full`)
- the `deny.toml` ignore expiry check
- two from-source builds of `.#nails-release` on fresh runners, compared byte for byte (`reproducibility.yml`)

### Weekly and on every push to main (`.github/workflows/scorecard.yml`)

OpenSSF Scorecard grades the repository's supply-chain practices and never gates a merge; the README badge and code scanning show the results ([ci.md](ci.md#openssf-scorecard)).

### On pull requests, on pushes to main and next, and weekly (`.github/workflows/codeql.yml`)

CodeQL analyses the Rust workspace and the Python with the `security-extended` queries, and the workflows with its default suite. Its alerts go to code scanning, whose check on a pull request fails on a new alert with a severity of error, critical or high ([ci.md](ci.md#codeql)).

### In release automation (`.github/workflows/release.yml`)

The release workflow adds:

- a check that the annotated tag, the workspace version, `Cargo.lock` and `CHANGELOG.md` agree
- the canonical Nix build of `.#nails-release`, compiled from source with `--locked`
- an independent rebuild on a fresh runner, compared byte for byte via `reproducibility.yml`
- the whole E2E suite on the tagged commit, without the project's binary cache, so every test boots there instead of counting a pass from an earlier run
- the release SBOM, musl included, checked for what `actions/attest` requires before the E2E suite starts, and an OpenVEX document for musl's patched CVEs
- GitHub artifact attestations for the archive, the binary, the SBOM and the VEX document, created only after every gate passed, attached to the release as Sigstore bundles and checked with cosign before the release is drafted

[ci.md](ci.md#release-workflow) describes the jobs.

## SBOMs

### Generate locally

The release SBOM describes the `nails` binary for the release target, without build-time dependencies:

```bash
cargo cyclonedx --manifest-path nails-cli/Cargo.toml --format json --spec-version 1.5 \
  --target x86_64-unknown-linux-musl --describe binaries --no-build-deps
```

It writes `nails-cli/nails_bin.cdx.json`. The release workflow then adds musl, which the binary links statically and cargo cannot see, with `python3 -m ci.release sbom-libc`. The version is that of `.#nails.libc`, the musl of the pinned nixpkgs, which the release build links instead of the copy that ships with the Rust toolchain. The CVEs that nixpkgs patches that musl against, read from the names of its patches, are recorded as backported fixes in the component's `pedigree`. The component also carries musl's CPE, so scanners check it against vulnerability data. Scanners such as grype ignore `pedigree`, so the release also publishes `musl.openvex.json`, an OpenVEX document that marks the same CVEs as fixed in musl, written by `python3 -m ci.release musl-vex`. Without it, a scan reports the patched CVEs as open.

The release workflow runs `cargo cyclonedx` with `SOURCE_DATE_EPOCH` set to the commit time, so the SBOM is the same on every run for a tag. cargo-cyclonedx then leaves out its random serial number, which `actions/attest` requires of a CycloneDX SBOM; `sbom-libc` sets a UUIDv5 of the file's download URL on the release instead.

### Validate format locally

```bash
cyclonedx validate --input-file sbom.cdx.json --input-format json --input-version v1_5 --fail-on-errors
```

Without `--fail-on-errors`, `cyclonedx validate` reports problems but still exits 0.

### Where SBOMs appear

| Source | Asset | Notes |
|---|---|---|
| Published GitHub releases and prereleases | `sbom.cdx.json`, `musl.openvex.json` | Produced and attested by `release.yml` |
| `ci.yml` runs with an `sbom` job | `sbom.cdx.json`, `musl.openvex.json` in the `release-sbom` artifact | Written for `v` plus the workspace version and checked as a release checks them; never attested or published |

### Example downstream use

```bash
grype sbom:sbom.cdx.json --vex musl.openvex.json
```

## Dependency policy

`deny.toml` holds the cargo-deny policy: RustSec advisories (vulnerabilities, unmaintained and unsound crates, yanked releases), bans, licenses and sources. The `justfile` checks it at two scopes:

| Recipe | Scope | Where it runs |
|---|---|---|
| `just deny` | The shipped graph: the x86_64 Linux release targets without dev-dependencies | Merge gate in `ci.yml`; run locally with `just deny` |
| `just deny-full` | Every target and every dev-dependency | Weekly in `scheduled.yml`; never blocks a merge |

Both recipes take the checks to run, for example `just deny advisories`.

In CI, bans, licenses and sources are checked on every run. Advisories are checked when `Cargo.toml`, `Cargo.lock` or `deny.toml` change, and on manual runs. Advisory results follow the RustSec database rather than the change under review, so a newly published advisory does not turn unrelated pull requests or `main` red; the weekly full-graph scan reports it instead. Crates that never ship, such as wasm-only crates or benchmark dependencies, are outside the merge gate and covered only by that scan.

### Ignoring an advisory

An ignore is a last resort. Each entry in `[advisories] ignore` needs a `reason` and a `# expires: YYYY-MM-DD` line in the comment block directly above it, at most 180 days ahead:

```toml
ignore = [
    # Only reachable from the benchmarks; drop once criterion updates.
    # expires: 2027-01-31
    { id = "RUSTSEC-0000-0000", reason = "dev-only, never shipped" },
]
```

`ci/deny_ignores.py` fails when an ignore has no expiry, a malformed one, one that has passed, or one more than 180 days ahead. It runs in CI next to the advisory check, weekly in `scheduled.yml`, and as a pre-commit hook whenever `deny.toml` changes.

### Run locally

The tools come from the flake dev shell:

```bash
nix develop -c just deny        # the merge gate
nix develop -c just deny-full   # the weekly full-graph scan
python3 ci/deny_ignores.py
```

## Deterministic release verification

The release path is intentionally stricter than standard CI.

### Canonical build

```bash
nix build -L .#nails-release -o result --option accept-flake-config false
```

### What is verified in automation

- the release derivation builds successfully
- the archive contains `LICENSE`, `README.md`, and the `nails` binary
- the binary runs with `--version` and reports the tagged version
- `checksums.txt` matches the archive and the binary
- an independent rebuild on a fresh runner matches the binary, the archive and `checksums.txt` byte for byte; this cross-runner comparison is the reproducibility evidence

For PRs and pushes, the `nix-build` job of `ci.yml` validates the same release derivation used by the release workflow.

## Provenance and verification

The release workflow creates GitHub artifact attestations: Sigstore-signed SLSA build provenance for the archive and the binary, an SBOM attestation that binds `sbom.cdx.json` to them, and an OpenVEX attestation for `musl.openvex.json`. They meet SLSA v1.0 Build Level 2, signed provenance from a hosted build platform; the build does not run in an isolated reusable workflow, so the project does not claim Build Level 3. Each release carries them as Sigstore bundles (`provenance.sigstore.json`, `sbom.sigstore.json`, `vex.sigstore.json`), so cosign can check a download without a GitHub account.

[verify-release.md](verify-release.md) is the one description of how to check a release: the checksum, the attestation, and where to do it without leaving a trace on the decoy system.

## Pre-merge and local validation

Useful local commands before opening or updating a PR:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
just deny
cargo nextest run --no-fail-fast --status-level all
cargo llvm-cov --all-features --workspace --all-targets --cobertura --output-path ./coverage/cobertura.xml
```

CI enforces a single line-coverage floor over production code, defined once in
`.config/coverage.toml` and read by `just coverage`. The in-memory filesystem
mock, the shared test fixtures and every test file are excluded, so the figure
measures only code that ships.

## Public release behavior

- An annotated `v<version>` tag on `main` starts the release workflow, which drafts the GitHub release; a maintainer publishes the draft ([RELEASING.md](../RELEASING.md)).
- `X.Y.Z-rc.N` versions are drafted as prereleases; a `-dev` version is never released.
- Release artifacts are intended to be independently verifiable by public users.

## Caveats

- GitHub artifact attestations depend on GitHub platform support to be signed. Checking one needs cosign (or the GitHub CLI), not a GitHub account, and a network connection unless cosign gets a saved copy of Sigstore's public keys.
- Workflow artifacts are temporary; published release assets are the public release channel.
- Provenance proves build origin and integrity, not that the software is free of design or implementation flaws.

## Related documents

- [SECURITY.md](../SECURITY.md)
- [docs/ci.md](ci.md)
- [docs/verify-release.md](verify-release.md)
- [docs/release-artifact-reproducibility.md](release-artifact-reproducibility.md)
