# Release Artifact Reproducibility

NAILS currently verifies deterministic release artifacts for one canonical target:

- flake attribute: `.#nails-release`
- target triple: `x86_64-unknown-linux-musl`
- artifact: `nails-<version>-git.<shortsha>-x86_64-unknown-linux-musl.tar.gz`

## What is guaranteed

For each `dev` and `main` build, CI:

- builds the canonical release bundle with Nix
- runs `nix-store --realise --check` against the release derivation
- rebuilds the same artifact in two independent GitHub Actions jobs
- compares the canonical bundle, checksums, metadata, and binary hash byte-for-byte

This is evidence of deterministic output for the pinned source revision, flake inputs, build instructions, and tested CI build environment.

## What is not guaranteed

This does not, by itself, establish that any third party can reproduce identical bytes outside the tested build definition.
Reproducible-builds.org definitions depend on the same source, relevant build environment, and build instructions being available and matched.

## Rebuild the canonical artifact locally

Check out the exact commit you want to verify in a clean working tree, then run:

```bash
git checkout <commit-or-tag>
nix build -L .#nails-release -o result --option accept-flake-config false
```

The canonical release files will be in `result/`.

To run the same determinism check locally:

```bash
drv=$(nix path-info --derivation .#nails-release)
nix-store --realise "$drv" --check -K
```

## Attestation vs reproducibility

GitHub artifact attestation and reproducibility answer different questions:

- attestation provides provenance about which GitHub workflow produced the published artifact
- reproducibility asks whether the same source, build instructions, and relevant build environment can produce the same bytes

An attested artifact is traceable to CI, but attestation alone does not prove reproducibility.
