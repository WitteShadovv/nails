# Release artifact reproducibility

NAILS verifies deterministic release artifacts for one canonical target:

- flake attribute: `.#nails-release`
- target triple: `x86_64-unknown-linux-musl`
- artifact: `nails-<version>-x86_64-unknown-linux-musl.tar.gz`, next to the bare `nails` binary
  and `checksums.txt`

## What is guaranteed

For every release, the release workflow:

- builds the canonical release bundle with Nix, with the project binary cache disabled, so the
  `nails` binary is compiled from source instead of being fetched
- builds the same bundle again, independently, on a fresh GitHub-hosted runner
- compares the two byte for byte: the binary, the archive and `checksums.txt`

The cross-runner comparison is the evidence that the binary is reproducible: two runners compiled
it separately and produced the same bytes. The same comparison runs every week on `main`, with two
independent builds, so a regression shows up before the next release.

`nix-store --realise --check` is not part of this evidence. It rebuilds only the top-level
derivation, which here is the archive packaging, on the same machine and from the same compiled
binary; at most it shows that the packaging is deterministic.

This is evidence of deterministic output for the pinned source revision, flake inputs, build
instructions, and tested CI build environment.

## What is not guaranteed

This does not, by itself, establish that any third party can reproduce identical bytes outside the
tested build definition. Reproducible-builds.org definitions depend on the same source, relevant
build environment, and build instructions being available and matched.

## Rebuild a release locally

Check out the release tag in a clean clone, so that the archive gets the commit time of the tag
as its file times, then build:

```bash
git clone https://github.com/WitteShadovv/nails && cd nails
git checkout vX.Y.Z
nix build -L .#nails-release -o result --option accept-flake-config false
```

Compare the result with the `checksums.txt` of the release:

```bash
diff result/checksums.txt /path/to/downloaded/checksums.txt
```

No output means that your build produced the same binary and archive as the release. The same
OPSEC rules as for verifying a download apply: do this in a live environment or an active hidden
session, never on the decoy system (see [verify-release.md](verify-release.md#where-to-verify)).

## Attestation vs reproducibility

GitHub artifact attestation and reproducibility answer different questions:

- attestation provides provenance about which GitHub workflow produced the published artifact
- reproducibility asks whether the same source, build instructions, and relevant build environment
  can produce the same bytes

An attested artifact is traceable to CI, but attestation alone does not prove reproducibility.
[verify-release.md](verify-release.md) describes how to check the attestation.
