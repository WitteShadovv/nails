# Verify a release

Each release on the [Releases page](https://github.com/WitteShadovv/nails/releases) holds four
files:

| File | What it is |
|---|---|
| `nails` | The static `x86_64-unknown-linux-musl` binary |
| `nails-<version>-x86_64-unknown-linux-musl.tar.gz` | The same binary with `LICENSE` and `README.md` |
| `checksums.txt` | SHA-256 of the binary and the archive |
| `sbom.cdx.json` | CycloneDX SBOM of the binary: every crate it is built from, and musl |

This page is the only place that describes how to check them. Other documents link here.

## Where to verify

Never download or verify a release on the decoy system. A copy of `nails` on the decoy disk, even
a deleted one, can be recovered and identifies the tool (see
[Keeping NAILS off the decoy](operator-guide.md#keeping-nails-off-the-decoy)). The
browser's download history, the shell history and the GitHub CLI's login token in
`~/.config/gh` would point to it as well.

- **First installation:** boot a live environment that keeps nothing, open and mount the hidden
  volume there, and download into it.
- **Updates:** download from inside an active hidden session, into the hidden volume.

The examples assume the hidden volume is mounted at `/mnt/data` and the release is
`v0.3.0`.

## 1. Download

Only the files you want to check are needed; for most people that is `nails` and `checksums.txt`:

```bash
cd /mnt/data
gh release download v0.3.0 --repo WitteShadovv/nails --pattern nails --pattern checksums.txt
```

Downloading both files from the release page with the browser of the live environment works just
as well.

## 2. Check the checksum

```bash
sha256sum --check --ignore-missing checksums.txt
```

It prints `nails: OK`. `--ignore-missing` skips the entries of `checksums.txt` whose files you did
not download; the command still fails when none of them is present.

A matching checksum shows that the download is complete and unchanged relative to
`checksums.txt`. It says nothing about who built the file, because `checksums.txt` comes from the
same page. The next step does.

## 3. Check the provenance

```bash
gh attestation verify nails --repo WitteShadovv/nails
```

The command succeeds only when a Sigstore-signed attestation, issued to a GitHub Actions workflow
of `WitteShadovv/nails`, covers the SHA-256 of the file. Check that its output names the workflow
`.github/workflows/release.yml` and the ref `refs/tags/v0.3.0`, the tag you downloaded. The same
command works for the archive.

`gh` needs a GitHub login (`gh auth login`), one more reason to run it only where nothing
persists or inside the hidden session.

To check that the SBOM attestation covers the binary as well:

```bash
gh attestation verify nails --repo WitteShadovv/nails --predicate-type https://cyclonedx.org/bom
```

## What the checks prove

- **Integrity:** the file is the one the release lists (step 2).
- **Provenance:** the release workflow of this repository built the file from the tagged commit,
  on a GitHub-hosted runner, after the whole E2E suite passed on that commit (step 3). This is
  GitHub artifact attestation, which meets SLSA v1.0 Build Level 2: signed provenance from a hosted
  build platform. It is not Build Level 3, because the build does not run in a separate,
  isolated reusable workflow.
- **Reproducibility:** before attesting, the release workflow built the bundle a second time on a
  fresh runner and compared the binary, the archive and `checksums.txt` byte for byte. To repeat
  that comparison yourself, see [release-artifact-reproducibility.md](release-artifact-reproducibility.md).

None of these checks says that the code is free of flaws; [threat-model.md](threat-model.md) sets
out what NAILS does and does not protect against.
