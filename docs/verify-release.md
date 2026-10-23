# Verify a release

Each release on the [Releases page](https://github.com/WitteShadovv/nails/releases) holds eight
files:

| File | What it is |
|---|---|
| `nails` | The static `x86_64-unknown-linux-musl` binary |
| `nails-<version>-x86_64-unknown-linux-musl.tar.gz` | The same binary with `LICENSE` and `README.md` |
| `checksums.txt` | SHA-256 of the binary and the archive |
| `provenance.sigstore.json` | The signed build provenance of the binary and the archive |
| `sbom.cdx.json` | CycloneDX SBOM of the binary: every crate it is built from, and musl |
| `sbom.sigstore.json` | The signed attestation that binds the SBOM to the binary and the archive |
| `musl.openvex.json` | OpenVEX statements that the musl in the binary is patched against the CVEs it names |
| `vex.sigstore.json` | The signed attestation that binds the VEX document to the binary and the archive |

The three `.sigstore.json` files are Sigstore bundles. Each holds one attestation, the signature
over it, the certificate of the release run that signed it and the proof that the signature is in
Sigstore's public transparency log. With them, checking a release needs no GitHub account.
Releases 0.2.0 and older have none of these three: their provenance is `nails.intoto.jsonl`, made
by the SLSA GitHub generator in an older format, so step 3 does not apply to them. The
documentation at their tag says how to check it.

This page is the only place that describes how to check them. Other documents link here.

## Where to verify

Never download or verify a release on the decoy system. A copy of `nails` on the decoy disk, even
a deleted one, can be recovered and identifies the tool (see
[Keeping NAILS off the decoy](operator-guide.md#keeping-nails-off-the-decoy)). The
browser's download history and the shell history would point to it as well, and so would the
files the tools below keep in the home directory: cosign's copy of Sigstore's public keys in
`~/.sigstore`, and the GitHub CLI's copy in `~/.cache/gh` and its login token in `~/.config/gh`.

- **First installation:** boot a live environment that keeps nothing, open and mount the hidden
  volume there, and download into it. [First install from Tails](install-from-tails.md) goes
  through it with Tails.
- **Updates:** download from inside an active hidden session, into the hidden volume.

The examples assume the hidden volume is mounted at `/mnt/data` and the release is
`v0.3.0`.

## 1. Download

For most people three files are enough: `nails`, `checksums.txt` and `provenance.sigstore.json`.
Download them from the release page with the browser of the live environment, or:

```bash
cd /mnt/data
tag=v0.3.0
for file in nails checksums.txt provenance.sigstore.json; do
  curl -fsSLO "https://github.com/WitteShadovv/nails/releases/download/$tag/$file"
done
```

Neither way needs a GitHub account. The commands below use `$tag` as well.

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

### Get cosign

[cosign](https://github.com/sigstore/cosign), the Sigstore project's command-line tool, checks the
bundles. Use cosign 3.1.3 or later, or 2.6.5 or later on the older 2.x line. Earlier releases can
print `Verified OK` for an attestation that the command below must refuse
([GHSA-w6c6-c85g-mmv6](https://github.com/sigstore/cosign/security/advisories/GHSA-w6c6-c85g-mmv6),
[GHSA-fx35-mq7g-6g98](https://github.com/sigstore/cosign/security/advisories/GHSA-fx35-mq7g-6g98)).
`cosign version` prints the release you have. Distribution packages lag behind: Debian 13 has
cosign 2.5.0, Ubuntu 26.04 2.6.2 and Ubuntu 26.10 3.1.1, all too old, while NixOS 26.05 has 3.1.3.
[Sigstore's installation guide](https://docs.sigstore.dev/cosign/system_config/installation/)
lists the other ways to get it, among them the static `cosign-linux-amd64` binary from cosign's
[releases](https://github.com/sigstore/cosign/releases), and how to check that binary.

cosign fetches Sigstore's current public keys from `tuf-repo-cdn.sigstore.dev` each time it runs,
so it needs a network connection. It asks GitHub for nothing. To check without a connection, give
it the keys as a file instead (see [Without a network connection](#without-a-network-connection)).

### Check the binary

```bash
identity="https://github.com/WitteShadovv/nails/.github/workflows/release.yml@refs/tags/$tag"
cosign verify-blob-attestation \
  --bundle provenance.sigstore.json \
  --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "$identity" \
  --check-claims=true \
  nails
```

It prints `Verified OK` only when all of this holds:

- The certificate in the bundle was issued to a GitHub Actions run (`--certificate-oidc-issuer`)
  of the release workflow of this repository for the tag you downloaded
  (`--certificate-identity`, with the identity set on the first line). The attestation is
  signed with it, and the signature is in Sigstore's transparency log.
- The attestation is build provenance (`--type slsaprovenance1`), not another kind of signed
  statement.
- The attestation names the SHA-256 of the file you check (`--check-claims=true`, which is also
  cosign's default). Never set it to `false`: cosign then checks only the signature, and any file
  passes.

The identity must name the tag exactly as you downloaded it: an attestation from a run for another
tag or for a branch does not match. To check the archive, put its name in place of `nails`.

### Check the SBOM and the VEX document

`sbom.sigstore.json` binds the SBOM, which it contains, to the binary and the archive, and
`vex.sigstore.json` does the same for the VEX document. To check them, download them as in step 1
and run the same command with their bundle and type, in the same shell as above:

```bash
cosign verify-blob-attestation \
  --bundle sbom.sigstore.json \
  --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "$identity" \
  --check-claims=true \
  nails

cosign verify-blob-attestation \
  --bundle vex.sigstore.json \
  --type https://openvex.dev/ns/v0.2.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "$identity" \
  --check-claims=true \
  nails
```

The VEX document needs the full type: cosign's short name `openvex` stands for
`https://openvex.dev/ns`, without the version the attestation names.

These checks cover the SBOM and the VEX document inside the bundles. `sbom.cdx.json` and
`musl.openvex.json` are the same documents as plain files, which the release workflow compared
with the bundles before it drafted the release. To use the checked copy itself, take it out of
its bundle (with `jq`):

```bash
jq -r .dsseEnvelope.payload sbom.sigstore.json | base64 -d | jq .predicate > sbom.checked.cdx.json
jq -r .dsseEnvelope.payload vex.sigstore.json | base64 -d | jq .predicate > musl.checked.openvex.json
```

### Without a network connection

cosign can also check the bundles on a computer without a network connection, if it gets
Sigstore's public keys as a file. Fetch them once where you have a connection, into the directory
of the downloads:

```bash
TUF_ROOT="$PWD/sigstore" cosign initialize
cp sigstore/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json .
```

`cosign initialize` downloads the keys and checks their signatures against the root of trust that
is built into cosign; `TUF_ROOT` keeps them out of `~/.sigstore`. Take `trusted_root.json` along
with the release files, and add `--trusted-root trusted_root.json` to each
`cosign verify-blob-attestation` command above. cosign then needs no connection and writes nothing
to the home directory. Sigstore adds new keys from time to time, so fetch a fresh copy before you
check a newer release.

### With the GitHub CLI instead

`gh` checks the same bundle:

```bash
identity="https://github.com/WitteShadovv/nails/.github/workflows/release.yml@refs/tags/$tag"
gh attestation verify nails --repo WitteShadovv/nails \
  --bundle provenance.sigstore.json \
  --cert-identity "$identity"
```

With `sbom.sigstore.json`, add `--predicate-type https://cyclonedx.org/bom`; with
`vex.sigstore.json`, `--predicate-type https://openvex.dev/ns/v0.2.0`. Without `--bundle`, `gh`
fetches the attestation from GitHub instead, which needs a GitHub login (`gh auth login`).

## What the checks prove

- **Integrity:** the file is the one the release lists (step 2).
- **Provenance:** the release workflow of this repository built the file from the tagged commit,
  on a GitHub-hosted runner, after the whole E2E suite passed on that commit (step 3). This is
  GitHub artifact attestation, which meets SLSA v1.0 Build Level 2: signed provenance from a hosted
  build platform. It is not Build Level 3, because the build does not run in a separate,
  isolated reusable workflow. Before it drafted the release, the workflow checked every bundle
  with the commands above.
- **Reproducibility:** before attesting, the release workflow built the binary and the archive a
  second time on a fresh runner and compared them and `checksums.txt` byte for byte. To repeat
  that comparison yourself, see [release-artifact-reproducibility.md](release-artifact-reproducibility.md).

Releases are published as immutable releases: once a release is published, GitHub lets no one
change its files or move its tag.

None of these checks says that the code is free of flaws; [threat-model.md](threat-model.md) sets
out what NAILS does and does not protect against.
