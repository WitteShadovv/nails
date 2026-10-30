# Releasing NAILS

A release is one annotated `v*` tag on `main`. Pushing it starts `.github/workflows/release.yml`,
which checks the tag, builds the bundle from source, rebuilds it on a fresh runner, generates the
SBOM, runs the whole E2E suite, attests the files, checks the attestations as users will and
drafts the GitHub release. Publishing the draft is the only manual step after the tag.
[docs/ci.md](docs/ci.md#release-workflow) describes the jobs;
[docs/verify-release.md](docs/verify-release.md) is what users run on the result.

## Versions

- `X.Y.Z` is a stable release and `X.Y.Z-rc.N` a release candidate, published as a prerelease.
- Between releases, `main` carries the next version with a `-dev` suffix, for example
  `0.4.0-dev`. The release workflow refuses to release a `-dev` version.
- The tag is always `v` plus the version in `Cargo.toml`: `v0.3.0`, `v0.3.0-rc.1`.

## Checklist

1. **Set the version.** On a branch, set `version` under `[workspace.package]` in `Cargo.toml`
   to the release version, run `cargo update --workspace`, `just fuzz-lock` and `just gui-lock`,
   and commit `Cargo.toml` together with `Cargo.lock`, `fuzz/Cargo.lock` and `gui/Cargo.lock`
   (the window's workspace links `nails-api`, which takes the root version). The release build runs
   cargo with `--locked` and fails on a stale `Cargo.lock`, and the `lint` job of `ci.yml` on a
   stale lock of any of the three; `cargo metadata --locked` (with `--manifest-path` for the other
   two) shows the same failure locally.
2. **Refresh the screenshots.** The README shows real output, rendered from the captures in
   `docs/assets/screenshots/`, and nothing checks that a capture still matches what NAILS
   prints. On the branch, with the version set, run
   `nix build -L .#e2e.session-readme-captures` (a decoy set up as the docs recommend; the test
   fails when `check` or `activate` prints a warning) and copy the `check`, `activate` and
   `status --json` output of that one run, unedited, below the `---` line of `check.txt`,
   `activate.txt` and `status-json.txt`. Replace the output in `help.txt` with what `nails -h`
   prints from a build of the branch. Update the dates in the captions, run
   `scripts/render-terminal-svg.py --all docs/assets/screenshots`, and commit the captures with
   their SVGs. [docs/assets/README.md](docs/assets/README.md) has the details.
3. **Write the changelog.** In `CHANGELOG.md`, rename `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD` and open a new, empty `## [Unreleased]` above it. That section
   becomes the release notes word for word, so write it for users.
4. **Merge** the pull request into `main` once `gate` and `e2e-result` are green.
5. **Wait for the runs on `main`.** The push of the merge commit starts `ci.yml`, whose `sbom`
   job writes and checks the SBOM as the release run will, and `e2e.yml`.
   On `main`, `e2e.yml` runs the whole suite (mode `all`) on the runners the release run uses,
   while the pull request's `e2e-result` may have covered only the affected tests. Tag only once
   both runs are green: a test that fails there costs a fix on `main`, one that fails in the
   release run costs the version, because a pushed tag is never re-created (see
   [When something fails](#when-something-fails)). If the path filter skipped the E2E run, the
   last E2E run on `main` must be green. The push run takes a test that passed before from the
   binary cache, but the release run boots every test. So a run that boots every test must also
   have passed on the commit: the nightly run, or a dispatch that runs the suite as the release
   will:

   ```bash
   gh workflow run e2e.yml --ref main -f mode=all -f cache=false
   ```
6. **Tag** the merge commit with an annotated tag and push only that tag:

   ```bash
   git switch main && git pull --ff-only
   git tag -a vX.Y.Z -m "nails X.Y.Z"
   git push origin vX.Y.Z
   ```

   A lightweight tag fails the first job.
7. **Watch the run.** The first job fails within seconds when the tag, `Cargo.lock` or the
   changelog section is wrong, and the `sbom` job within minutes, before the E2E suite starts,
   when `actions/attest` would refuse the SBOM; the whole run takes about as long as the E2E
   suite. A failed run opens or comments on the `CI red: Release` issue.
8. **Review the draft** on the Releases page: the notes, and the eight assets (the archive,
   `nails`, `checksums.txt`, `sbom.cdx.json`, `musl.openvex.json` and the Sigstore bundles
   `provenance.sigstore.json`, `sbom.sigstore.json`, `vex.sigstore.json`). Drafts are visible to
   maintainers only, and the download URLs work only once a release is published, so download
   `nails`, `checksums.txt` and `provenance.sigstore.json` from the draft and follow
   [docs/verify-release.md](docs/verify-release.md) from step 2.
9. **Publish** the draft. Once published, a release, its assets and its tag never change. For a
   candidate, keep "Set as a pre-release"; the workflow ticks it for `-rc.N` versions.
10. **Open the next cycle.** Bump `main` to the next `-dev` version (for example `0.3.1-dev` or
    `0.4.0-dev`) with `Cargo.lock` and `fuzz/Cargo.lock` (`just fuzz-lock`), in a pull request of
    its own.

## When something fails

- **An infrastructure failure** (runner, network, flaky test): re-run the failed jobs from the run
  page, or dispatch the workflow again. A dispatch must run from the tag itself, so that the
  provenance names the tag:

  ```bash
  gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z
  ```

  The dispatch also takes `e2e-runner` and `e2e-max-shards`, to run the E2E suite on a
  self-hosted runner. The workflow never touches an existing release, so delete a draft left by an
  earlier attempt first.
- **A problem in the code, the version or the changelog**: never move or re-create a pushed tag.
  Delete the draft, fix the problem on `main`, and release the next version: a new `-rc.N`, or the
  next patch version.

## One-time repository setup

These steps clean up what earlier release workflows left behind and protect the tags. They need
admin rights on the repository and are not automated.

1. Delete the stray tags `list` and `listr`:

   ```bash
   git push origin :refs/tags/list :refs/tags/listr
   ```

2. Delete the `v0.1.0-git.*` prereleases together with their tags:

   ```bash
   gh release list --repo WitteShadovv/nails --limit 100 --json tagName \
     --jq '.[].tagName | select(startswith("v0.1.0-git."))' |
     while read -r tag; do
       gh release delete "$tag" --repo WitteShadovv/nails --cleanup-tag --yes
     done
   ```

3. Add a tag ruleset (Settings, Rules, Rulesets, New tag ruleset) that targets `refs/tags/v*`,
   restricts creation, update and deletion to maintainers, and blocks force pushes. Rulesets cannot
   require annotated tags; the release workflow refuses lightweight ones.
4. Enable release immutability (Settings, General, Releases), so a published release, its assets
   and its tag can no longer change.
