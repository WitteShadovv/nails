# Where a prepared test image is fetched from, and the one place that knows it.
#
# The desktop test images are not committed to this repository: they are built
# every night in CI from the pinned upstream cloud image plus a pinned package
# snapshot, and each result is published as a release asset of a separate public
# assets repository (every asset stays under the 2 GiB release-asset limit).
# An entry whose own upstream carries a bootable cloud image (Debian and Ubuntu
# through nix-vm-test, Fedora and arch-boxes through a hash-pinned `fetchurl`)
# needs no mirror; an entry that has no upstream URL of its own -- the
# archinstall image, which is assembled rather than downloaded -- can only come
# from this mirror.
#
# `base` is the release-download root of that assets repository. It is empty
# until the assets repository exists, and the `distro-images` check reads an
# empty base as "mirror not configured yet" rather than as an error, so the seam
# can land before the hosting does. The weekly link check probes no mirror
# asset: it lists an enabled mirror entry as not checked. Fill it with
#   "https://github.com/<owner>/<assets-repo>/releases/download"
# once the repository is created; nothing else moves.
rec {
  base = "";

  # The release tag that holds a family's nightly assets. One rolling tag per
  # family keeps a stable download URL while the asset behind it is refreshed.
  tagFor = family: "images-${family}";

  # The download URL for one mirrored asset, or null when no mirror is set or
  # the entry names no asset yet. Keeping the whole shape in one function means
  # a change to the hosting layout is a change here alone.
  urlFor =
    { family, asset }:
    if base == "" || asset == null then null else "${base}/${tagFor family}/${asset}";
}
