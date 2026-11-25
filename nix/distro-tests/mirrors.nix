# Where a prepared test image is fetched from, and the one place that knows it.
#
# The desktop test images are not committed to this repository: they are built
# every night in CI from pinned inputs (an upstream cloud image or installer
# ISO, and a package snapshot), and each result is published as a release asset of a separate public
# assets repository (every asset stays under the 2 GiB release-asset limit).
# An entry whose own upstream carries a bootable cloud image (Debian and Ubuntu
# through nix-vm-test, Fedora and arch-boxes through a hash-pinned `fetchurl`)
# needs no mirror; an entry that has no upstream URL of its own -- the
# archinstall image, which is assembled rather than downloaded -- can only come
# from this mirror.
#
# `base` is the release-download root of that assets repository,
# WitteShadovv/nails-test-images. The test-images workflow
# (.github/workflows/test-images.yml) builds each image every night and uploads
# it there under a name of its own, so a pin in images.json keeps naming the
# same file while newer builds land beside it. ci/distro_images.py reads `base`
# and the tag shape below out of this file, for the weekly link check and for
# `repin`, so both stay written as plain strings. An empty base would read as
# "mirror not configured yet": no mirror entry is then fetched or checked.
rec {
  base = "https://github.com/WitteShadovv/nails-test-images/releases/download";

  # The release tag that holds a family's nightly assets. One rolling tag per
  # family keeps every build of it under one release, beside the
  # `<family>-latest.json` manifest that names the newest.
  tagFor = family: "images-${family}";

  # The download URL for one mirrored asset, or null when no mirror is set or
  # the entry names no asset yet. Keeping the whole shape in one function means
  # a change to the hosting layout is a change here alone.
  urlFor =
    { family, asset }:
    if base == "" || asset == null then null else "${base}/${tagFor family}/${asset}";
}
