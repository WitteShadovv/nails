# The distribution image table: the single source of which distributions the
# smoke suite runs and where each cloud image comes from.
#
# Adding a distribution NAILS has a backend for is one entry here. Everything
# downstream -- the per-distribution smoke tests, the flake's `e2e-distro`
# attribute set, the distro metadata the CI planner reads -- is derived by
# mapping over this attribute set, so nothing else has to change.
#
# Each image is pinned as a fixed-output derivation (`pkgs.fetchurl`): the
# `sha256` content-addresses it, so once a release is pinned, upstream pruning
# the cloud image cannot change what the suite runs. Mirror the pinned files
# into the project binary cache so a pruned upstream URL still resolves.
#
#   IMPORTANT (deferred): the `sha256` values below are placeholders
#   (`lib.fakeHash`). They cannot be computed in the development sandbox, which
#   has no network and no Nix daemon. Before the suite builds, fetch each image
#   once on a networked host and replace the placeholder with the real hash
#   (`nix store prefetch-file --json <url>` prints it), then mirror the file to
#   the binary cache. The build fails loudly on a placeholder hash, so a forgotten
#   pin cannot slip through as a passing run.
{ pkgs }:
let
  inherit (pkgs) lib;

  # `cloud` builds one pinned image entry. `url`/`sha256` content-address the
  # download; `format` is the on-disk image format nix-vm-test boots (qcow2 for
  # every current entry). `release` is the distribution's own version string,
  # used only for diagnostics. Keeping this a small constructor means a new
  # distribution is a single `cloud { ... }` call below.
  cloud =
    {
      distro,
      release,
      url,
      sha256,
      format ? "qcow2",
    }:
    {
      inherit
        distro
        release
        format
        ;
      image = pkgs.fetchurl { inherit url sha256; };
    };
in
{
  # Debian 12 "bookworm" generic cloud image (amd64).
  "debian-12" = cloud {
    distro = "debian";
    release = "12";
    url = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2";
    sha256 = lib.fakeHash;
  };

  # Debian 13 "trixie" generic cloud image (amd64).
  "debian-13" = cloud {
    distro = "debian";
    release = "13";
    url = "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2";
    sha256 = lib.fakeHash;
  };

  # Ubuntu 24.04 LTS "noble" server cloud image (amd64).
  "ubuntu-24.04" = cloud {
    distro = "ubuntu";
    release = "24.04";
    url = "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img";
    sha256 = lib.fakeHash;
  };
}
