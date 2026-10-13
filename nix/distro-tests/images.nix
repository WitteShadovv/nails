# The distribution table: the single source of which distributions the smoke
# suite runs.
#
# Adding a distribution NAILS has a backend for is one entry here. Everything
# downstream -- the per-distribution smoke tests, the flake's `e2e-distro`
# attribute set, the distro metadata the CI planner reads -- is derived by
# mapping over this attribute set, so nothing else has to change.
#
# The cloud images themselves come from nix-vm-test, which pins each one as a
# fixed-output derivation of a dated upstream release. The flake.lock pin of
# nix-vm-test therefore fixes exactly which image every entry boots; bumping
# that input is how the images move forward.
_:
let
  # `distro` is the nix-vm-test distribution set, `image` the key of the
  # release inside it, and `release` the distribution's own version string,
  # used only for diagnostics.
  entry = distro: image: release: { inherit distro image release; };
in
# Every entry must ship systemd 254 or newer: the hidden session is entered and
# left with `systemctl soft-reboot`. Debian 12 "bookworm" (systemd 252) and
# Ubuntu 22.04 "jammy" (249) are refused by `nails check` and are not run.
{
  # Debian 13 "trixie".
  "debian-13" = entry "debian" "13" "13";

  # Ubuntu 24.04 LTS "noble".
  "ubuntu-24.04" = entry "ubuntu" "24_04" "24.04";
}
