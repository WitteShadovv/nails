# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The access-time scenarios (tests/access-times.nix), one per image: Debian 13
# with the release binary, and Fedora 44 with the test-only build in which the
# Fedora row of the family table is admitted (lib/admitted.nix), since the
# release refuses Fedora. What the Fedora run shows says what NAILS reads on
# that image, not that NAILS supports Fedora.
#
# They are host drivers, keyed "<image>-access-times", which the records suite
# of distro-e2e.yml runs beside the login- and boot-record scenarios.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  images = import ./images.nix { inherit pkgs; };
  makeAccessTimes = import ./tests/access-times.nix { inherit pkgs nix-vm-test; };
  admitted = import ./lib/admitted.nix { inherit self; };

  scenario =
    name: nails:
    makeAccessTimes {
      inherit name nails;
      entry = images.${name};
    };

  drivers = {
    "debian-13" = scenario "debian-13" self.packages.x86_64-linux.nails;
    "fedora-44" = scenario "fedora-44" (admitted "fedora");
  };
in
{
  inherit drivers;
  # Both images are pinned.
  runnable = builtins.attrNames drivers;
  # The seconds a run gets: a boot, seven switches and an aging and a listing
  # of the whole decoy disk before and after each phase.
  timeout = 2700;
}
