# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The access-time scenarios (tests/access-times.nix), one per image, each with
# the release binary: Debian 13, and Fedora 44 booted with SELinux enforcing as
# the image table pins it.
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

  scenario =
    name: nails:
    makeAccessTimes {
      inherit name nails;
      entry = images.${name};
    };

  drivers = {
    "debian-13" = scenario "debian-13" self.packages.x86_64-linux.nails;
    "fedora-44" = scenario "fedora-44" self.packages.x86_64-linux.nails;
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
