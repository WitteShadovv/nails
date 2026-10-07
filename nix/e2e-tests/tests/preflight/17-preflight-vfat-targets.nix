# Preflight checks against FAT filesystems, one VM boot for both.
#
# preflight-overlay-compat (a small VFAT overlay target) and
# preflight-symlink-support (a FAT hidden volume) were single-boot tests with
# the same node: the standard decoy VM plus nails and dosfstools for mkfs.vfat.
# Their node derivations were identical, and this test declares that node
# unchanged. Each runs as a scenario (lib/batch.nix): it starts from a guest as
# clean as it booted and the guest is reset before the next one. The old test
# names stay aliases of this test.

args@{ self, pkgs, ... }:
let
  batch = import ./../../lib/batch.nix { inherit (pkgs) lib; };
  scenario = path: import path args;
in
batch.mkBatch {
  name = "preflight-vfat-targets";
  tags = [
    "preflight"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.dosfstools
      ];
    };

  scenarios = map scenario [
    ./../../scenarios/preflight/17-preflight-overlay-compat.nix
    ./../../scenarios/preflight/18-preflight-symlink-support.nix
  ];
}
