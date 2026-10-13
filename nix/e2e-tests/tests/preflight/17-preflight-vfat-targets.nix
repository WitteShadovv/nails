# Preflight checks against FAT filesystems: a FAT hidden volume cannot hold
# symlinks or an overlay upper and is refused (preflight-symlink-support). The
# former preflight-overlay-compat scenario (a small VFAT overlay target pivoted
# through a RAM snapshot) is gone with the per-directory overlays: a FAT
# filesystem in the decoy's fstab is now bound read-only into the hidden root
# (see session-fstab-policy). It runs as a scenario (lib/batch.nix).

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
    ./../../scenarios/preflight/18-preflight-symlink-support.nix
  ];
}
