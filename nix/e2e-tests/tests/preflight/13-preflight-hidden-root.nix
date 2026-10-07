# Preflight checks on the hidden root itself, one VM boot for both.
#
# preflight-hidden-volume (unmounted, read-only, immutable and store-backed
# hidden roots) and preflight-mount-namespace (activation from a private mount
# namespace) were single-boot tests on the decoy VM plus nails and e2fsprogs.
# preflight-mount-namespace also listed util-linux, which lib/vm-config.nix
# already installs, so its package set was the same; this test declares
# preflight-hidden-volume's node unchanged. Each runs as a scenario
# (lib/batch.nix): it starts from a guest as clean as it booted and the guest
# is reset before the next one. The old test names stay aliases of this test.

args@{ self, pkgs, ... }:
let
  batch = import ./../../lib/batch.nix { inherit (pkgs) lib; };
  scenario = path: import path args;
in
batch.mkBatch {
  name = "preflight-hidden-root";
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
        pkgs.e2fsprogs
      ];
    };

  scenarios = map scenario [
    ./../../scenarios/preflight/13-preflight-hidden-volume.nix
    ./../../scenarios/preflight/23-preflight-mount-namespace.nix
  ];
}
