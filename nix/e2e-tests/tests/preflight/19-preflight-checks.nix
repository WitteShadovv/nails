# Preflight checks on the shared base node, one VM boot for all of them.
#
# These were four single-boot tests with the same node (the standard decoy VM
# plus nails; their node derivations were identical). Each now runs as a
# scenario of this test: it starts with a check that the guest is as clean as it
# booted, keeps its own subtests and assertions, and the guest is reset before
# the next one (lib/batch.nix, nails_e2e/batch.py). The old test names stay
# aliases of this test; preflight-pending-offline-update was written as a
# scenario. preflight-state-check enters and leaves a hidden session (two
# soft-reboots), so it runs last.

args@{ pkgs, ... }:
let
  batch = import ./../../lib/batch.nix { inherit (pkgs) lib; };
  scenario = path: import path args;
in
batch.mkBatch {
  name = "preflight-checks";
  tags = [
    "preflight"
    "smoke"
  ];

  scenarios = map scenario [
    ./../../scenarios/preflight/19-preflight-nixos-config.nix
    ./../../scenarios/preflight/21-preflight-nixos-build-target.nix
    ./../../scenarios/preflight/24-preflight-upper-fs-capability.nix
    ./../../scenarios/preflight/26-preflight-pending-offline-update.nix
    ./../../scenarios/preflight/20-preflight-state-check.nix
  ];

  # The offline-update scenario stages /system-update on the decoy root, outside
  # every scratch directory; a later scenario would be refused while it stays.
  cleanupPaths = [ "/system-update" ];
}
