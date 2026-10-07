# verify and config handling on the shared base node, one VM boot.
#
# verify (clean, dirty and active verification states) and config-handling
# (--config, invalid, missing and unreadable configs) were single-boot tests
# with the same node (the standard decoy VM plus nails; their node derivations
# were identical). Each runs as a scenario (lib/batch.nix): it starts from a
# guest as clean as it booted and the guest is reset before the next one.
# verify runs first, because its baseline deep scan is the most sensitive to
# anything an earlier scenario could leave behind. Both old names stay aliases
# of this test, so the `ci` group keeps running it.

args@{ pkgs, ... }:
let
  batch = import ./../../lib/batch.nix { inherit (pkgs) lib; };
  scenario = path: import path args;
in
batch.mkBatch {
  name = "smoke-verify-config";
  tags = [
    "smoke"
    "contract"
  ];

  scenarios = map scenario [
    ./../../scenarios/smoke/02-verify.nix
    ./../../scenarios/smoke/08-config-handling.nix
  ];
}
