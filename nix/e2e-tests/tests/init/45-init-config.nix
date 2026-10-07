# `nails init` and config validation on the shared base node, one VM boot.
#
# init-bootstrap, init-idempotency, init-refuse-overwrite and
# config-unknown-key were single-boot tests with the same node (the standard
# decoy VM plus nails; their node derivations were identical). Each runs as a
# scenario (lib/batch.nix): it starts from a guest as clean as it booted and the
# guest is reset before the next one. config-unknown-key runs last because it
# runs a real emergency teardown. The old test names stay aliases of this test.

args@{ pkgs, ... }:
let
  batch = import ./../../lib/batch.nix { inherit (pkgs) lib; };
  scenario = path: import path args;
in
batch.mkBatch {
  name = "init-config";
  tags = [
    "init"
    "config"
    "smoke"
  ];

  scenarios = map scenario [
    ./../../scenarios/init/45-init-bootstrap.nix
    ./../../scenarios/init/46-init-idempotency.nix
    ./../../scenarios/init/47-init-refuse-overwrite.nix
    ./../../scenarios/config/23-config-unknown-key.nix
  ];
}
