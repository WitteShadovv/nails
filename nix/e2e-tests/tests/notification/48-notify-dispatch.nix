# The notification dispatcher on the shared base node, one VM boot.
#
# notify-malformed-signal, notify-no-notify-send and
# notify-dispatch-signal-flow were single-boot tests with the same node (the
# standard decoy VM plus nails, without notify-send, which the absence test
# relies on; their node derivations were identical). Each runs as a scenario
# (lib/batch.nix): it starts from a guest as clean as it booted and the guest is
# reset before the next one, which also deletes the notify-send stubs the
# earlier scenarios install under /tmp. notify-dispatch-signal-flow activates,
# so it runs last. The old test names stay aliases of this test.

args@{ pkgs, ... }:
let
  batch = import ./../../lib/batch.nix { inherit (pkgs) lib; };
  scenario = path: import path args;
in
batch.mkBatch {
  name = "notify-dispatch";
  tags = [
    "notification"
    "smoke"
  ];

  scenarios = map scenario [
    ./../../scenarios/notification/50-notify-malformed-signal.nix
    ./../../scenarios/notification/51-notify-no-notify-send.nix
    ./../../scenarios/notification/48-notify-dispatch-signal-flow.nix
  ];
}
