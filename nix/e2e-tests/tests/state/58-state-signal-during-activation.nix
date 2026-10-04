# Test 58: Signal during activation
#
# A SIGINT or SIGTERM received while activation is parked in the Activating state
# must roll the activation back cleanly: the cancellation checkpoint after the
# gate returns Cancelled, the overlay rollback and StateGuard run, and the system
# is left Inactive with no overlays mounted, so a following `nails emergency`
# exits 0. A SIGHUP is NOT a cancellation: a terminal hangup must let the
# activation run to completion.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  stateHelpers = import ./../../lib/state-helpers.nix;
in
{
  name = "state-signal-during-activation";
  meta.tags = [
    "state"
    "faults"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # The Activating gate (NAILS_TEST_ACTIVATING_GATE_PATH) is a test-hooks-only
      # hook, so run the nails-e2e package that carries it.
      environment.systemPackages = [ self.packages.x86_64-linux.nails-e2e ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${stateHelpers.installActivationGateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-tests/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    overlay_targets = ["/home", "/etc", "/root", "/srv", "/tmp"]

    def park_activation_at_gate(unit_name):
        # Arm the Activating gate, launch an overlay-only activation detached in a
        # transient unit so we can signal it, and wait until it is parked just
        # after the Activating state transition (the cancellation checkpoint sits
        # immediately after the gate). setupHiddenVolume left the backend open and
        # mounted, and neither the rollback nor `nails emergency` closes it (only a
        # reboot does), so every round runs on that same open backend; opening it
        # again would fail on the existing device-mapper node.
        machine.succeed("mountpoint -q /mnt/data")
        env_prefix, gate_path, entered_path = install_activation_gate()
        run_detached_command(
            unit_name,
            f"{env_prefix} nails --config {headless_config} activate "
            f"--overlay-only --session keep -y",
        )
        machine.wait_until_succeeds(f"test -f {entered_path}", timeout=180)
        wait_for_status_state("Activating", config_path=headless_config, timeout=180)
        return gate_path

    def signal_release_and_wait(signal, gate_path):
        # Signal the nails process itself (by its exact command name), not the
        # whole transient unit: killing the launching shell would let systemd tear
        # the unit's cgroup down with SIGKILL before the rollback could run, which
        # is not what we are testing. Then release the gate so activation resumes
        # into the cancellation checkpoint.
        pid = machine.succeed("pgrep -x nails").strip().splitlines()[0]
        machine.succeed(f"kill -s {signal} {pid}")
        machine.succeed(f"rm -f {gate_path}")

    def assert_cancelled_clean(unit_name, signal):
        gate_path = park_activation_at_gate(unit_name)
        signal_release_and_wait(signal, gate_path)
        # The activation rolls back to Inactive with no overlays mounted.
        wait_for_status_state("Inactive", config_path=headless_config, timeout=180)
        assert_no_overlays(overlay_targets)
        assert_status_state("Inactive", config_path=headless_config)
        # A following emergency teardown succeeds on the already-clean system.
        machine.succeed(f"nails --config {headless_config} emergency")

    with subtest("SIGINT during activation rolls back to a clean inactive state"):
        assert_cancelled_clean("nails-signal-sigint", "SIGINT")

    with subtest("SIGTERM during activation rolls back to a clean inactive state"):
        assert_cancelled_clean("nails-signal-sigterm", "SIGTERM")

    with subtest("SIGHUP does not cancel: activation completes"):
        unit_name = "nails-signal-sighup"
        gate_path = park_activation_at_gate(unit_name)
        signal_release_and_wait("SIGHUP", gate_path)
        # A terminal hangup must not abort the operation: activation runs to
        # completion and the overlays come up.
        wait_for_status_state("Active", config_path=headless_config, timeout=180)
        assert_overlay_mounted("/home")
        assert_status_state("Active", config_path=headless_config)
        # Leave the machine clean for any later use.
        machine.succeed(f"nails --config {headless_config} emergency")
        wait_for_status_state("Inactive", config_path=headless_config, timeout=180)
  '';
}
