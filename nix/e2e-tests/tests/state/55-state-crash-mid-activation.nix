# Test 55: State Crash Mid Activation

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  stateHelpers = import ./../../lib/state-helpers.nix;
in
{
  name = "state-crash-mid-activation";
  meta.tags = [
    "state"
    "faults"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # Drives the activation/deactivation gates (NAILS_TEST_*_GATE_PATH), a
      # test-hooks-only hook, so it runs the nails-e2e package.
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
    ${stateHelpers.captureCommandFns}
    ${stateHelpers.installSlowNixosRebuildGateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-tests/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    bin_dir, gate_path, entered_path = install_slow_nixos_rebuild_gate(
        gate_path="/tmp/nails-crash-rebuild.gate",
        entered_path="/tmp/nails-crash-rebuild-entered",
    )

    with subtest("drive activation into a durable activating state"):
        run_detached_captured_command(
            "nails-activate-crash-mid-activation",
            "state-crash-primary",
            f"PATH={bin_dir}:$PATH nails --config {headless_config} activate --session keep -y",
        )
        machine.wait_until_succeeds(f"test -f {entered_path}", timeout=180)
        wait_for_status_state("Activating", config_path=headless_config, timeout=180)
        assert_status_state("Activating", config_path=headless_config)

    with subtest("crash the machine mid-activation"):
        machine.crash()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        write_headless_config(headless_config)

    with subtest("the crashed boot's Activating state is reconciled, not trusted"):
        # Re-open the hidden backend so status actually reads the state file that
        # survived the crash. Reading it while the backend is closed would hit a
        # missing file that defaults to Inactive, making the assertion vacuous.
        # The file still records the crashed boot's Activating state, but the boot
        # id now differs, so reconciliation must surface it as a safe-to-reset
        # stale state: the raw recorded kind is still "activating", while the
        # reconciled posture is the decoy, and no overlays are mounted.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        payload = read_status_json(config_path=headless_config)
        assert payload["state"]["kind"] == "activating", payload
        assert payload["posture"] == "decoy", payload

    with subtest("recover clears the stale transitional state (T-107)"):
        # recover is the state-independent cleanup added in T-107: it reconciles
        # the stale Activating file against the live mount table and resets it to
        # Inactive without requiring an Active state and without rebooting.
        # Reverting that fix removes the recover command, so this subtest fails.
        machine.succeed(f"nails --config {headless_config} recover")
        payload = read_status_json(config_path=headless_config)
        assert payload["state"]["kind"] == "inactive", payload
        assert payload["posture"] == "decoy", payload

    with subtest("re-activation after the reset really mounts the overlays"):
        # With the stale state reconciled away, a fresh activation must actually
        # mount overlays rather than refuse or silently no-op.
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=headless_config, timeout=180)
        assert_overlay_mounted("/home")
        assert_status_state("Active", config_path=headless_config)
  '';
}
