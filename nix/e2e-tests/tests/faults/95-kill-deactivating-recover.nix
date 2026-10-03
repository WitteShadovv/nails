# Fault test (f): the process is SIGKILLed mid-deactivation.
#
# A `kill -9` during deactivation cannot run any cleanup: the overlays are still
# mounted and state.json is frozen at Deactivating with a dead owner. recover is
# the state-independent cleanup that must finish the job from there — tear the
# surviving overlays down and reset the state to Inactive — without requiring an
# Active state and without a reboot.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  stateHelpers = import ./../../lib/state-helpers.nix;
in
{
  name = "faults-kill-deactivating-recover";
  meta.tags = [
    "faults"
    "state"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # The deactivation gate (NAILS_TEST_DEACTIVATING_GATE_PATH) is a
      # test-hooks-only hook, so run the nails-e2e package that carries it.
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
    ${stateHelpers.installDeactivationGateFn}

    overlay_targets = ["/etc", "/home", "/root", "/srv", "/tmp", "/usr", "/bin", "/lib64"]

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-tests/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activate a hidden session"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")

    with subtest("park a deactivation at the gate and SIGKILL it"):
        env_prefix, gate_path, entered_path = install_deactivation_gate()
        run_detached_command(
            "nails-kill-deactivating",
            f"{env_prefix} nails --config {headless_config} deactivate -y",
        )
        machine.wait_until_succeeds(f"test -f {entered_path}", timeout=180)
        wait_for_status_state("Deactivating", config_path=headless_config, timeout=180)
        # SIGKILL leaves no chance to clean up: the overlays stay mounted and the
        # state is frozen at Deactivating with a dead owner.
        pid = machine.succeed("pgrep -x nails").strip().splitlines()[0]
        machine.succeed(f"kill -9 {pid}")
        machine.succeed(f"rm -f {gate_path}")
        machine.wait_until_fails("pgrep -x nails", timeout=60)
        assert_overlay_mounted("/home")

    with subtest("recover finishes the teardown from the stuck Deactivating state"):
        machine.succeed(f"nails --config {headless_config} recover")
        assert_no_overlays(overlay_targets)
        assert_status_state("inactive", config_path=headless_config)

    with subtest("the backend then closes cleanly with the strict helper"):
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        machine.fail("test -e /dev/mapper/data")
  '';
}
