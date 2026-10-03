# Test 75: Emergency From Deactivating

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
  stateHelpers = import ./../../lib/state-helpers.nix;
in
{
  name = "emergency-from-deactivating";
  meta.tags = [ "security" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # This test drives the deactivation gate (NAILS_TEST_*_GATE_PATH), which
      # exists only in the test-hooks build, so it runs the nails-e2e package.
      environment.systemPackages = [
        self.packages.x86_64-linux.nails-e2e
        pkgs.python3
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}
    ${stateHelpers.installDeactivationGateFn}

    # The headless config also overlays the base-OS trees (/usr, /bin, /lib64).
    expected_overlays = ["/etc", "/home", "/root", "/srv", "/tmp", "/usr", "/bin", "/lib64"]

    def assert_expected_overlays(paths):
        for path in paths:
            assert_overlay_mounted(path)

    def assert_status_overlays(paths, payload):
        actual = {overlay["mount_point"] for overlay in payload["overlays"]}
        expected = set(paths)
        assert actual == expected, f"Expected status overlays {expected}, got: {payload}"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    env_prefix, gate_path, entered_path = install_deactivation_gate(
        gate_path="/run/nails-tests/nails-emergency-deactivating.gate",
        entered_path="/run/nails-tests/nails-emergency-deactivating-entered",
    )

    with subtest("prepare active session before real deactivation gate"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
        status = read_status_json(config_path=headless_config)
        assert status["state"]["kind"] == "active", status
        assert_status_overlays(expected_overlays, status)
        assert_expected_overlays(expected_overlays)

    with subtest("prepare a real in-flight deactivating state"):
        run_detached_command(
            "nails-emergency-deactivating-primary",
            f"{env_prefix} nails --config {headless_config} deactivate -y",
        )
        machine.wait_until_succeeds(
            f"test -f {entered_path}",
            timeout=180,
        )
        machine.succeed(f"test -f {entered_path}")
        machine.wait_until_succeeds(
            f"nails --config {headless_config} status --json | grep -F '\"kind\":\"deactivating\"'",
            timeout=180,
        )
        status = read_status_json(config_path=headless_config)
        assert_status_state("deactivating", payload=status)
        assert status["overlays"] == [], status
        assert_expected_overlays(expected_overlays)

    with subtest("the deactivation is interrupted, leaving a stuck Deactivating state"):
        # SIGKILL the parked deactivation so nothing finishes the teardown: the
        # overlays stay mounted and state.json is frozen at Deactivating. This is
        # the realistic precondition for an emergency from this state (a stuck or
        # crashed teardown), without the race of signalling a still-live owner.
        pid = machine.succeed("pgrep -x nails").strip().splitlines()[0]
        machine.succeed(f"kill -9 {pid}")
        machine.succeed(f"rm -f {gate_path}")
        machine.wait_until_fails("pgrep -x nails", timeout=60)

        status = read_status_json(config_path=headless_config)
        assert_status_state("deactivating", payload=status)
        assert_expected_overlays(expected_overlays)

    with subtest("emergency finishes the teardown from the stuck Deactivating state"):
        # Emergency is state-independent after T-107: from a non-Active state it
        # enumerates the live NAILS overlays from the kernel mount table and tears
        # them down, converging to Inactive without requiring an Active state and
        # without a reboot.
        prefix = "/run/nails-tests/emergency-from-deactivating"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency"],
            unit_name="nails-emergency-from-deactivating",
            timeout=60,
        )

        assert result["rc"] == 0, f"Expected emergency to succeed from Deactivating, got: {result}"

        assert_no_overlays(expected_overlays)
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
