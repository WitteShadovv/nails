# Test 74: Emergency From Activating

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
  stateHelpers = import ./../../lib/state-helpers.nix;
in
{
  name = "emergency-from-activating";
  meta.tags = [ "security" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # This test drives the activation gate (NAILS_TEST_*_GATE_PATH), which
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
    ${stateHelpers.captureCommandFns}
    ${stateHelpers.installActivationGateFn}

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

    env_prefix, gate_path, entered_path = install_activation_gate(
        gate_path="/run/nails-tests/nails-emergency-activating.gate",
        entered_path="/run/nails-tests/nails-emergency-activating-entered",
    )

    with subtest("prepare a real in-flight activating state"):
        run_detached_captured_command(
            "nails-emergency-activating-primary",
            "emergency-activating-primary",
            f"{env_prefix} nails --config {headless_config} activate --overlay-only --session keep -y",
        )
        primary_rc_path = "/tmp/emergency-activating-primary.rc"
        machine.wait_until_succeeds(
            f"test -f {entered_path} || test -f {primary_rc_path}",
            timeout=180,
        )
        if machine.execute(f"test -f {primary_rc_path}")[0] == 0:
            rc, stdout, stderr = wait_for_captured_command("emergency-activating-primary", timeout=5)
            raise AssertionError(
                "Activation exited before reaching the Activating gate: "
                f"rc={rc}, stdout={stdout!r}, stderr={stderr!r}"
            )
        machine.succeed(f"test -f {entered_path}")
        machine.wait_until_succeeds(
            f"nails --config {headless_config} status --json | grep -F '\"kind\":\"activating\"'",
            timeout=180,
        )
        status = read_status_json(config_path=headless_config)
        assert_status_state("activating", payload=status)
        assert status["overlays"] == [], status
        assert_no_overlays(expected_overlays)

        # The parked activation keeps a progress record on the hidden volume, so
        # status shows the phase it is in and how long it has been running. An
        # overlay-only run has five steps; it is parked in session management.
        flight = status["activation_in_flight"]
        assert flight["phase"] == "session_management", status
        assert flight["step"] == 2 and flight["total_steps"] == 5, status
        assert flight["elapsed_seconds"] >= 0, status
        human = machine.succeed(f"nails --config {headless_config} status")
        assert "Activation:         in progress: Preparing session management (2/5)" in human, human

    with subtest("the activation is interrupted, leaving a stuck Activating state"):
        # SIGKILL the parked activation so nothing finishes or rolls back the
        # switch: state.json stays frozen at Activating. This is the realistic
        # precondition for an emergency from this state (a crashed or killed
        # activation), without racing a still-live owner.
        pid = machine.succeed("pgrep -x nails").strip().splitlines()[0]
        machine.succeed(f"kill -9 {pid}")
        machine.succeed(f"rm -f {gate_path}")
        machine.wait_until_fails("pgrep -x nails", timeout=60)

        # With no live owner the frozen Activating state is inconsistent with the
        # kernel, so status reports the posture fail-closed: exit 7 (degraded,
        # reboot or tear down) with the payload still written.
        rc, status = read_status_json_with_rc(config_path=headless_config)
        assert rc == 7, f"expected status to fail closed (exit 7), got rc={rc}: {status}"
        assert status["posture"] == "inconsistent", status
        assert_status_state("activating", payload=status)

    with subtest("emergency tears down from the stuck Activating state"):
        # Emergency is state-independent: from a non-Active state it enumerates
        # the live NAILS mounts from the kernel mount table, tears them down and
        # converges to Inactive instead of refusing.
        prefix = "/run/nails-tests/emergency-from-activating"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency"],
            unit_name="nails-emergency-from-activating",
            timeout=60,
        )

        assert result["rc"] == 0, f"Expected emergency to succeed from Activating, got: {result}"

        assert_no_overlays(expected_overlays)
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)

    with subtest("a fresh activation after the teardown can be emergency-cleaned"):
        # The gate file is gone, so this activation runs straight through.
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
        status = read_status_json(config_path=headless_config)
        assert status["state"]["kind"] == "active", status
        assert_status_overlays(expected_overlays, status)
        # A completed activation records its duration and leaves no activation in
        # flight.
        assert status["last_activation"]["duration_ms"] > 0, status
        assert "activation_in_flight" not in status, status
        assert_expected_overlays(expected_overlays)

        prefix = "/run/nails-tests/emergency-from-activating-cleanup"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency"],
            unit_name="nails-emergency-from-activating-cleanup",
            timeout=30,
        )

        assert result["rc"] == 0, result
        assert "Emergency teardown complete" in result["stdout"], result

        assert_no_overlays(expected_overlays)
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
