# Test 74: Emergency From Activating
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

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
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
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

    expected_overlays = ["/etc", "/home", "/root", "/srv", "/tmp"]

    def assert_expected_overlays(paths):
        for path in paths:
            assert_overlay_mounted(path)

    def assert_status_overlays(paths, payload):
        actual = {overlay["path"] for overlay in payload["overlays"]}
        expected = set(paths)
        assert actual == expected, f"Expected status overlays {expected}, got: {payload}"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
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
            f"{env_prefix} nails --config {headless_config} activate --overlay-only --no-kill-session -y",
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
            f"nails --config {headless_config} status --json | grep -F 'Activating'",
            timeout=180,
        )
        status = read_status_json(config_path=headless_config)
        assert_status_state("activating", payload=status)
        assert status["overlays"] == [], status
        assert_no_overlays(expected_overlays)

    with subtest("emergency fails closed while activation is in progress"):
        prefix = "/run/nails-tests/emergency-from-activating"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency", "--no-countdown"],
            unit_name="nails-emergency-from-activating",
            timeout=30,
        )

        assert result["rc"] == 1, f"Expected emergency to fail from Activating, got: {result}"
        assert "Activating" in result["stderr"], result
        assert "Must be ACTIVE" in result["stderr"], result

        status = read_status_json(config_path=headless_config)
        assert_status_state("activating", payload=status)
        assert status["overlays"] == [], status
        assert_no_overlays(expected_overlays)

    with subtest("releasing activation allows a real active session to be emergency-cleaned"):
        machine.succeed(f"rm -f {gate_path}")
        rc, stdout, stderr = wait_for_captured_command("emergency-activating-primary", timeout=240)
        assert rc == 0, f"Expected activation success, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"
        status = read_status_json(config_path=headless_config)
        assert status["state"].startswith("Active"), status
        assert_status_overlays(expected_overlays, status)
        assert_expected_overlays(expected_overlays)

        prefix = "/run/nails-tests/emergency-from-activating-cleanup"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency", "--no-countdown"],
            unit_name="nails-emergency-from-activating-cleanup",
            timeout=30,
        )

        assert result["rc"] == 0, result
        assert "Emergency deactivation complete" in result["stdout"], result

        assert_no_overlays(expected_overlays)
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
