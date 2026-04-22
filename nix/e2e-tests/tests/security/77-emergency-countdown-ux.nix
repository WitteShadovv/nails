# Test 77: Emergency Countdown UX
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
in
{
  name = "emergency-countdown-ux";
  meta.tags = [ "security" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    def now():
        import time

        return time.time()

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("default emergency countdown is visible and ordered"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

        prefix = "/run/nails-tests/emergency-countdown-default"
        started_at = now()
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency"],
            unit_name="nails-emergency-countdown-default",
            timeout=45,
        )
        default_elapsed = now() - started_at

        assert result["rc"] == 0, result
        assert result["systemd"].get("ExecMainCode") in ("exited", "0"), result
        assert result["systemd"].get("ExecMainStatus") == "0", result
        assert result["systemd"].get("Result") == "success", result
        assert "Emergency deactivation complete" in result["stdout"], result
        stderr = result["stderr"]
        for marker in [
            "Emergency deactivation in 3",
            "Emergency deactivation in 2",
            "Emergency deactivation in 1",
            "Emergency deactivation starting now!",
        ]:
            assert marker in stderr, stderr
        assert stderr.find("in 3") < stderr.find("in 2") < stderr.find("in 1") < stderr.find("starting now!"), stderr
        assert default_elapsed >= 3.0, f"Countdown completed too quickly: {default_elapsed:.3f}s"
        assert default_elapsed < 20.0, f"Countdown command took too long: {default_elapsed:.3f}s"
        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)

    with subtest("--no-countdown removes countdown text and delay"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

        prefix = "/run/nails-tests/emergency-countdown-disabled"
        started_at = now()
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency", "--no-countdown"],
            unit_name="nails-emergency-countdown-disabled",
            timeout=30,
        )
        no_countdown_elapsed = now() - started_at

        assert result["rc"] == 0, result
        assert result["systemd"].get("ExecMainCode") in ("exited", "0"), result
        assert result["systemd"].get("ExecMainStatus") == "0", result
        assert result["systemd"].get("Result") == "success", result
        assert "Emergency deactivation in " not in result["stderr"], result
        assert "starting now!" not in result["stderr"], result
        assert "Emergency deactivation complete" in result["stdout"], result
        assert default_elapsed - no_countdown_elapsed >= 2.0, \
            f"Expected --no-countdown to skip roughly three seconds (default={default_elapsed:.3f}s, no-countdown={no_countdown_elapsed:.3f}s)"
        assert no_countdown_elapsed < 12.0, f"--no-countdown command took too long: {no_countdown_elapsed:.3f}s"
        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
