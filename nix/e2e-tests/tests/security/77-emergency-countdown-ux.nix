# Test 77: Emergency Countdown UX
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
in {
  name = "emergency-countdown-ux";
  meta.tags = [ "security" ];

  nodes.machine = { ... }: {
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

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("default emergency countdown is visible and ordered"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

        prefix = "/tmp/emergency-countdown-default"
        stderr_path = prefix + ".stderr"
        started_at = now()
        run_captured_command(
            prefix,
            f"nails --config {headless_config} emergency",
            unit_name="nails-emergency-countdown-default",
            background=True,
        )

        machine.wait_until_succeeds(f"grep -Fq 'Emergency deactivation in 3' {stderr_path}")
        machine.wait_until_succeeds(f"grep -Fq 'Emergency deactivation in 2' {stderr_path}")
        machine.wait_until_succeeds(f"grep -Fq 'Emergency deactivation in 1' {stderr_path}")
        machine.wait_until_succeeds(f"grep -Fq 'Emergency deactivation starting now!' {stderr_path}")
        result = wait_for_command_result(prefix)
        default_elapsed = now() - started_at

        assert result["rc"] == 0, result
        assert "Emergency deactivation complete" in result["stdout"], result
        stderr = result["stderr"]
        assert stderr.count("Emergency deactivation in ") == 3, stderr
        assert stderr.find("in 3") < stderr.find("in 2") < stderr.find("in 1") < stderr.find("starting now!"), stderr
        assert default_elapsed >= 3.0, f"Countdown completed too quickly: {default_elapsed:.3f}s"
        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)

    with subtest("--no-countdown removes countdown text and delay"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

        prefix = "/tmp/emergency-countdown-disabled"
        started_at = now()
        run_captured_command(
            prefix,
            f"nails --config {headless_config} emergency --no-countdown",
        )
        result = read_command_result(prefix)
        no_countdown_elapsed = now() - started_at

        assert result["rc"] == 0, result
        assert "Emergency deactivation in " not in result["stderr"], result
        assert "starting now!" not in result["stderr"], result
        assert "Emergency deactivation complete" in result["stdout"], result
        assert default_elapsed - no_countdown_elapsed >= 2.0, \
            f"Expected --no-countdown to skip roughly three seconds (default={default_elapsed:.3f}s, no-countdown={no_countdown_elapsed:.3f}s)"
        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
