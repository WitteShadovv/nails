# Test 77: Emergency Countdown UX

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in
{
  name = "emergency-countdown-ux";
  meta.tags = [ "security" ];

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
    ${sessionHelpers.loginSessionSurvivalFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("--countdown shows an abortable countdown and waits"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")

        sessions_before_emergency = login_session_ids()
        prefix = "/run/nails-tests/emergency-countdown-optin"
        started_at = now()
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency", "--countdown", "3"],
            unit_name="nails-emergency-countdown-optin",
            timeout=45,
        )
        countdown_elapsed = now() - started_at

        assert result["rc"] == 0, result
        assert result["systemd"].get("ExecMainCode") in ("exited", "0"), result
        assert result["systemd"].get("ExecMainStatus") == "0", result
        assert result["systemd"].get("Result") == "success", result
        assert "Emergency teardown complete" in result["stdout"], result
        stderr = result["stderr"]
        for marker in [
            "Emergency deactivation in 3",
            "Emergency deactivation in 2",
            "Emergency deactivation in 1",
            "Emergency deactivation starting now!",
        ]:
            assert marker in stderr, stderr
        # The countdown always prints the Ctrl+C abort hint, regardless of output flags.
        assert "(Ctrl+C to abort)" in stderr, stderr
        assert stderr.find("in 3") < stderr.find("in 2") < stderr.find("in 1") < stderr.find("starting now!"), stderr
        assert countdown_elapsed >= 3.0, f"Countdown completed too quickly: {countdown_elapsed:.3f}s"
        assert countdown_elapsed < 20.0, f"Countdown command took too long: {countdown_elapsed:.3f}s"
        assert_no_overlays(["/home", "/etc"])
        # Emergency must not log the operator out while it tears the overlays down.
        assert_login_sessions_survived(sessions_before_emergency)
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)

    with subtest("default emergency is immediate (no countdown text)"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")

        prefix = "/run/nails-tests/emergency-countdown-immediate"
        started_at = now()
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency"],
            unit_name="nails-emergency-countdown-immediate",
            timeout=30,
        )
        immediate_elapsed = now() - started_at

        assert result["rc"] == 0, result
        assert result["systemd"].get("ExecMainCode") in ("exited", "0"), result
        assert result["systemd"].get("ExecMainStatus") == "0", result
        assert result["systemd"].get("Result") == "success", result
        assert "Emergency deactivation in " not in result["stderr"], result
        assert "starting now!" not in result["stderr"], result
        assert "Emergency teardown complete" in result["stdout"], result
        assert countdown_elapsed - immediate_elapsed >= 2.0, \
            f"Expected the default to skip the ~3s countdown (countdown={countdown_elapsed:.3f}s, immediate={immediate_elapsed:.3f}s)"
        assert immediate_elapsed < 12.0, f"Immediate emergency took too long: {immediate_elapsed:.3f}s"
        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
