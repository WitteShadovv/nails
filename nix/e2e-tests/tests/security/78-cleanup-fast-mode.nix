# Test 78: Cleanup Fast Mode

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
  perf = import ./../../lib/perf.nix;
in
{
  name = "cleanup-fast-mode";
  meta.tags = [ "security" ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}
    ${perf.nailsDurationFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    decoy_history = "/home/testuser/.bash_history"
    # No "nails" in the name, so the pre-activation hygiene leaves it alone.
    decoy_temp = "/tmp/fast-mode-decoy-artifact"

    def stat_times(path):
        return machine.succeed(f"stat -c '%s %Y %X' {path}").strip()

    with subtest("plant decoy files before activation and session artifacts during it"):
        machine.succeed(f"printf 'decoy temp\n' > {decoy_temp}")
        # Let the timestamps settle so a later read or write would show.
        machine.succeed("sleep 1")
        decoy_temp_before = stat_times(decoy_temp)
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
        machine.succeed("printf 'nails fast mode history\n' >> /home/testuser/.bash_history")

    with subtest("emergency runs no artifact cleanup after the unmount"):
        unit_name = "nails-emergency-fast-mode"
        prefix = "/run/nails-tests/emergency-fast-mode"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency", "-vv"],
            unit_name=unit_name,
            timeout=45,
        )
        combined_output = result["stdout"] + "\n" + result["stderr"]

        assert result["rc"] == 0, result
        assert result["systemd"].get("ExecMainCode") in ("exited", "0"), result
        assert result["systemd"].get("ExecMainStatus") == "0", result
        assert result["systemd"].get("Result") == "success", result
        assert "Emergency cleanup complete" not in combined_output, combined_output
        assert "Phase 2 cleanup" not in combined_output, combined_output
        # The page cache is dropped after unmount (requires root; the VM runs as
        # root), and the log must say so honestly rather than "memory sanitized".
        assert "page cache dropped" in combined_output, combined_output
        assert "memory saniti" not in combined_output.lower(), combined_output
        # nails' own measurement of the teardown, so a stall of the host or
        # of the driver polling the unit cannot fail the check.
        elapsed_ms = deactivation_duration_ms(result["stderr"])
        assert elapsed_ms is not None, combined_output
        assert elapsed_ms < 10000, f"Fast-mode emergency took too long: {elapsed_ms} ms"

    with subtest("decoy files are neither written nor read after the unmount"):
        assert stat_times(decoy_temp) == decoy_temp_before, stat_times(decoy_temp)
        history_after = machine.succeed(f"cat {decoy_history} 2>/dev/null || true")
        assert "nails fast mode history" not in history_after, history_after
        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
