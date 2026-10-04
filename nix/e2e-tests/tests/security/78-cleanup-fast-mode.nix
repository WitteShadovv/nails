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

    with subtest("plant representative cleanup targets"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
        machine.succeed("mkdir -p /mnt/data/logs")
        machine.succeed("printf 'fast-mode-log\n' > /mnt/data/logs/nails.log")
        machine.succeed("printf 'nails fast mode history\n' >> /home/testuser/.bash_history")
        machine.succeed("printf 'nails temp\n' > /tmp/nails-fast-mode-artifact")
        machine.succeed("test -f /mnt/data/logs/nails.log")
        machine.succeed("test -f /tmp/nails-fast-mode-artifact")

    with subtest("emergency path uses fast cleanup semantics"):
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
        assert "Emergency cleanup complete (best-effort)" in combined_output, combined_output
        assert "Starting Phase 2 cleanup on real disk" not in combined_output, combined_output
        assert "Phase 2 cleanup complete" not in combined_output, combined_output
        # The page cache is dropped after unmount (requires root; the VM runs as
        # root), and the log must say so honestly rather than "memory sanitized".
        assert "page cache dropped" in combined_output, combined_output
        assert "memory saniti" not in combined_output.lower(), combined_output
        # nails' own measurement of the teardown, so a stall of the host or
        # of the driver polling the unit cannot fail the check.
        elapsed_ms = deactivation_duration_ms(result["stderr"])
        assert elapsed_ms is not None, combined_output
        assert elapsed_ms < 10000, f"Fast-mode emergency took too long: {elapsed_ms} ms"

    with subtest("fast cleanup still removes key artifacts and leaves inactive state"):
        machine.fail("test -f /tmp/nails-fast-mode-artifact")
        machine.fail("test -f /mnt/data/logs/nails.log")
        history_after = machine.succeed("cat /home/testuser/.bash_history 2>/dev/null || true")
        assert "nails fast mode history" not in history_after, history_after
        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
