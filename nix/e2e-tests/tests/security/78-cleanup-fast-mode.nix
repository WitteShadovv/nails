# Test 78: Cleanup Fast Mode
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
in {
  name = "cleanup-fast-mode";
  meta.tags = [ "security" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("plant representative cleanup targets"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        machine.succeed("mkdir -p /mnt/hidden-volume/logs")
        machine.succeed("printf 'fast-mode-log\n' > /mnt/hidden-volume/logs/nails.log")
        machine.succeed("printf 'nails fast mode history\n' >> /home/testuser/.bash_history")
        machine.succeed("printf 'nails temp\n' > /tmp/nails-fast-mode-artifact")
        machine.succeed("test -f /mnt/hidden-volume/logs/nails.log")
        machine.succeed("test -f /tmp/nails-fast-mode-artifact")

    with subtest("emergency path uses fast cleanup semantics"):
        unit_name = "nails-emergency-fast-mode"
        prefix = "/tmp/emergency-fast-mode"
        shell_command = (
            "set +e; systemd-run --unit "
            + unit_name
            + " --wait --collect --service-type=exec /bin/sh -lc "
            + shlex.quote(
                f"nails --config {headless_config} emergency --no-countdown -vv"
            )
            + " > "
            + prefix
            + ".stdout 2> "
            + prefix
            + ".stderr; printf \"%s\" \"$?\" > "
            + prefix
            + ".rc"
        )
        machine.succeed("/bin/sh -lc " + shlex.quote(shell_command))
        result = read_command_result(prefix)
        journal = machine.succeed(f"journalctl -u {unit_name} --no-pager -o cat")

        assert result["rc"] == 0, result
        assert "Emergency cleanup complete (best-effort)" in journal, journal
        assert "Starting Phase 2 cleanup on real disk" not in journal, journal
        assert "Phase 2 cleanup complete" not in journal, journal

    with subtest("fast cleanup still removes key artifacts and leaves inactive state"):
        machine.fail("test -f /tmp/nails-fast-mode-artifact")
        machine.fail("test -f /mnt/hidden-volume/logs/nails.log")
        history_after = machine.succeed("cat /home/testuser/.bash_history 2>/dev/null || true")
        assert "nails fast mode history" not in history_after, history_after
        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
