# Test 64: Log-File Suppression (--no-log-file)

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "no-logs-suppression";
  meta.tags = [ "contract" ];

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

    def hidden_log_size():
        return int(
            machine.succeed(
                "bash -lc '"
                + "if [ -f /mnt/data/logs/nails.log ]; then stat -c %s /mnt/data/logs/nails.log; else echo 0; fi'"
            ).strip()
        )

    def nails_journal_lines():
        # Any record the nails process wrote to the journal would carry its
        # command name. With logging suppressed there must be none.
        raw = machine.succeed(
            "journalctl -b --no-pager -o cat _COMM=nails 2>/dev/null || true"
        )
        return [
            line
            for line in raw.splitlines()
            if line.strip() and line.strip() != "-- No entries --"
        ]

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.toml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activation with --no-log-file succeeds without touching the log file"):
        size_before = hidden_log_size()
        machine.succeed(
            f"nails --no-log-file --config {headless_config} activate --overlay-only --session keep -y --ascii"
        )
        size_after = hidden_log_size()
        assert size_after == size_before, (size_before, size_after)
        assert_status_state("Active", config_path=headless_config)
        # --no-log-file silences every sink, not just the file: nails must not
        # fall back to the journal.
        leaked = nails_journal_lines()
        assert not leaked, f"nails leaked {len(leaked)} journal line(s) under --no-log-file: {leaked[:5]}"

    with subtest("deactivation with --no-log-file succeeds"):
        run_detached_command(
            "nails-deactivate-no-logs-suppression",
            f"nails --no-log-file --config {headless_config} deactivate -y --ascii",
        )
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        # The whole --no-log-file cycle must leave the hidden log untouched.
        size_final = hidden_log_size()
        assert size_final == size_before, (size_before, size_final)
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
