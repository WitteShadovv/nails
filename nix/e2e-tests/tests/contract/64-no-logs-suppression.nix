# Test 64: Log-File Suppression (--no-log-file)
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

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

    with subtest("deactivation with --no-log-file succeeds"):
        run_detached_command(
            "nails-deactivate-no-logs-suppression",
            f"nails --no-log-file --config {headless_config} deactivate -y --ascii",
        )
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        print(f"Note: hidden log size after --no-log-file deactivation: {hidden_log_size()} bytes")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
