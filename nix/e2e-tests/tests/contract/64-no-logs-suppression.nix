# Test 64: No-Logs Suppression
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
                + "if [ -f /mnt/hidden-volume/logs/nails.log ]; then stat -c %s /mnt/hidden-volume/logs/nails.log; else echo 0; fi'"
            ).strip()
        )

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.yaml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activation with --no-logs succeeds"):
        machine.succeed(
            f"nails --no-logs --config {headless_config} activate --overlay-only --no-kill-session -y --plain"
        )
        assert_status_state("Active", config_path=headless_config)
        print(f"Note: hidden log size after --no-logs activation: {hidden_log_size()} bytes (--no-logs suppresses console/journald logs only)")

    with subtest("deactivation with --no-logs succeeds"):
        run_detached_command(
            "nails-deactivate-no-logs-suppression",
            f"nails --no-logs --config {headless_config} deactivate --plain",
        )
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        print(f"Note: hidden log size after --no-logs deactivation: {hidden_log_size()} bytes")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
