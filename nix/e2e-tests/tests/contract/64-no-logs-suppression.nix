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

    def assert_hidden_logs_empty():
        machine.succeed(
            "bash -lc '"
            + "if [ ! -d /mnt/hidden-volume/logs ]; then exit 0; fi; "
            + "shopt -s nullglob dotglob; files=(/mnt/hidden-volume/logs/*); "
            + "[ ''${#files[@]} -eq 0 ]'"
        )

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.yaml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activation with --no-logs succeeds without creating hidden logs"):
        assert_hidden_logs_empty()
        machine.succeed(
            f"nails --no-logs --config {headless_config} activate --overlay-only --no-kill-session -y --plain"
        )
        assert_status_state("Active", config_path=headless_config)
        assert_hidden_logs_empty()
        machine.fail("test -e /mnt/hidden-volume/logs/nails.log")

    with subtest("deactivation with --no-logs also leaves hidden logs empty"):
        run_detached_command(
            "nails-deactivate-no-logs-suppression",
            f"nails --no-logs --config {headless_config} deactivate --plain",
        )
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        assert_hidden_logs_empty()
        machine.fail("test -e /mnt/hidden-volume/logs/nails.log")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
