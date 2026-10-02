# Test 03: Emergency Deactivation
# Tests the functional emergency workflow and cleanup behavior

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "emergency";
  meta.tags = [
    "security"
    "smoke"
    "forensic"
  ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
        services.getty.autologinUser = "root";
        systemd.services.nails-emergency-test = emergency.makeEmergencyUnit self.packages.x86_64-linux.nails "/tmp/nails-headless.toml";
      };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${emergency.prepareTty1ShellFn}
    ${emergency.waitForConsoleLogFn}
    ${emergency.rebootAfterEmergencyFn}
    ${emergency.runEmergencyCommandFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    def assert_session_data_gone():
        assert_no_overlays(["/home", "/etc"])
        for marker in ("secret_1", "secret_50", "secret_100"):
            machine.fail(f"su - testuser -c 'test -f ~/{marker}.txt'")
        history = machine.succeed(
            "su - testuser -c 'cat ~/.bash_history 2>/dev/null || echo gone'"
        )
        assert "sensitive_command_1" not in history, \
            f"shell history still holds sensitive commands: {history!r}"
        assert "secret_key_export" not in history, \
            f"shell history still holds the secret key export: {history!r}"

    with subtest("set up an active session with sensitive data"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
        machine.succeed("su - testuser -c 'for i in $(seq 1 100); do echo \"secret data $i\" > ~/secret_$i.txt; done'")
        machine.succeed("su - testuser -c 'echo \"sensitive_command_1\" >> ~/.bash_history'")
        machine.succeed("su - testuser -c 'echo \"secret_key_export\" >> ~/.bash_history'")
        machine.succeed("su - testuser -c 'test -s ~/.bash_history'")
        for marker in ("secret_1", "secret_50", "secret_100"):
            machine.succeed(f"su - testuser -c 'test -f ~/{marker}.txt'")

    with subtest("emergency teardown cleans the live system before any reboot"):
        # Stop short of the reboot so the assertions below prove the emergency
        # command itself tore the session down, not a lucky reboot.
        emergency_time = run_emergency_command(reboot=False)
        print(f"✓ emergency command completed in {emergency_time:.3f}s")
        assert_session_data_gone()

    with subtest("the decoy state survives the reboot"):
        reboot_after_emergency()
        assert_session_data_gone()
        assert_status_state("inactive", config_path=headless_config)
  '';
}
