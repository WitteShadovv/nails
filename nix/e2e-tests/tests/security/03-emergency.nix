# Test 03: Emergency Deactivation
# Tests the functional emergency workflow and cleanup behavior

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  assertions = import ./../../lib/assertions.nix;
in {
  name = "emergency";
  meta.tags = [ "security" "smoke" "forensic" ];

  nodes = {
    machine = { ... }: {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      services.getty.autologinUser = "root";
      systemd.services.nails-emergency-test =
        emergency.makeEmergencyUnit self.packages.x86_64-linux.nails
        "/tmp/nails-headless.yaml";
    };
  };

  testScript = _: ''
    import time

    ${testHelpers.writeHeadlessConfigFn}
    ${emergency.prepareTty1ShellFn}
    ${emergency.waitForConsoleLogFn}
    ${emergency.rebootAfterEmergencyFn}
    ${emergency.runEmergencyCommandFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    print("\n=== Setting up active session with data ===")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
    print("✓ NAILS activated")

    machine.succeed("su - testuser -c 'for i in $(seq 1 100); do echo \"secret data $i\" > ~/secret_$i.txt; done'")
    print("✓ Created 100 secret files")

    machine.succeed("su - testuser -c 'echo \"sensitive_command_1\" >> ~/.bash_history'")
    machine.succeed("su - testuser -c 'echo \"secret_key_export\" >> ~/.bash_history'")
    machine.succeed("su - testuser -c 'echo \"password_entry\" >> ~/.bash_history'")
    machine.succeed("su - testuser -c 'test -f ~/.bash_history && test -s ~/.bash_history'")
    print("✓ Added shell history entries")

    machine.succeed("su - testuser -c 'test -f ~/secret_1.txt'")
    machine.succeed("su - testuser -c 'test -f ~/secret_50.txt'")
    machine.succeed("su - testuser -c 'test -f ~/secret_100.txt'")
    print("✓ Verified data exists")

    print("\n=== Running Emergency Deactivation ===")
    emergency_time = run_emergency_command()
    print(f"✓ Emergency command completed in {emergency_time:.3f}s")

    print("\n=== Verifying Clean State ===")
    assert_no_overlays(["/home", "/etc"])
    print("✓ Overlays unmounted")

    machine.fail("su - testuser -c 'test -f ~/secret_1.txt'")
    machine.fail("su - testuser -c 'test -f ~/secret_50.txt'")
    machine.fail("su - testuser -c 'test -f ~/secret_100.txt'")
    print("✓ All secret files removed")

    history_check = machine.succeed("su - testuser -c 'cat ~/.bash_history 2>/dev/null || echo \"gone\"'")
    assert "sensitive_command_1" not in history_check, "Shell history not cleaned - sensitive commands found"
    assert "secret_key_export" not in history_check, "Shell history not cleaned - secret key export found"
    print("✓ Shell history cleaned")

    status = machine.succeed(f"nails --config {headless_config} status")
    assert "Inactive" in status or "INACTIVE" in status, f"Expected Inactive in status, got: {status}"
    print("✓ NAILS status reports inactive")

    print("\n=== All Emergency Tests Passed ===")
  '';
}
