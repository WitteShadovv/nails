# Story 13.5: Emergency Deactivation Test
# Tests the functional emergency workflow and cleanup behavior

{ self, ... }:
let
  hiddenVolume = import ./../lib/hidden-volume.nix;
  testHelpers = import ./../lib/test-helpers.nix;
in {
  name = "emergency";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      services.getty.autologinUser = "root";
      systemd.services.nails-emergency-test = {
        description = "NAILS emergency test runner";
        serviceConfig = {
          Type = "exec";
          ExecStart =
            "${self.packages.x86_64-linux.nails}/bin/nails --config /tmp/nails-headless.yaml emergency --no-countdown";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };
    };
  };

  testScript = _: ''
    import re
    import time

    ${testHelpers.writeHeadlessConfigFn}

    def wait_for_console_log(regex, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if re.search(regex, machine.get_console_log()):
                return
            time.sleep(0.2)
        raise AssertionError(f"Timed out after {timeout}s waiting for console log regex: {regex}")

    def prepare_tty1_shell():
        machine.wait_for_unit("getty@tty1.service")
        machine.send_key("alt-f1")
        machine.wait_until_tty_matches("1", r"#", timeout=60)
        machine.send_chars("export PS1='TTY1_READY# '\n", delay=0)
        machine.wait_until_tty_matches("1", r"TTY1_READY#", timeout=30)

    def reboot_after_emergency():
        machine.send_key("ctrl-alt-delete")
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")

    def run_emergency_command():
        prepare_tty1_shell()

        start_time = time.time()
        machine.send_key("alt-f1")
        machine.send_chars("systemctl start --no-block nails-emergency-test.service\n", delay=0)
        wait_for_console_log(r"Emergency deactivation complete", timeout=30)
        wait_for_console_log(r"System returned to decoy configuration", timeout=5)
        elapsed = time.time() - start_time
        reboot_after_emergency()
        return elapsed

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    # ============================================================================
    # SETUP: Create active session with data
    # ============================================================================

    print("\n=== Setting up active session with data ===")

    # Setup hidden volume with error handling
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    # Activate NAILS
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
    print("✓ NAILS activated")

    # Create 100 secret files
    machine.succeed("su - testuser -c 'for i in $(seq 1 100); do echo \"secret data $i\" > ~/secret_$i.txt; done'")
    print("✓ Created 100 secret files")

    # Add shell history entries (simulated sensitive commands)
    machine.succeed("su - testuser -c 'echo \"sensitive_command_1\" >> ~/.bash_history'")
    machine.succeed("su - testuser -c 'echo \"secret_key_export\" >> ~/.bash_history'")
    machine.succeed("su - testuser -c 'echo \"password_entry\" >> ~/.bash_history'")
    # Verify shell history was created
    machine.succeed("su - testuser -c 'test -f ~/.bash_history && test -s ~/.bash_history'")
    print("✓ Added shell history entries")

    # Verify data exists before emergency
    machine.succeed("su - testuser -c 'test -f ~/secret_1.txt'")
    machine.succeed("su - testuser -c 'test -f ~/secret_50.txt'")
    machine.succeed("su - testuser -c 'test -f ~/secret_100.txt'")
    print("✓ Verified data exists")

    # ============================================================================
    # EMERGENCY FLOW
    # ============================================================================

    print("\n=== Running Emergency Deactivation ===")

    emergency_time = run_emergency_command()

    print(f"✓ Emergency command completed in {emergency_time:.3f}s")

    # ============================================================================
    # VERIFY CLEAN STATE (AC: #3)
    # ============================================================================

    print("\n=== Verifying Clean State ===")

    # Verify overlays are unmounted (they won't survive reboot)
    machine.fail("mount | grep 'overlay on /home'")
    machine.fail("mount | grep 'overlay on /etc'")
    print("✓ Overlays unmounted")

    # Verify secret files are gone
    machine.fail("su - testuser -c 'test -f ~/secret_1.txt'")
    machine.fail("su - testuser -c 'test -f ~/secret_50.txt'")
    machine.fail("su - testuser -c 'test -f ~/secret_100.txt'")
    print("✓ All secret files removed")

    # Verify shell history is cleaned
    history_check = machine.succeed("su - testuser -c 'cat ~/.bash_history 2>/dev/null || echo \"gone\"'")
    assert "sensitive_command_1" not in history_check, "Shell history not cleaned - sensitive commands found"
    assert "secret_key_export" not in history_check, "Shell history not cleaned - secret key export found"
    print("✓ Shell history cleaned")

    # Verify NAILS status reports inactive state
    status = machine.succeed(f"nails --config {headless_config} status")
    assert "Inactive" in status or "INACTIVE" in status, f"Expected Inactive in status, got: {status}"
    print("✓ NAILS status reports inactive")

    print("\n=== All Emergency Tests Passed ===")
  '';
}
