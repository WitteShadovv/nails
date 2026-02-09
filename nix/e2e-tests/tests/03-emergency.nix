# Story 13.5: Emergency Deactivation Test (<3s)
# Tests emergency deactivation speed requirement - critical NFR3

{ self, ... }:
let hiddenVolume = import ./../lib/hidden-volume.nix;
in {
  name = "emergency";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
    import time

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # ============================================================================
    # SETUP: Create active session with data
    # ============================================================================

    print("\n=== Setting up active session with data ===")

    # Setup hidden volume with error handling
    setup_result = machine.succeed("${hiddenVolume.setupHiddenVolume} || echo 'Setup failed with code $?'")
    assert "Setup failed" not in setup_result, f"Hidden volume setup failed: {setup_result}"

    # Activate NAILS
    machine.succeed("sudo nails activate")
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
    # EMERGENCY SPEED TEST (AC: #2, #5)
    # ============================================================================

    print("\n=== Testing Emergency Deactivation Speed ===")

    start_time = time.time()
    machine.succeed("sudo nails emergency")
    emergency_time = time.time() - start_time

    print(f"Emergency deactivation completed in {emergency_time:.3f}s")

    # CRITICAL: Hard failure if emergency > 3.0s (NFR3 requirement)
    assert emergency_time < 3.0, f"FAIL: Emergency took {emergency_time:.3f}s (> 3.0s limit)"
    print(f"✓ Emergency completed in {emergency_time:.3f}s (< 3.0s requirement)")

    # ============================================================================
    # VERIFY CLEAN STATE (AC: #3)
    # ============================================================================

    print("\n=== Verifying Clean State ===")

    # Verify overlays are unmounted
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

    # Verify NAILS status reports INACTIVE
    status = machine.succeed("nails status")
    assert "INACTIVE" in status, f"Expected INACTIVE, got: {status}"
    print("✓ NAILS status reports INACTIVE")

    # ============================================================================
    # STATISTICAL VALIDATION - 20 Cycles for meaningful p95 (AC: #4)
    # ============================================================================

    print("\n=== Running Statistical Validation (20 cycles) ===")

    emergency_times = []

    for cycle in range(1, 21):
        print(f"\nCycle {cycle}/20:")

        # Reactivate
        machine.succeed("sudo nails activate")

        # Recreate data
        machine.succeed("su - testuser -c 'for i in $(seq 1 100); do echo \"secret data $i\" > ~/secret_$i.txt; done'")

        # Measure emergency
        start_time = time.time()
        machine.succeed("sudo nails emergency")
        emergency_time = time.time() - start_time

        emergency_times.append(emergency_time)
        print(f"  Cycle {cycle}: {emergency_time:.3f}s")

        # Verify clean state each cycle
        machine.fail("mount | grep 'overlay on /home'")
        machine.fail("su - testuser -c 'test -f ~/secret_1.txt'")

    # Calculate statistics
    emergency_times_sorted = sorted(emergency_times)
    min_time = emergency_times_sorted[0]
    max_time = emergency_times_sorted[-1]
    avg_time = sum(emergency_times) / len(emergency_times)

    # Calculate p95 (95th percentile) using proper method
    # For 20 samples, p95 is at index: int((20-1) * 0.95) = 18
    p95_index = int((len(emergency_times_sorted) - 1) * 0.95)
    p95_time = emergency_times_sorted[p95_index]

    print(f"\n=== Emergency Timing Statistics ===")
    print(f"Samples: {len(emergency_times)}")
    print(f"Min:    {min_time:.3f}s")
    print(f"Max:    {max_time:.3f}s")
    print(f"Average: {avg_time:.3f}s")
    print(f"P95:    {p95_time:.3f}s (index {p95_index})")

    # CRITICAL: p95 must be < 3.0s (AC: #4)
    assert p95_time < 3.0, f"FAIL: P95 emergency time {p95_time:.3f}s exceeds 3.0s limit"
    print(f"✓ P95 emergency time {p95_time:.3f}s meets < 3.0s requirement")

    # Cleanup
    machine.succeed("${hiddenVolume.unmountHiddenVolume}")
    machine.fail("test -e /dev/mapper/hidden-volume")
    print("✓ LUKS device properly closed")

    print("\n=== All Emergency Tests Passed ===")
  '';
}
