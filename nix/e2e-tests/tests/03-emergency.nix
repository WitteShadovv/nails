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

    def write_headless_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: root
        lower: /root
        upper: /mnt/hidden-volume/root
        work: /mnt/hidden-volume/.work/root
        target: /root
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
      - name: tmp
        lower: /tmp
        upper: /mnt/hidden-volume/tmp
        work: /mnt/hidden-volume/.work/tmp
        target: /tmp
    EOF""" % path
        )

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    # Detect if running under QEMU TCG (software emulation) vs KVM hardware acceleration.
    # When QEMU uses TCG, /proc/cpuinfo model name contains "QEMU TCG CPU".
    # When QEMU uses KVM, it passes through the real host CPU model.
    # Note: /dev/kvm may exist inside the VM even under TCG (guest kernel loads kvm module).
    cpu_model = machine.succeed("cat /proc/cpuinfo | head -20").strip()
    is_tcg: bool = "QEMU TCG" in cpu_model
    threshold_multiplier: float = 3.0 if is_tcg else 1.0
    emergency_threshold: float = 3.0 * threshold_multiplier
    print(f"TCG mode: {is_tcg}, emergency threshold: {emergency_threshold:.1f}s")

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
    # EMERGENCY SPEED TEST (AC: #2, #5)
    # ============================================================================

    print("\n=== Testing Emergency Deactivation Speed ===")

    start_time = time.time()
    machine.succeed("sudo nails emergency")
    emergency_time: float = time.time() - start_time

    print(f"Emergency deactivation completed in {emergency_time:.3f}s")

    # CRITICAL: Hard failure if emergency exceeds threshold (NFR3 requirement)
    assert emergency_time < emergency_threshold, \
        f"FAIL: Emergency took {emergency_time:.3f}s (> {emergency_threshold:.1f}s limit)"
    print(f"✓ Emergency completed in {emergency_time:.3f}s (< {emergency_threshold:.1f}s requirement)")

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

    # Verify NAILS status reports inactive state
    status = machine.succeed("nails status")
    assert "Inactive" in status or "INACTIVE" in status, f"Expected Inactive in status, got: {status}"
    print("✓ NAILS status reports inactive")

    # ============================================================================
    # STATISTICAL VALIDATION - 20 Cycles for meaningful p95 (AC: #4)
    # ============================================================================

    print("\n=== Running Statistical Validation (20 cycles) ===")

    emergency_times: list[float] = []

    for cycle in range(1, 21):
        print(f"\nCycle {cycle}/20:")

        # Reactivate
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

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
    min_time: float = emergency_times_sorted[0]
    max_time: float = emergency_times_sorted[-1]
    avg_time: float = sum(emergency_times) / len(emergency_times)

    # Calculate p95 (95th percentile) using proper method
    # For 20 samples, p95 is at index: int((20-1) * 0.95) = 18
    p95_index = int((len(emergency_times_sorted) - 1) * 0.95)
    p95_time: float = emergency_times_sorted[p95_index]

    print("\n=== Emergency Timing Statistics ===")
    print(f"Samples: {len(emergency_times)}")
    print(f"Min:    {min_time:.3f}s")
    print(f"Max:    {max_time:.3f}s")
    print(f"Average: {avg_time:.3f}s")
    print(f"P95:    {p95_time:.3f}s (index {p95_index})")

    # CRITICAL: p95 must be within threshold (AC: #4)
    assert p95_time < emergency_threshold, \
        f"FAIL: P95 emergency time {p95_time:.3f}s exceeds {emergency_threshold:.1f}s limit"
    print(f"✓ P95 emergency time {p95_time:.3f}s meets < {emergency_threshold:.1f}s requirement")

    # Cleanup
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    # Note: /dev/mapper/hidden-volume may persist in VM environments due to
    # kernel-internal dm-crypt references. This is a known test infrastructure
    # limitation and does not affect test validity (device cleaned up on VM shutdown).
    print("✓ Hidden volume cleanup completed")

    print("\n=== All Emergency Tests Passed ===")
  '';
}
