# Story 13.8: Performance Validation Test
# Tests all performance requirements with statistical rigor

{ self, ... }:
let hiddenVolume = import ./../lib/hidden-volume.nix;
in {
  name = "performance";

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

    # Setup hidden volume
    setup_result = machine.succeed("${hiddenVolume.setupHiddenVolume} || echo 'Setup failed with code $?'")
    assert "Setup failed" not in setup_result, f"Hidden volume setup failed: {setup_result}"

    # ============================================================================
    # STATUS PERFORMANCE TEST (NFR6: <500ms p95) (AC: #1)
    # ============================================================================

    print("\n=== Testing Status Command Performance (<500ms p95) ===")

    status_times = []
    for i in range(1, 11):
        start = time.time()
        machine.succeed("nails status")
        status_times.append(time.time() - start)

    status_times_sorted = sorted(status_times)
    p95_index = int((len(status_times_sorted) - 1) * 0.95)
    p95_status = status_times_sorted[p95_index]
    median_status = status_times_sorted[4]

    print(f"Status Performance (10 iterations):")
    print(f"  Median: {median_status:.3f}s")
    print(f"  P95:    {p95_status:.3f}s")

    assert p95_status < 0.5, f"FAIL: Status p95 {p95_status:.3f}s exceeds 500ms threshold"
    print(f"✓ Status p95 {p95_status:.3f}s meets <500ms requirement")

    # ============================================================================
    # ACTIVATION/DEACTIVATION PERFORMANCE (NFR1, NFR2: <5s p95) (AC: #2)
    # ============================================================================

    print("\n=== Testing Activation/Deactivation Performance (<5s p95) ===")

    activation_times = []
    deactivation_times = []

    for i in range(1, 6):
        # Measure activation
        start = time.time()
        machine.succeed("sudo nails activate")
        activation_times.append(time.time() - start)

        # Measure deactivation
        start = time.time()
        machine.succeed("sudo nails deactivate")
        deactivation_times.append(time.time() - start)

        # Verify clean state
        machine.fail("mount | grep 'overlay on /home'")

    # Calculate statistics for activation
    activation_sorted = sorted(activation_times)
    p95_activation = activation_sorted[int((len(activation_sorted) - 1) * 0.95)]
    median_activation = activation_sorted[2]

    # Calculate statistics for deactivation
    deactivation_sorted = sorted(deactivation_times)
    p95_deactivation = deactivation_sorted[int((len(deactivation_sorted) - 1) * 0.95)]
    median_deactivation = deactivation_sorted[2]

    print(f"Activation Performance (5 cycles):")
    print(f"  Median: {median_activation:.3f}s")
    print(f"  P95:    {p95_activation:.3f}s")

    print(f"Deactivation Performance (5 cycles):")
    print(f"  Median: {median_deactivation:.3f}s")
    print(f"  P95:    {p95_deactivation:.3f}s")

    assert p95_activation < 5.0, f"FAIL: Activation p95 {p95_activation:.3f}s exceeds 5s threshold"
    assert p95_deactivation < 5.0, f"FAIL: Deactivation p95 {p95_deactivation:.3f}s exceeds 5s threshold"
    print(f"✓ Activation p95 {p95_activation:.3f}s meets <5s requirement")
    print(f"✓ Deactivation p95 {p95_deactivation:.3f}s meets <5s requirement")

    # ============================================================================
    # EMERGENCY PERFORMANCE (NFR3: <3s p95) (AC: #3)
    # ============================================================================

    print("\n=== Testing Emergency Performance (<3s p95) ===")

    emergency_times = []

    for i in range(1, 6):
        # Activate first
        machine.succeed("sudo nails activate")

        # Measure emergency
        start = time.time()
        machine.succeed("sudo nails emergency")
        emergency_times.append(time.time() - start)

        # Verify clean state
        machine.fail("mount | grep 'overlay on /home'")

    # Calculate statistics
    emergency_sorted = sorted(emergency_times)
    p95_emergency = emergency_sorted[int((len(emergency_sorted) - 1) * 0.95)]
    median_emergency = emergency_sorted[2]

    print(f"Emergency Performance (5 cycles):")
    print(f"  Median: {median_emergency:.3f}s")
    print(f"  P95:    {p95_emergency:.3f}s")

    assert p95_emergency < 3.0, f"FAIL: Emergency p95 {p95_emergency:.3f}s exceeds 3s threshold"
    print(f"✓ Emergency p95 {p95_emergency:.3f}s meets <3s requirement")

    # ============================================================================
    # SUMMARY (AC: #4, #5)
    # ============================================================================

    print(f"\n{'='*60}")
    print("PERFORMANCE TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Status Command:")
    print(f"  Median: {median_status:.3f}s  P95: {p95_status:.3f}s  (Threshold: <500ms)")
    print(f"  {'✓ PASS' if p95_status < 0.5 else '✗ FAIL'}")
    print(f"\nActivation:")
    print(f"  Median: {median_activation:.3f}s  P95: {p95_activation:.3f}s  (Threshold: <5s)")
    print(f"  {'✓ PASS' if p95_activation < 5.0 else '✗ FAIL'}")
    print(f"\nDeactivation:")
    print(f"  Median: {median_deactivation:.3f}s  P95: {p95_deactivation:.3f}s  (Threshold: <5s)")
    print(f"  {'✓ PASS' if p95_deactivation < 5.0 else '✗ FAIL'}")
    print(f"\nEmergency:")
    print(f"  Median: {median_emergency:.3f}s  P95: {p95_emergency:.3f}s  (Threshold: <3s)")
    print(f"  {'✓ PASS' if p95_emergency < 3.0 else '✗ FAIL'}")
    print(f"{'='*60}")

    # Cleanup
    machine.succeed("${hiddenVolume.unmountHiddenVolume}")
    machine.fail("test -e /dev/mapper/hidden-volume")

    print("\n=== All Performance Tests Passed ===")
  '';
}
