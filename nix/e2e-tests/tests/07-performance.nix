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

    # Setup hidden volume
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    # Detect if running under QEMU TCG (software emulation) vs KVM hardware acceleration.
    # When QEMU uses TCG, /proc/cpuinfo model name contains "QEMU TCG CPU".
    # When QEMU uses KVM, it passes through the real host CPU model.
    # Note: /dev/kvm may exist inside the VM even under TCG (guest kernel loads kvm module).
    cpu_model = machine.succeed("cat /proc/cpuinfo | head -20").strip()
    is_tcg: bool = "QEMU TCG" in cpu_model
    threshold_multiplier: float = 3.0 if is_tcg else 1.0

    status_threshold: float = 0.5 * threshold_multiplier
    activation_threshold: float = 5.0 * threshold_multiplier
    emergency_threshold: float = 3.0 * threshold_multiplier

    print(f"TCG mode: {is_tcg}, threshold multiplier: {threshold_multiplier:.1f}x")
    print(f"  Status threshold:     {status_threshold:.1f}s")
    print(f"  Activation threshold: {activation_threshold:.1f}s")
    print(f"  Emergency threshold:  {emergency_threshold:.1f}s")

    # ============================================================================
    # STATUS PERFORMANCE TEST (NFR6: <500ms p95) (AC: #1)
    # ============================================================================

    print("\n=== Testing Status Command Performance ===")

    status_times: list[float] = []
    for i in range(1, 11):
        start = time.time()
        machine.succeed("nails status")
        status_times.append(time.time() - start)

    status_times_sorted = sorted(status_times)
    p95_index = int((len(status_times_sorted) - 1) * 0.95)
    p95_status: float = status_times_sorted[p95_index]
    median_status: float = status_times_sorted[4]

    print("Status Performance (10 iterations):")
    print(f"  Median: {median_status:.3f}s")
    print(f"  P95:    {p95_status:.3f}s")

    assert p95_status < status_threshold, \
        f"FAIL: Status p95 {p95_status:.3f}s exceeds {status_threshold:.1f}s threshold"
    print(f"✓ Status p95 {p95_status:.3f}s meets <{status_threshold:.1f}s requirement")

    # ============================================================================
    # ACTIVATION PERFORMANCE (NFR1, NFR2: <5s p95) (AC: #2)
    # ============================================================================

    print("\n=== Testing Activation Performance ===")

    activation_times: list[float] = []

    for i in range(1, 6):
        # Measure activation
        start = time.time()
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        activation_times.append(time.time() - start)

        # Emergency provides same-boot cleanup between timing samples
        machine.succeed("sudo nails emergency")
        machine.fail("mount | grep 'overlay on /home'")

    # Calculate statistics for activation
    activation_sorted = sorted(activation_times)
    p95_activation: float = activation_sorted[int((len(activation_sorted) - 1) * 0.95)]
    median_activation: float = activation_sorted[2]

    print("Activation Performance (5 cycles):")
    print(f"  Median: {median_activation:.3f}s")
    print(f"  P95:    {p95_activation:.3f}s")

    assert p95_activation < activation_threshold, \
        f"FAIL: Activation p95 {p95_activation:.3f}s exceeds {activation_threshold:.1f}s threshold"
    print(f"✓ Activation p95 {p95_activation:.3f}s meets <{activation_threshold:.1f}s requirement")

    # ============================================================================
    # EMERGENCY PERFORMANCE (NFR3: <3s p95) (AC: #3)
    # ============================================================================

    print("\n=== Testing Emergency Performance ===")

    emergency_times: list[float] = []

    for i in range(1, 6):
        # Activate first
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

        # Measure emergency
        start = time.time()
        machine.succeed("sudo nails emergency")
        emergency_times.append(time.time() - start)

        # Verify clean state
        machine.fail("mount | grep 'overlay on /home'")

    # Calculate statistics
    emergency_sorted = sorted(emergency_times)
    p95_emergency: float = emergency_sorted[int((len(emergency_sorted) - 1) * 0.95)]
    median_emergency: float = emergency_sorted[2]

    print("Emergency Performance (5 cycles):")
    print(f"  Median: {median_emergency:.3f}s")
    print(f"  P95:    {p95_emergency:.3f}s")

    assert p95_emergency < emergency_threshold, \
        f"FAIL: Emergency p95 {p95_emergency:.3f}s exceeds {emergency_threshold:.1f}s threshold"
    print(f"✓ Emergency p95 {p95_emergency:.3f}s meets <{emergency_threshold:.1f}s requirement")

    # ============================================================================
    # SUMMARY (AC: #4, #5)
    # ============================================================================

    print(f"\n{'='*60}")
    print("PERFORMANCE TEST SUMMARY")
    print(f"{'='*60}")
    kvm_note = " (TCG mode - relaxed thresholds)" if is_tcg else ""
    print(f"Environment:{kvm_note}")
    print("\nStatus Command:")
    print(f"  Median: {median_status:.3f}s  P95: {p95_status:.3f}s  (Threshold: <{status_threshold:.1f}s)")
    print(f"  {'✓ PASS' if p95_status < status_threshold else '✗ FAIL'}")
    print("\nActivation:")
    print(f"  Median: {median_activation:.3f}s  P95: {p95_activation:.3f}s  (Threshold: <{activation_threshold:.1f}s)")
    print(f"  {'✓ PASS' if p95_activation < activation_threshold else '✗ FAIL'}")
    print("\nEmergency:")
    print(f"  Median: {median_emergency:.3f}s  P95: {p95_emergency:.3f}s  (Threshold: <{emergency_threshold:.1f}s)")
    print(f"  {'✓ PASS' if p95_emergency < emergency_threshold else '✗ FAIL'}")
    print(f"{'='*60}")

    # Cleanup
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    # Note: /dev/mapper/hidden-volume may persist in VM environments due to
    # kernel-internal dm-crypt references. This is a known test infrastructure
    # limitation and does not affect test validity (device cleaned up on VM shutdown).

    print("\n=== All Performance Tests Passed ===")
  '';
}
