# Test 07: Performance Validation
# Tests all performance requirements with statistical rigor

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  perf = import ./../../lib/perf.nix;
in
{
  name = "performance";
  meta.tags = [ "performance" ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
        services.getty.autologinUser = "root";
        systemd.services.nails-emergency-test = emergency.makeEmergencyUnit self.packages.x86_64-linux.nails "/tmp/nails-headless.yaml";
      };
  };

  testScript = _: ''
    def now():
        import time

        return time.time()

    ${testHelpers.writeHeadlessConfigFn}
    ${emergency.prepareTty1ShellFn}
    ${emergency.waitForConsoleLogFn}
    ${emergency.rebootAfterEmergencyFn}
    ${emergency.runEmergencyCommandFn}
    ${perf.detectTcgThresholdMultiplierFn}
    ${perf.p95Fn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    is_tcg, threshold_multiplier = detect_tcg_threshold_multiplier()
    status_threshold = 0.5 * threshold_multiplier
    activation_threshold = 5.0 * threshold_multiplier
    emergency_threshold = 3.0 * threshold_multiplier

    print(f"TCG mode: {is_tcg}, threshold multiplier: {threshold_multiplier:.1f}x")
    print(f"  Status threshold:     {status_threshold:.1f}s")
    print(f"  Activation threshold: {activation_threshold:.1f}s")
    print(f"  Emergency threshold:  {emergency_threshold:.1f}s")

    print("\n=== Testing Status Command Performance ===")
    status_times = []
    for _ in range(1, 11):
        start = now()
        machine.succeed("nails status")
        status_times.append(now() - start)

    status_times_sorted = sorted(status_times)
    p95_status = p95(status_times)
    median_status = status_times_sorted[4]

    print("Status Performance (10 iterations):")
    print(f"  Median: {median_status:.3f}s")
    print(f"  P95:    {p95_status:.3f}s")

    assert p95_status < status_threshold, \
        f"FAIL: Status p95 {p95_status:.3f}s exceeds {status_threshold:.1f}s threshold"
    print(f"✓ Status p95 {p95_status:.3f}s meets <{status_threshold:.1f}s requirement")

    print("\n=== Testing Activation Performance ===")
    activation_times = []
    for _ in range(1, 6):
        start = now()
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        activation_times.append(now() - start)

        machine.execute("sudo nails emergency")
        machine.crash()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.fail("mount | grep 'overlay on /home'")
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    activation_sorted = sorted(activation_times)
    p95_activation = p95(activation_times)
    median_activation = activation_sorted[2]

    print("Activation Performance (5 cycles):")
    print(f"  Median: {median_activation:.3f}s")
    print(f"  P95:    {p95_activation:.3f}s")

    assert p95_activation < activation_threshold, \
        f"FAIL: Activation p95 {p95_activation:.3f}s exceeds {activation_threshold:.1f}s threshold"
    print(f"✓ Activation p95 {p95_activation:.3f}s meets <{activation_threshold:.1f}s requirement")

    print("\n=== Testing Emergency Performance ===")
    emergency_times = []
    for i in range(1, 6):
        if i > 1:
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        emergency_time = run_emergency_command()
        emergency_times.append(emergency_time)

        machine.fail("mount | grep 'overlay on /home'")
        machine.fail("mount | grep 'overlay on /etc'")

    emergency_sorted = sorted(emergency_times)
    p95_emergency = p95(emergency_times)
    median_emergency = emergency_sorted[2]

    print("Emergency Performance (5 cycles):")
    print(f"  Median: {median_emergency:.3f}s")
    print(f"  P95:    {p95_emergency:.3f}s")

    assert p95_emergency < emergency_threshold, \
        f"FAIL: Emergency p95 {p95_emergency:.3f}s exceeds {emergency_threshold:.1f}s threshold"
    print(f"✓ Emergency p95 {p95_emergency:.3f}s meets <{emergency_threshold:.1f}s requirement")

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

    print("\n=== All Performance Tests Passed ===")
  '';
}
