# Story 13.8: Performance Validation Test
# Tests all performance requirements with statistical rigor

{ self, ... }:
let
  hiddenVolume = import ./../lib/hidden-volume.nix;
  testHelpers = import ./../lib/test-helpers.nix;
in {
  name = "performance";

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

    def wait_for_console_log(regex, timeout, start_index=0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            console_log = machine.get_console_log()[start_index:]
            if re.search(regex, console_log):
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
        console_start = len(machine.get_console_log())

        start_time = time.time()
        machine.send_key("alt-f1")
        machine.send_chars("systemctl reset-failed nails-emergency-test.service\n", delay=0)
        machine.wait_until_tty_matches("1", r"TTY1_READY#", timeout=30)
        machine.send_chars("systemctl start --no-block nails-emergency-test.service\n", delay=0)
        wait_for_console_log(r"Emergency deactivation complete", timeout=30, start_index=console_start)
        wait_for_console_log(r"System returned to decoy configuration", timeout=5, start_index=console_start)
        elapsed = time.time() - start_time
        reboot_after_emergency()
        return elapsed

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

        # Emergency for cleanup (kills backdoor)
        machine.execute("sudo nails emergency")

        # Crash and restart to restore backdoor
        machine.crash()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.fail("mount | grep 'overlay on /home'")

        # Re-setup hidden volume (lost after crash)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

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
        if i > 1:
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

        # Activate first
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

        # Measure the full emergency workflow to completion, not detached dispatch time.
        emergency_time = run_emergency_command()
        emergency_times.append(emergency_time)

        # Verify clean state
        machine.fail("mount | grep 'overlay on /home'")
        machine.fail("mount | grep 'overlay on /etc'")

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

    print("\n=== All Performance Tests Passed ===")
  '';
}
