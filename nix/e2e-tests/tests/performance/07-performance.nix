# Test 07: Performance Validation
#
# Holds the whole-root session to its time budgets, each timed inside the
# guest:
#   - `nails status` (on the decoy and in the hidden session) and `nails check`
#     stay fast: they only read;
#   - `nails activate`, from the trigger until the new userspace has settled
#     after the soft-reboot (the `trigger_to_settled` timing follow_soft_reboot
#     takes from the guest's uptime), stays within a generous VM budget, over
#     two round trips;
#   - `nails deactivate`, from the trigger until the machine is off (the
#     `trigger_to_off` timing follow_power_off takes on the host: the guest has
#     no clock left to read), stays within the same budget;
#   - `nails emergency` in the hidden session powers the machine off quickly
#     (`trigger_to_off`): its hot path phases are logged by the hidden
#     process, which the power-off ends, so the time until the machine is off
#     is what is measured.
# The slowest sample must stay under each budget. Wall-clock budgets on shared
# runners cannot gate a merge, so only the nightly E2E run executes this test.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  perf = import ./../../lib/perf.nix;
in
{
  name = "performance-validation";
  # Three soft-reboots in and three power-offs with a cold boot out, at about
  # 15-30 s each, plus setup.
  globalTimeout = 1500;
  meta.tags = [ "performance" ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.canonicalEmergencyFn}
    ${perf.detectTcgThresholdMultiplierFn}
    ${perf.guestElapsedMsFn}

    CONFIG = "/mnt/data/config/nails.toml"


    def assert_within_budget(label, samples_s, budget_s):
        slowest = max(samples_s)
        print(f"{label}: samples {samples_s} s, slowest {slowest:.3f}s, budget {budget_s:.1f}s")
        assert slowest < budget_s, f"FAIL: {label} took {slowest:.3f}s, over its {budget_s:.1f}s budget"


    def timed_reads(label, command, budget_s, samples=3):
        assert_within_budget(
            label, [guest_elapsed_ms(command) / 1000.0 for _ in range(samples)], budget_s
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    is_tcg, threshold_multiplier = detect_tcg_threshold_multiplier()
    status_threshold = 0.5 * threshold_multiplier
    check_threshold = 10.0 * threshold_multiplier
    # The spike measured 10 to 15 s per transition (about 6 s of it the DHCP
    # client) on two vCPUs; a misbehaving unit can stall the shutdown far
    # longer, which is what the budget is there to catch.
    switch_threshold = 60.0 * threshold_multiplier
    emergency_threshold = 30.0 * threshold_multiplier
    print(f"TCG mode: {is_tcg}, threshold multiplier: {threshold_multiplier:.1f}x")

    with subtest("status and check on the decoy"):
        timed_reads("Status (decoy)", f"nails --config {CONFIG} status", status_threshold)
        # check exits 0 or 4 by readiness; only its run time matters here.
        timed_reads(
            "Check", f"nails --config {CONFIG} check --overlay-only || true", check_threshold
        )

    with subtest("activate and deactivate round trips"):
        activate_s = []
        deactivate_s = []
        for cycle in range(2):
            if cycle > 0:
                machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
            timings = canonical_activate(CONFIG, "--overlay-only", f"perf-activate-{cycle}")
            activate_s.append(timings["trigger_to_settled"])
            if cycle == 0:
                timed_reads("Status (hidden)", f"nails --config {CONFIG} status", status_threshold)
            timings = canonical_deactivate(CONFIG, f"perf-deactivate-{cycle}")
            deactivate_s.append(timings["trigger_to_off"])
        assert_within_budget("Activate to the settled hidden root", activate_s, switch_threshold)
        assert_within_budget("Deactivate to the power-off", deactivate_s, switch_threshold)

    with subtest("emergency powers off quickly"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "perf-activate-emergency")
        timings = canonical_emergency(CONFIG, "perf-emergency", boot=False)
        assert_within_budget(
            "Emergency to the power-off", [timings["trigger_to_off"]], emergency_threshold
        )
  '';
}
