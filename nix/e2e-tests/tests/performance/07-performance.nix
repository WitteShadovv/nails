# Test 07: Performance Validation
# Holds status, activation and emergency to their time budgets. Every sample
# is timed inside the guest, by nails' own duration_ms where it reports one,
# and the slowest of a few samples must stay under the budget. Wall-clock
# budgets on shared runners cannot gate a merge, so only the nightly E2E run
# executes this test.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  perf = import ./../../lib/perf.nix;
in
{
  name = "performance-validation";
  # Twice the recorded shard weight (684 s, shard-durations.json), which was
  # measured while every sample still rebooted the VM; lower both once the
  # nightly run has refreshed the weight.
  globalTimeout = 1500;
  meta.tags = [ "performance" ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
        services.getty.autologinUser = "root";
        # The emergency's own duration_ms is read from a file the unit writes
        # directly (not via journald): the teardown restarts journald, which
        # can drop lines from the journal+console stream mid-run.
        systemd.services.nails-emergency-test =
          let
            unit = emergency.makeEmergencyUnit self.packages.x86_64-linux.nails "/tmp/nails-headless.toml";
          in
          unit
          // {
            serviceConfig = unit.serviceConfig // {
              StandardOutput = "truncate:/run/nails-emergency-test.out";
              StandardError = "inherit";
            };
          };
      };
  };

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${emergency.prepareTty1ShellFn}
    ${emergency.waitForEmergencyUnitFn}
    ${emergency.rebootAfterEmergencyFn}
    ${perf.detectTcgThresholdMultiplierFn}
    ${perf.guestElapsedMsFn}
    ${perf.nailsDurationFns}

    def timed_activation_ms(extra_args="", env_prefix=""):
        output = machine.succeed(
            f"{env_prefix} nails --config {headless_config} activate {extra_args} --json --session keep -y"
        )
        return activation_duration_ms(output)

    # The emergency runs from the unit started on tty1 and is followed by a
    # reboot, as in the emergency test. Completion comes from the unit's result
    # file and nails' own measurement from the output file the unit writes
    # directly, both under /run, so a journald restart during the teardown can
    # lose neither (a console-regex wait here could).
    def timed_emergency_ms():
        prepare_tty1_shell()
        clear_emergency_result()
        machine.succeed("rm -f /run/nails-emergency-test.out")
        machine.send_key("alt-f1")
        machine.send_chars("systemctl reset-failed nails-emergency-test.service\n", delay=0)
        machine.wait_until_tty_matches("1", r"TTY1_READY#", timeout=30)
        machine.send_chars("systemctl start --no-block nails-emergency-test.service\n", delay=0)
        wait_for_emergency_unit(timeout=60)
        output = machine.succeed("cat /run/nails-emergency-test.out")
        duration = deactivation_duration_ms(output)
        assert duration is not None, (
            f"emergency logged no 'Deactivation complete' duration_ms: {output!r}"
        )
        reboot_after_emergency()
        return duration

    # A reboot closes the hidden volume. Opening it again keeps its contents,
    # and the state the emergency recorded there has to read Inactive, or the
    # next activation would only hit the idempotent fast path.
    def reopen_hidden_volume():
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        status = json.loads(machine.succeed(f"nails --config {headless_config} status --json"))["data"]
        assert status["state"]["kind"] == "inactive", f"Expected inactive state after emergency, got: {status}"

    # Stands in for the hidden system build: the build time depends on the
    # store contents and the network, not on nails, so it stays out of the
    # budget while every other step of a default activation is timed.
    def install_nixos_rebuild_stub(log_path):
        machine.succeed(
            f"""mkdir -p /tmp/nails-perf-wrapper/bin
    rm -f {log_path}
    cat > /tmp/nails-perf-wrapper/bin/nixos-rebuild <<'EOF'
    #!/bin/sh
    printf '%s\\n' "$*" >> {log_path}
    exit 0
    EOF
    chmod 755 /tmp/nails-perf-wrapper/bin/nixos-rebuild"""
        )
        return "PATH=/tmp/nails-perf-wrapper/bin:$PATH"

    def assert_within_budget(label, samples_ms, budget_s):
        slowest = max(samples_ms) / 1000.0
        print(f"{label}: samples {samples_ms} ms, slowest {slowest:.3f}s, budget {budget_s:.1f}s")
        assert slowest < budget_s, f"FAIL: {label} took {slowest:.3f}s, over its {budget_s:.1f}s budget"

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    is_tcg, threshold_multiplier = detect_tcg_threshold_multiplier()
    status_threshold = 0.5 * threshold_multiplier
    activation_threshold = 5.0 * threshold_multiplier
    emergency_threshold = 3.0 * threshold_multiplier
    print(f"TCG mode: {is_tcg}, threshold multiplier: {threshold_multiplier:.1f}x")

    with subtest("status"):
        status_ms = [guest_elapsed_ms(f"nails --config {headless_config} status") for _ in range(3)]
        assert_within_budget("Status", status_ms, status_threshold)

    with subtest("overlay-only activation and emergency"):
        activation_ms = []
        emergency_ms = []
        for cycle in range(2):
            if cycle > 0:
                reopen_hidden_volume()
            activation_ms.append(timed_activation_ms("--overlay-only"))
            emergency_ms.append(timed_emergency_ms())
        assert_within_budget("Overlay-only activation", activation_ms, activation_threshold)
        assert_within_budget("Emergency", emergency_ms, emergency_threshold)

    with subtest("default activation"):
        reopen_hidden_volume()
        machine.succeed("""cat > /mnt/data/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      documentation.nixos.enable = false;
    }
    EOF""")
        rebuild_log = "/tmp/nixos-rebuild-perf.log"
        wrapper_env = install_nixos_rebuild_stub(rebuild_log)
        default_ms = timed_activation_ms(env_prefix=wrapper_env)
        rebuild_calls = machine.succeed(f"cat {rebuild_log}")
        assert "test" in rebuild_calls, f"Expected the NixOS switch step to run, got: {rebuild_calls!r}"
        assert_within_budget("Default activation", [default_ms], activation_threshold)
  '';
}
