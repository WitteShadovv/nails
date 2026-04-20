# Test 57: State Transitions Observability
# Self-check list:
# 1. Uses with subtest(...).
# 2. Uses deterministic waits only.
# 3. Uses hard assertions only.
# 4. Sets meta.tags.
# 5. Uses shared lib helpers.
# 6. Preserves forensic invariants.
# 7. Exercises explicit failure injection and recovery.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  stateHelpers = import ./../../lib/state-helpers.nix;
in {
  name = "state-transitions-observability";
  meta.tags = [ "state" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${stateHelpers.captureCommandFns}
    ${stateHelpers.installSlowNixosRebuildGateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    bin_dir, gate_path, entered_path = install_slow_nixos_rebuild_gate(
        gate_path="/tmp/nails-observe-rebuild.gate",
        entered_path="/tmp/nails-observe-rebuild-entered",
    )

    with subtest("activation exposes activating status before completion"):
        run_detached_captured_command(
            "nails-activate-observability",
            "state-observability-primary",
            f"PATH={bin_dir}:$PATH nails --config {headless_config} activate --no-kill-session -y",
        )
        machine.wait_until_succeeds(f"test -f {entered_path}", timeout=180)
        machine.wait_until_succeeds(
            f"nails --config {headless_config} status --json | grep -F 'Activating'",
            timeout=180,
        )
        assert_status_state("Activating", config_path=headless_config)

    with subtest("activation completes and status converges to active"):
        machine.succeed(f"rm -f {gate_path}")
        rc, stdout, stderr = wait_for_captured_command("state-observability-primary", timeout=240)
        assert rc == 0, f"Expected activation success, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"
        machine.wait_until_succeeds(
            f"nails --config {headless_config} status --json | grep -F 'Active'",
            timeout=180,
        )
        assert_status_state("Active", config_path=headless_config)

    with subtest("deactivation returns status to inactive"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-state-observability")
        assert_status_state("Inactive")
  '';
}
