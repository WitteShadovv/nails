# Test 54: State Concurrent Invocation
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
  name = "state-concurrent-invocation";
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
    ${assertions.assertOverlayMountedFn}
    ${stateHelpers.captureCommandFns}
    ${stateHelpers.installSlowNixosRebuildGateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    bin_dir, gate_path, entered_path = install_slow_nixos_rebuild_gate()

    with subtest("start a blocked activation and observe transitional state"):
        run_detached_captured_command(
            "nails-activate-concurrent-primary",
            "state-concurrent-primary",
            f"PATH={bin_dir}:$PATH nails --config {headless_config} activate --no-kill-session -y",
        )
        machine.wait_until_succeeds(f"test -f {entered_path}", timeout=180)
        machine.wait_until_succeeds(
            f"nails --config {headless_config} status --json | grep -F 'Activating'",
            timeout=180,
        )
        assert_status_state("Activating", config_path=headless_config)

    with subtest("second invocation fails while first activation is in progress"):
        rc, stdout, stderr = capture_command(
            "state-concurrent-secondary",
            f"nails --config {headless_config} activate --no-kill-session -y",
        )
        assert rc == 1, f"Expected second activation to fail, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"
        combined = (stdout + stderr).lower()
        assert (
            "activating" in combined or "in progress" in combined or "wait for completion" in combined
        ), f"Expected in-progress refusal, got stdout={stdout!r}, stderr={stderr!r}"

    with subtest("release primary activation and confirm only one succeeds"):
        machine.succeed(f"rm -f {gate_path}")
        rc, stdout, stderr = wait_for_captured_command("state-concurrent-primary", timeout=240)
        assert rc == 0, f"Expected primary activation success, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"
        assert_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")

    with subtest("deactivate after concurrent activation test"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-state-concurrent")
        assert_status_state("Inactive")
  '';
}
