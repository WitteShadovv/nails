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
in
{
  name = "state-transitions-observability";
  meta.tags = [ "state" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${stateHelpers.captureCommandFns}
    ${stateHelpers.installActivationGateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-tests/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    env_prefix, gate_path, entered_path = install_activation_gate(
        gate_path="/run/nails-tests/nails-observe-activation.gate",
        entered_path="/run/nails-tests/nails-observe-activation-entered",
    )

    with subtest("activation exposes activating status before completion"):
        run_detached_captured_command(
            "nails-activate-observability",
            "state-observability-primary",
            f"{env_prefix} nails --config {headless_config} activate --overlay-only --no-kill-session -y",
        )
        primary_rc_path = "/tmp/state-observability-primary.rc"
        machine.wait_until_succeeds(
            f"test -f {entered_path} || test -f {primary_rc_path}",
            timeout=180,
        )
        if machine.execute(f"test -f {primary_rc_path}")[0] == 0:
            rc, stdout, stderr = wait_for_captured_command("state-observability-primary", timeout=5)
            primary_status = machine.succeed(
                "timeout 10s systemctl status nails-activate-observability --no-pager --full || true"
            )
            primary_journal = machine.succeed(
                "timeout 10s journalctl -u nails-activate-observability --no-pager -n 100 -o short-precise || true"
            )
            raise AssertionError(
                "Observability activation exited before reaching activation gate: "
                f"rc={rc}, stdout={stdout!r}, stderr={stderr!r}, "
                f"systemctl_status={primary_status!r}, journalctl={primary_journal!r}"
            )
        machine.succeed(f"test -f {entered_path}")
        wait_for_status_state("Activating", config_path=headless_config, timeout=180)
        assert_status_state("Activating", config_path=headless_config)

    with subtest("activation completes and status converges to active"):
        machine.succeed(f"rm -f {gate_path}")
        rc, stdout, stderr = wait_for_captured_command("state-observability-primary", timeout=240)
        assert rc == 0, f"Expected activation success, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"
        wait_for_status_state("Active", config_path=headless_config, timeout=180)
        assert_status_state("Active", config_path=headless_config)

    with subtest("deactivation returns status to inactive"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-state-observability")
        assert_status_state("Inactive")
  '';
}
