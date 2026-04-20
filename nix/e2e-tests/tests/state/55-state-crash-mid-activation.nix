# Test 55: State Crash Mid Activation
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
  name = "state-crash-mid-activation";
  meta.tags = [ "state" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${stateHelpers.captureCommandFns}
    ${stateHelpers.installSlowNixosRebuildGateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    bin_dir, gate_path, entered_path = install_slow_nixos_rebuild_gate(
        gate_path="/tmp/nails-crash-rebuild.gate",
        entered_path="/tmp/nails-crash-rebuild-entered",
    )

    with subtest("drive activation into a durable activating state"):
        run_detached_captured_command(
            "nails-activate-crash-mid-activation",
            "state-crash-primary",
            f"PATH={bin_dir}:$PATH nails --config {headless_config} activate --no-kill-session -y",
        )
        machine.wait_until_succeeds(f"test -f {entered_path}", timeout=180)
        machine.wait_until_succeeds(
            f"nails --config {headless_config} status --json | grep -F 'Activating'",
            timeout=180,
        )
        assert_status_state("Activating", config_path=headless_config)

    with subtest("crash the machine mid-activation"):
        machine.crash()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        write_headless_config(headless_config)

    with subtest("reboot returns to decoy-safe inactive view with no overlays mounted"):
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        payload = read_status_json(config_path=headless_config)
        assert_status_state("Inactive", payload=payload)
  '';
}
