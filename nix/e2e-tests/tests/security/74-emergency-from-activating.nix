# Test 74: Emergency From Activating
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
in {
  name = "emergency-from-activating";
  meta.tags = [ "security" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}
    ${securityHelpers.transitionalStateFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    state_path = "/mnt/hidden-volume/state.json"
    backup_path = "/tmp/active-state.json"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("prepare active session and force activating state"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        machine.succeed(f"test -f {state_path}")
        backup_state_file(state_path, backup_path)
        force_state_file_state(state_path, "Activating")

        status = read_status_json(config_path=headless_config)
        assert_status_state("activating", payload=status)
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")

    with subtest("emergency fails closed while activation is in progress"):
        prefix = "/tmp/emergency-from-activating"
        run_captured_command(
            prefix,
            f"nails --config {headless_config} emergency --no-countdown",
        )
        result = read_command_result(prefix)

        assert result["rc"] == 1, f"Expected emergency to fail from Activating, got: {result}"
        assert "Activating" in result["stderr"], result
        assert "Must be ACTIVE" in result["stderr"], result

        status = read_status_json(config_path=headless_config)
        assert_status_state("activating", payload=status)
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")

    with subtest("restored active state can still be emergency-cleaned"):
        restore_state_file(state_path, backup_path)
        status = read_status_json(config_path=headless_config)
        assert status["state"].startswith("Active"), status

        prefix = "/tmp/emergency-from-activating-cleanup"
        run_captured_command(
            prefix,
            f"nails --config {headless_config} emergency --no-countdown",
        )
        result = read_command_result(prefix)

        assert result["rc"] == 0, result
        assert "Emergency deactivation complete" in result["stdout"], result

        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
