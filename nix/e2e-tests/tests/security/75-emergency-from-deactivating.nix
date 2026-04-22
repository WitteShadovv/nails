# Test 75: Emergency From Deactivating
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
in
{
  name = "emergency-from-deactivating";
  meta.tags = [ "security" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
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
    backup_path = "/tmp/deactivating-active-state.json"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("prepare active session and force deactivating state"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        machine.succeed(f"test -f {state_path}")
        backup_state_file(state_path, backup_path)
        force_state_file_state(state_path, "Deactivating")

        status = read_status_json(config_path=headless_config)
        assert_status_state("deactivating", payload=status)
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")

    with subtest("emergency fails closed while deactivation is in progress"):
        prefix = "/run/nails-tests/emergency-from-deactivating"
        capture = run_captured_command(
            prefix,
            f"nails --config {headless_config} emergency --no-countdown",
            unit_name="nails-emergency-from-deactivating",
        )
        result = read_command_result(prefix, unit_name=capture["unit_name"], timeout=30)

        assert result["rc"] == 1, f"Expected emergency to fail from Deactivating, got: {result}"
        assert "Deactivating" in result["stderr"], result
        assert "Must be ACTIVE" in result["stderr"], result

        status = read_status_json(config_path=headless_config)
        assert_status_state("deactivating", payload=status)
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")

    with subtest("restored active state can still be emergency-cleaned"):
        restore_state_file(state_path, backup_path)
        status = read_status_json(config_path=headless_config)
        assert status["state"].startswith("Active"), status

        result = run_shellless_transient_command(
            "/run/nails-tests/emergency-from-deactivating-cleanup",
            [
                "nails",
                "--config",
                headless_config,
                "emergency",
                "--no-countdown",
            ],
            unit_name="nails-emergency-from-deactivating-cleanup",
        )

        assert result["rc"] == 0, result
        assert "Emergency deactivation complete" in result["stdout"], result

        assert_no_overlays(["/home", "/etc"])
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
