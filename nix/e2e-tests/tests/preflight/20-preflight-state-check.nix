# Test 20: Preflight State Check Integrity

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-state-check";
  meta.tags = [ "preflight" ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-state-check.yaml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("baseline activation and deactivation produce a signed state file"):
        machine.succeed(f"nails --config {config_path} activate --overlay-only --no-kill-session -y")
        assert_status_state("active")
        assert_overlay_mounted("/home")
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-state-initial")
        assert_status_state("inactive")

    with subtest("tampered checksum blocks the next activation"):
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        machine.succeed(
            "python3 - <<'PY'\n"
            "import json\n"
            "from pathlib import Path\n"
            "path = Path('/mnt/hidden-volume/state.json')\n"
            "payload = json.loads(path.read_text())\n"
            "payload['version'] = payload['version'] + '-tampered'\n"
            "path.write_text(json.dumps(payload, indent=2))\n"
            "PY"
        )
        result = run_command_capture(
            "preflight-state-checksum",
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["Checksum mismatch", "may be corrupted"], stream="stderr")
        assert_status_state("unknown")
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
