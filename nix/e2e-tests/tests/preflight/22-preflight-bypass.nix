# Test 22: Preflight Bypass Flag
#
# A file-backed swap makes the swap check refuse activation (nothing is
# prepared, the machine stays on the plain decoy). `--no-preflight` skips every
# pre-flight check: the same activation then enters the hidden session anyway
# (a soft-reboot into the root overlay), and deactivation returns to the plain
# decoy.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-bypass";
  meta.tags = [
    "preflight"
    "smoke"
  ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    from nails_e2e import session

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-bypass.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("swap would normally block activation"):
        machine.succeed("fallocate -l 256M /swapfile")
        machine.succeed("chmod 600 /swapfile")
        machine.succeed("mkswap /swapfile")
        machine.succeed("swapon /swapfile")
        blocked = run_command_capture(
            "preflight-bypass-blocked",
            f"nails --config {config_path} activate --overlay-only -y",
        )
        assert_command_failed(blocked)
        assert_result_contains(
            blocked,
            ["swap can leak memory to persistent storage", "/swapfile"],
            stream="stderr",
        )
        session.assert_decoy_root(machine)
        assert read_status_json(config_path=config_path)["posture"] == "decoy"

    with subtest("no-preflight bypasses the swap guard and enters the hidden session"):
        canonical_activate(config_path, "--overlay-only --no-preflight", "preflight-bypass")
        assert read_status_json(config_path=config_path)["posture"] == "active"

    with subtest("deactivation returns to the plain decoy after a bypassed activation"):
        canonical_deactivate(config_path, "preflight-bypass-deactivate")
        machine.succeed("swapoff /swapfile 2>/dev/null || true")
        machine.succeed("rm -f /swapfile")
  '';
}
