# Test 22: Preflight Bypass Flag

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-bypass";
  meta.tags = [
    "preflight"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
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

    config_path = "/tmp/preflight-bypass.yaml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("swap would normally block activation"):
        machine.succeed("fallocate -l 256M /swapfile")
        machine.succeed("chmod 600 /swapfile")
        machine.succeed("mkswap /swapfile")
        machine.succeed("swapon /swapfile")
        blocked = run_command_capture(
            "preflight-bypass-blocked",
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y",
        )
        assert_command_failed(blocked)
        assert_result_contains(blocked, ["swap", "Swap is enabled"], stream="stderr")
        assert_status_state("inactive")

    with subtest("no-preflight bypasses the swap guard and emits a danger warning"):
        bypassed = run_command_capture(
            "preflight-bypass-active",
            f"nails --config {config_path} activate --overlay-only --no-kill-session --no-preflight -y",
        )
        assert_command_succeeded(bypassed)
        combined = bypassed["stdout"] + "\n" + bypassed["stderr"]
        assert_text_contains(combined, ["Skipping pre-flight checks", "DANGER"])
        assert_status_state("active")
        assert_overlay_mounted("/home")

    with subtest("cleanup restores decoy state after bypassed activation"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-bypass")
        machine.succeed("sh -lc 'swapoff /swapfile || true'")
        machine.succeed("rm -f /swapfile")
        assert_status_state("inactive")
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
