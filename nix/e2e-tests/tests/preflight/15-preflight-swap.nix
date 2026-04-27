# Test 15: Preflight Swap Checks

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-swap";
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
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-swap.yaml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("swap-enabled system is refused with remediation guidance"):
        machine.succeed("fallocate -l 256M /swapfile")
        machine.succeed("chmod 600 /swapfile")
        machine.succeed("mkswap /swapfile")
        machine.succeed("swapon /swapfile")
        machine.succeed("grep -q '^/swapfile' /proc/swaps")

        result = run_command_capture(
            "preflight-swap-fail",
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["swap", "Swap is enabled", "swapoff -a"], stream="stderr")
        assert_status_state("inactive")

    with subtest("disabling swap restores a successful activation"):
        machine.succeed("swapoff /swapfile")
        machine.succeed("rm -f /swapfile")
        machine.succeed(f"nails --config {config_path} activate --overlay-only --no-kill-session -y")
        assert_status_state("active")
        assert_overlay_mounted("/home")
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-swap")
        assert_status_state("inactive")
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
