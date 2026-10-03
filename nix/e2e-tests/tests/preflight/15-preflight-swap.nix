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
      # The zram subtest brings up a RAM-only zram swap device by hand.
      boot.kernelModules = [ "zram" ];
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

    config_path = "/tmp/preflight-swap.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("file-backed swap is refused with remediation guidance"):
        machine.succeed("fallocate -l 256M /swapfile")
        machine.succeed("chmod 600 /swapfile")
        machine.succeed("mkswap /swapfile")
        machine.succeed("swapon /swapfile")
        machine.succeed("grep -q '^/swapfile' /proc/swaps")

        result = run_command_capture(
            "preflight-swap-fail",
            f"nails --config {config_path} activate --overlay-only --session keep -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["swap", "leak memory", "swapoff -a"], stream="stderr")
        assert_status_state("inactive")

    with subtest("RAM-only zram swap is permitted"):
        # Tear down the file swap and bring up a RAM-only zram device, which the
        # per-device classifier must treat as safe (backing_dev reads "none").
        machine.succeed("swapoff /swapfile")
        machine.succeed("rm -f /swapfile")
        machine.succeed("modprobe zram num_devices=1")
        machine.succeed("zramctl /dev/zram0 --algorithm lzo --size 256M")
        machine.succeed("mkswap /dev/zram0")
        machine.succeed("swapon --priority 100 /dev/zram0")
        machine.succeed("grep -q '^/dev/zram0' /proc/swaps")
        machine.succeed("test \"$(cat /sys/block/zram0/backing_dev)\" = none")

        machine.succeed(f"nails --config {config_path} activate --overlay-only --session keep -y")
        assert_status_state("active")
        assert_overlay_mounted("/home")
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-swap-zram")
        assert_status_state("inactive")
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
        machine.succeed("swapoff /dev/zram0")

    with subtest("disabling swap restores a successful activation"):
        machine.succeed(f"nails --config {config_path} activate --overlay-only --session keep -y")
        assert_status_state("active")
        assert_overlay_mounted("/home")
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-swap")
        assert_status_state("inactive")
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
