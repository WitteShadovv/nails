# Test 15: Preflight Swap Checks
#
# A disk-backed (file) swap is refused by the swap check with the exact
# `swapoff` remediation, and nothing is prepared: the machine stays on the
# plain decoy. A RAM-only zram swap is permitted: the same configuration then
# enters the hidden session (a soft-reboot into the root overlay) and leaves
# it again.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
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
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    from nails_e2e import session

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
            f"nails --config {config_path} activate --overlay-only -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["swap", "leak memory", "swapoff /swapfile"], stream="stderr")
        session.assert_decoy_root(machine)
        assert read_status_json(config_path=config_path)["posture"] == "decoy"

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

        canonical_activate(config_path, "--overlay-only", "preflight-swap-zram")
        assert read_status_json(config_path=config_path)["posture"] == "active"
        canonical_deactivate(config_path, "preflight-swap-zram-deactivate")
  '';
}
