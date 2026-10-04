# Test 16: A swap device re-enabled after activation is detected and reported.
#
# switch-to-configuration starts swap.target and can re-enable a swap device the
# operator turned off to pass pre-flight. The shared per-device classifier backs
# both the pre-flight check and `verify`, so once a disk/file swap reappears the
# running system reports it as a critical, memory-leaking posture. This exercises
# the detection surface without a full hidden NixOS switch; the post-switch
# re-check that logs and notifies lives in the activation path and is exercised
# by the NixOS-switch E2E suite under KVM.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-swap-reenable";
  meta.tags = [ "preflight" ];

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

    config_path = "/tmp/preflight-swap-reenable.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activation succeeds with no swap active"):
        machine.succeed("swapoff -a || true")
        machine.succeed(f"nails --config {config_path} activate --overlay-only --session keep -y")
        assert_status_state("active", config_path=config_path)
        assert_overlay_mounted("/home")

    with subtest("a swap device re-enabled after activation is reported by verify"):
        # Simulate swap.target bringing a disk/file swap back during the session.
        machine.succeed("fallocate -l 256M /swapfile")
        machine.succeed("chmod 600 /swapfile")
        machine.succeed("mkswap /swapfile")
        machine.succeed("swapon /swapfile")
        machine.succeed("grep -q '^/swapfile' /proc/swaps")

        result = run_command_capture(
            "swap-reenable-verify",
            f"nails --config {config_path} verify",
        )
        combined = result["stdout"] + result["stderr"]
        assert_text_contains(combined, ["swap", "leak memory"])
        machine.succeed("swapoff /swapfile")
        machine.succeed("rm -f /swapfile")

    with subtest("teardown is clean once swap is removed"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-swap-reenable")
        assert_status_state("inactive", config_path=config_path)
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
