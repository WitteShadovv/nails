# Test 71: Overlay Reverse-Order Unmount
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  assertions = import ./../../lib/assertions.nix;
  overlayHelpers = import ./../../lib/overlay-helpers.nix;
in
{
  name = "overlay-reverse-order-unmount";
  meta.tags = [ "overlay" ];

  testScript = _: ''
    import re
    import shlex

    ${overlayHelpers.writeOrderedOverlayConfigFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-overlay-order.toml"
    write_ordered_overlay_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/data/srv /mnt/data/.work/srv")

    with subtest("phase 1: activate overlays in a known order"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        for path in ["/home", "/etc", "/srv"]:
            assert_overlay_mounted(path)

    with subtest("phase 2: emergency deactivation logs reverse-order unmounting"):
        # Emergency scrubs the volatile runtime journal at the end of the teardown,
        # so its own log lines cannot be read back from the journal afterwards.
        # Capture the unit's output to a file under /run (never overlaid) instead.
        log_path = "/run/nails-overlay-order-test.log"
        machine.succeed(f"rm -f {log_path}")
        machine.succeed(
            "systemd-run --unit nails-overlay-order-test --wait --collect --service-type=exec "
            + f"-p StandardOutput=append:{log_path} -p StandardError=append:{log_path} "
            + "/bin/sh -lc "
            + shlex.quote(f"nails --config {config_path} emergency")
        )
        log_text = machine.succeed(f"cat {log_path}")
        clean_log_text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", log_text)
        unmounted = []
        for line in clean_log_text.splitlines():
            if "Overlay unmounted" not in line:
                continue
            for field in line.split():
                if field.startswith("path="):
                    unmounted.append(field.split("=", 1)[1])
                    break
        assert unmounted[:3] == ["/srv", "/etc", "/home"], \
            f"Expected reverse unmount order ['/srv', '/etc', '/home'], got: {unmounted}\nLogs:\n{clean_log_text}"
        assert_no_overlays(["/home", "/etc", "/srv"])
  '';
}
