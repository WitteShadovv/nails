# Test 71: Overlay Reverse-Order Unmount
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  assertions = import ./../../lib/assertions.nix;
  overlayHelpers = import ./../../lib/overlay-helpers.nix;
in
{
  name = "overlay-reverse-order-unmount";
  meta.tags = [ "overlay" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    import shlex

    ${overlayHelpers.writeOrderedOverlayConfigFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-overlay-order.yaml"
    write_ordered_overlay_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/hidden-volume/srv /mnt/hidden-volume/.work/srv")

    with subtest("phase 1: activate overlays in a known order"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y"
        )
        for path in ["/home", "/etc", "/srv"]:
            assert_overlay_mounted(path)

    with subtest("phase 2: emergency deactivation logs reverse-order unmounting"):
        machine.succeed(
            "systemd-run --unit nails-overlay-order-test --wait --collect --service-type=exec "
            + "/bin/sh -lc "
            + shlex.quote(f"nails --config {config_path} emergency")
        )
        log_text = machine.succeed("journalctl -u nails-overlay-order-test -o cat")
        unmounted = []
        for line in log_text.splitlines():
            if "Overlay unmounted" not in line:
                continue
            for field in line.split():
                if field.startswith("path="):
                    unmounted.append(field.split("=", 1)[1])
                    break
        assert unmounted[:3] == ["/srv", "/etc", "/home"], \
            f"Expected reverse unmount order ['/srv', '/etc', '/home'], got: {unmounted}\nLogs:\n{log_text}"
        assert_no_overlays(["/home", "/etc", "/srv"])
  '';
}
