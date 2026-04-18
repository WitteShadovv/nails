# Test 68: Overlay Bind Sync Visibility
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  assertions = import ./../../lib/assertions.nix;
  overlayHelpers = import ./../../lib/overlay-helpers.nix;
in {
  name = "overlay-bind-sync";
  meta.tags = [ "overlay" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${overlayHelpers.writeSrvOnlyConfigFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-bind-sync.yaml"
    write_srv_only_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /mnt/hidden-volume/srv /mnt/hidden-volume/.work/srv")

    with subtest("phase 1: create a bind-mounted subtree under the overlay target"):
        machine.succeed("mkdir -p /persist/srv/bind-source /srv/bind-source")
        machine.succeed("printf %s baseline > /persist/srv/bind-source/baseline.txt")
        machine.succeed("mount --bind /persist/srv/bind-source /srv/bind-source")
        machine.succeed("test -f /srv/bind-source/baseline.txt")

    with subtest("phase 2: activation preserves bind-mounted lower visibility"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y"
        )
        assert_overlay_mounted("/srv")
        baseline = machine.succeed("cat /srv/bind-source/baseline.txt").strip()
        assert baseline == "baseline", f"Expected bind-mounted lower content, got: {baseline!r}"

    with subtest("phase 3: current implementation writes into overlay upper, not the bind source"):
        machine.succeed("printf %s overlay-write > /srv/bind-source/overlay-write.txt")
        machine.succeed("test -f /mnt/hidden-volume/srv/bind-source/overlay-write.txt")
        machine.fail("test -e /persist/srv/bind-source/overlay-write.txt")

    with subtest("phase 4: emergency cleanup removes the overlay cleanly"):
        machine.succeed(f"nails --config {config_path} emergency")
        assert_no_overlays(["/srv"])
        machine.succeed("test -f /srv/bind-source/baseline.txt")
        machine.fail("test -e /srv/bind-source/overlay-write.txt")
        machine.succeed("umount /srv/bind-source")
  '';
}
