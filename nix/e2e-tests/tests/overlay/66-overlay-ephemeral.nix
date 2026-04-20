# Test 66: Overlay Ephemeral Semantics
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in {
  name = "overlay-ephemeral";
  meta.tags = [ "overlay" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeEphemeralConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-ephemeral.yaml"
    write_ephemeral_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("phase 1: activate RAM-backed extended overlays"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y"
        )
        for path in ["/var", "/tmp", "/srv", "/opt"]:
            assert_overlay_mounted(path)
        machine.succeed("findmnt -n -o FSTYPE /run/nails/srv-upper | grep -qx tmpfs")
        machine.succeed("findmnt -n -o FSTYPE /run/nails/srv-work | grep -qx tmpfs")

    with subtest("phase 2: writes land in tmpfs and not hidden storage"):
        machine.succeed("touch /srv/ephemeral-marker")
        machine.succeed("test -f /run/nails/srv-upper/ephemeral-marker")
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral-marker")

    with subtest("phase 3: deactivation drops ephemeral writes"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-overlay-ephemeral")
        assert_no_overlays(["/var", "/tmp", "/srv", "/opt"])
        machine.fail("test -e /srv/ephemeral-marker")
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral-marker")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
