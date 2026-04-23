# Test 66: Overlay Ephemeral Semantics (unsupported layout)
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "overlay-ephemeral";
  meta.tags = [ "overlay" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.writeEphemeralConfigFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-ephemeral.yaml"
    write_ephemeral_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("mkdir -p /opt")

    with subtest("phase 1: ephemeral overlay activation succeeds"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y"
        )
        for path in ["/var", "/tmp", "/srv", "/opt"]:
            assert_overlay_mounted(path)
        machine.succeed("findmnt -n -o FSTYPE /run/nails/srv-ephemeral | grep -qx tmpfs")
        machine.succeed("test -d /run/nails/srv-ephemeral/upper")
        machine.succeed("test -d /run/nails/srv-ephemeral/work")

    with subtest("phase 2: writes land in tmpfs and not hidden storage"):
        machine.succeed("touch /srv/ephemeral-marker")
        machine.succeed("test -f /run/nails/srv-ephemeral/upper/ephemeral-marker")
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral-marker")

    with subtest("phase 3: deactivation drops ephemeral writes"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-overlay-ephemeral")
        assert_no_overlays(["/var", "/tmp", "/srv", "/opt"])
        for path in [
            "/run/nails/var-ephemeral",
            "/run/nails/tmp-ephemeral",
            "/run/nails/srv-ephemeral",
            "/run/nails/opt-ephemeral",
        ]:
            machine.fail(f"mountpoint -q {path}")

    with subtest("phase 3: hidden storage remains untouched"):
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral-marker")
  '';
}
