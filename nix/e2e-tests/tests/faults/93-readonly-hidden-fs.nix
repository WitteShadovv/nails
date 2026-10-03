# Fault test (g): the hidden filesystem goes read-only while active.
#
# An ext4 error, or a backing device flipped read-only, leaves the hidden
# filesystem unwritable while the overlays above it are still mounted. Teardown
# must not depend on being able to write to that filesystem: emergency has to
# detach every overlay and converge to the decoy even when the upper is read-only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "faults-readonly-hidden-fs";
  meta.tags = [
    "faults"
    "security"
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
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    overlay_targets = ["/etc", "/home", "/root", "/srv", "/tmp", "/usr", "/bin", "/lib64"]
    documented_codes = {0, 7}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activate a hidden session"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")

    with subtest("the backing device is forced read-only"):
        # Flipping the device read-only at the block layer makes every write to the
        # hidden filesystem fail regardless of files held open by the overlays.
        machine.succeed("blockdev --setro /dev/mapper/data")

    with subtest("emergency still tears every overlay down"):
        rc, output = machine.execute(
            f"timeout 30 nails --config {headless_config} emergency", timeout=60
        )
        assert rc in documented_codes, f"emergency exit {rc} is not documented: {output!r}"
        assert_no_overlays(overlay_targets)

    with subtest("restoring write access lets the backend close cleanly"):
        machine.succeed("blockdev --setrw /dev/mapper/data")
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        machine.fail("test -e /dev/mapper/data")
  '';
}
