# Fault test (b): the hidden backing device vanishes while a session is active.
#
# A pulled USB key, a failed disk, or a yanked device-mapper node makes every
# read and write to the hidden filesystem return EIO while the overlays above it
# are still mounted. Emergency is the panic button for exactly this case: it must
# still detach every overlay within a bound (so the operator is not left staring
# at a wedged system) and exit with a documented status code.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "faults-hidden-disk-removed";
  meta.tags = [
    "faults"
    "security"
  ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    overlay_targets = ["/etc", "/home", "/root", "/srv", "/tmp", "/usr", "/bin", "/lib64"]

    # The documented exit codes for emergency: a clean teardown (Ok) or a
    # degraded teardown that asks for a reboot to finish clearing RAM.
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

    with subtest("the backing device is yanked out from under the overlays"):
        # Replacing the dm target with an error target makes the hidden filesystem
        # return EIO for every access, simulating a removed backing disk while the
        # overlays above it stay mounted. wipe_table performs exactly that swap in
        # place: "dmsetup remove" cannot be used here because the backing node is
        # still held open by the live /mnt/data mount and its overlays, so even
        # "remove --force" leaves the error target loaded but exits non-zero on the
        # failed remove ioctl. wipe_table loads the error target and resumes the
        # device without removing the node, so the fault injection itself succeeds.
        machine.succeed("dmsetup wipe_table --force data")

    with subtest("emergency detaches every overlay within the time bound"):
        # timeout caps the whole teardown so a wedge on the dead device is a
        # failure, not a hang that holds the shard until the global timeout.
        rc, output = machine.execute(
            f"timeout 30 nails --config {headless_config} emergency", timeout=60
        )
        assert rc in documented_codes, f"emergency exit {rc} is not documented: {output!r}"
        # The security-critical guarantee: no NAILS overlay survives the yank.
        assert_no_overlays(overlay_targets)
  '';
}
