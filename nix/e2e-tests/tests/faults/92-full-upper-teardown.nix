# Fault test (c): the hidden upper fills up while a session is active.
#
# Once the hidden filesystem that backs the overlay upper dirs is full, every new
# write returns ENOSPC. Teardown must not depend on free space: both a normal
# deactivation and the emergency panic button have to complete and leave no
# overlay behind even when there is nothing left to allocate.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in
{
  name = "faults-full-upper-teardown";
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
    ${sessionHelpers.loginSessionSurvivalFns}

    overlay_targets = ["/etc", "/home", "/root", "/srv", "/tmp", "/usr", "/bin", "/lib64"]

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

    with subtest("fill the hidden filesystem that backs the overlay uppers"):
        # overlayfs performs copy-up and all upper-dir writes with the *mounter's*
        # credentials (root, since nails mounted the overlay), not the writing
        # user's. Root can draw on ext4's 5% reserved-block pool, which an
        # unprivileged `df --output=avail` reports as unavailable. If we fill only
        # that unprivileged "available" figure, the whole reserved pool (~95 MB on
        # this 2 GB disk) stays free and a root-credentialed overlay write never
        # hits ENOSPC. Drop the reserved pool to zero first so "available" matches
        # the space overlay writes can actually reach.
        machine.succeed("tune2fs -m 0 /dev/mapper/data")
        # Leave only a sliver free so overlay writes hit ENOSPC, but the small,
        # in-place state-file rewrite the teardown performs can still land.
        avail = int(
            machine.succeed("df -B1 --output=avail /mnt/data | tail -1").strip()
        )
        fill_bytes = max(0, avail - 1048576)
        machine.succeed(f"fallocate -l {fill_bytes} /mnt/data/fill")
        # A fresh overlay write should now fail for lack of space.
        machine.fail("su - testuser -c 'dd if=/dev/zero of=$HOME/overflow bs=1M count=4'")

    with subtest("emergency completes and leaves no overlay behind on a full upper"):
        sessions_before_emergency = login_session_ids()
        machine.succeed(f"nails --config {headless_config} emergency")
        assert_no_overlays(overlay_targets)
        # Emergency detaches the overlays without logging the operator out.
        assert_login_sessions_survived(sessions_before_emergency)
        assert_status_state("inactive", config_path=headless_config)

    with subtest("freeing space lets the backend close cleanly"):
        machine.succeed("rm -f /mnt/data/fill")
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        machine.fail("test -e /dev/mapper/data")
  '';
}
