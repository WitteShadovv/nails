# Backend: a bind-mounted directory as the hidden root
#
# The hidden root need not be a dedicated block device: a directory on any local
# Linux filesystem, bind-mounted at the configured root, must back a full
# activate/deactivate cycle. This exercises the path a user takes when the hidden
# storage is a subtree of an already-mounted encrypted disk rather than its own
# mapper. The backing ext4 lives on /dev/disk/by-id/virtio-data (the secondary test disk), a
# subdirectory of it is bind-mounted at /mnt/data, and the standard headless
# config activates over it unchanged.

_:
let
  backends = import ./../../lib/backends.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "bind-mounted-root";
  meta.tags = [
    "lifecycle"
    "overlay"
  ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("prepare a bind-mounted directory root on local ext4"):
        # Back the hidden root with a plain directory on an ext4 disk, then
        # bind-mount that directory at the configured root. /mnt/data is a real
        # mount point (a bind), so the upper-fs probe and NAILS treat it exactly
        # like a dedicated volume.
        machine.succeed(
            "mkfs.ext4 -F -L data /dev/disk/by-id/virtio-data",
            "mkdir -p /mnt/backing",
            "mount /dev/disk/by-id/virtio-data /mnt/backing",
            "mkdir -p /mnt/backing/vol",
        )
        machine.succeed("""${backends.nailsDirStructure "/mnt/backing/vol"}""")
        machine.succeed("mkdir -p /mnt/data", "mount --bind /mnt/backing/vol /mnt/data")
        machine.succeed("mountpoint -q /mnt/data")

    with subtest("activate over the bind-mounted root"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        home_mount = machine.succeed("mount | grep 'overlay on /home'")
        assert "/mnt/data/home" in home_mount, (
            f"overlay upperdir not on the bind-mounted root: {home_mount!r}"
        )
        active_status = read_status_json(config_path=headless_config)
        assert active_status["state"]["kind"] == "active", (
            f"expected active, got: {active_status}"
        )

    with subtest("hidden-session writes land under the bind-mounted root"):
        machine.succeed("su - testuser -c 'echo bind-backend-ok > ~/notes.txt'")
        machine.succeed("test -f /mnt/backing/vol/home/testuser/notes.txt")

    with subtest("deactivate restores the decoy and tears every overlay down"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-bind-mounted-root")
        post_status = read_status_json()
        assert post_status["state"]["kind"] == "inactive", (
            f"expected inactive after reboot, got: {post_status}"
        )
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp", "/var"])
        # The backing data survives the cycle; only the overlays are gone. The
        # reboot dropped every mount, so remount the backing disk to inspect it.
        machine.fail("su - testuser -c 'test -f ~/notes.txt'")
        machine.succeed("mkdir -p /mnt/backing", "mount /dev/disk/by-id/virtio-data /mnt/backing")
        machine.succeed("test -f /mnt/backing/vol/home/testuser/notes.txt")
        machine.succeed("umount /mnt/backing")
  '';
}
