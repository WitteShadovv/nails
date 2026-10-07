# Backend: a bind-mounted directory as the hidden root
#
# The hidden root need not be a dedicated block device: a directory on any local
# Linux filesystem, bind-mounted at the configured root, must back a full
# whole-root session. The backing ext4 lives on /dev/disk/by-id/virtio-data (the
# secondary test disk), a subdirectory of it is bind-mounted at /mnt/data, and
# the standard headless config activates over it unchanged:
#
#   1. `nails activate` soft-reboots into the root overlay with its upper in
#      the bound directory, and status reports the session;
#   2. a hidden write lands in that directory (/mnt/data/root/upper/...);
#   3. `nails deactivate` soft-reboots back to the plain decoy, which does not
#      see the hidden file, while the backing disk still holds it.

_:
let
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "bind-mounted-root";
  meta.tags = [
    "lifecycle"
    "session"
  ];

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    UPPER = "/mnt/data/root/upper"
    NOTE = "home/testuser/notes.txt"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/bind-root.toml"
    write_headless_config(headless_config)

    with subtest("prepare a bind-mounted directory root on local ext4"):
        # Back the hidden root with a plain directory on an ext4 disk, then
        # bind-mount that directory at the configured root. /mnt/data is a real
        # mount point (a bind) on its own device, so NAILS treats it exactly
        # like a dedicated volume.
        machine.succeed(
            "mkfs.ext4 -F -L data /dev/disk/by-id/virtio-data",
            "mkdir -p /mnt/backing",
            "mount /dev/disk/by-id/virtio-data /mnt/backing",
            "mkdir -p /mnt/backing/vol/root/work /mnt/backing/vol/config/nixos",
        )
        machine.succeed("mkdir -p /mnt/data", "mount --bind /mnt/backing/vol /mnt/data")
        machine.succeed("mountpoint -q /mnt/data")

    with subtest("activate over the bind-mounted root"):
        canonical_activate(headless_config, "--overlay-only", "activate-bind")
        session.assert_hidden_root(machine, UPPER)
        status = read_status_json(config_path=headless_config)
        assert status["posture"] == "active", status

    with subtest("hidden-session writes land under the bound directory"):
        machine.succeed("su - testuser -c 'echo bind-backend-ok > ~/notes.txt' && sync")
        machine.succeed(f"grep -qx bind-backend-ok {UPPER}/{NOTE}")

    with subtest("deactivate returns to the plain decoy; the backing disk keeps the file"):
        canonical_deactivate(headless_config, "deactivate-bind")
        status = read_status_json(config_path=headless_config)
        assert status["posture"] == "decoy", status
        machine.fail("su - testuser -c 'test -e ~/notes.txt'")
        # The switch dropped the backing mount with the hidden root; mount the
        # backing disk again to look at it.
        machine.succeed("mount /dev/disk/by-id/virtio-data /mnt/backing")
        machine.succeed(f"grep -qx bind-backend-ok /mnt/backing/vol/root/upper/{NOTE}")
        machine.succeed("umount /mnt/backing")
  '';
}
