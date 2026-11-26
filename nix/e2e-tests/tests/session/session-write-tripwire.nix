# The write tripwire (`[session_mounts] write_tripwire`) against a real write
# to the decoy disk.
#
# The decoy VM's root disk is the decoy disk (an ext4 filesystem on the whole
# of /dev/vda, no partition table); the hidden volume is LUKS on the second
# disk; a third disk holds a decoy XFS filesystem at /srv/xfs. With the
# tripwire on:
#
#   1. A session that writes nothing to the decoy disk keeps running past
#      several of the watcher's polls. Just before its switch the decoy
#      appends to a file on /srv/xfs and removes a tree there: after a
#      `sync`, XFS writes its log's items and covers its log 20 to 80 seconds
#      later, which the last step before the switch writes at once by
#      freezing and thawing the filesystem, so the session runs past them.
#   2. Rewriting one sector of the decoy disk with the bytes it already holds
#      (a write that changes nothing, so the filesystem stays intact) powers
#      the machine off within a few polls; the next cold boot is the plain
#      decoy. The block-write oracle, which counts the same write from the
#      host, is told that this one sector is the test's own.
#   3. With the tripwire off, the same write leaves the session running.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-write-tripwire";
  meta.tags = [
    "security"
    "session"
  ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      boot.supportedFilesystems = [ "xfs" ];
      environment.systemPackages = [ pkgs.xfsprogs ];
      # XFS needs 300 MiB at least.
      virtualisation.emptyDiskImages = [
        {
          size = 512;
          driveConfig.deviceExtraOpts.serial = "xfs";
        }
      ];
    };

  testScript = _: ''
    from nails_e2e import blockwrites, session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"


    def write_config(tripwire):
        write_headless_config(CONFIG)
        machine.succeed(
            f"printf '[session_mounts]\\nwrite_tripwire = {str(tripwire).lower()}\\n' >> {CONFIG}"
        )


    def last_sector():
        """The last sector of the decoy disk."""
        sectors = int(machine.succeed("blockdev --getsz /dev/vda").strip())
        return sectors - 1


    def rewrite(sector):
        """Write one sector of the decoy disk with the bytes it holds."""
        machine.succeed(
            f"dd if=/dev/vda of=/run/sector bs=512 skip={sector} count=1 status=none"
            f" && dd if=/run/sector of=/dev/vda bs=512 seek={sector} count=1"
            " oflag=direct conv=notrunc status=none && rm /run/sector"
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    sector = last_sector()
    # A lived-in XFS filesystem of the decoy, settled.
    machine.succeed(
        "mkfs.xfs -q -f /dev/disk/by-id/virtio-xfs && mkdir -p /srv/xfs"
        " && mount /dev/disk/by-id/virtio-xfs /srv/xfs"
        " && for d in $(seq 1 30); do mkdir -p /srv/xfs/tmp/d$d"
        " && head -c 65536 /dev/urandom > /srv/xfs/tmp/d$d/f; done"
        " && sync && sleep 30 && sync"
    )

    with subtest("a session that writes nothing to the decoy disk runs on"):
        write_config(True)
        # What a decoy's stop jobs do to a filesystem, just before the switch.
        machine.succeed(
            "for i in $(seq 1 50); do echo rec $i >> /srv/xfs/wtmp; done"
            " && rm -rf /srv/xfs/tmp/d1*"
        )
        canonical_activate(CONFIG, "--overlay-only", "activate-quiet")
        # Past XFS's late writes (20 to 80 s after a sync), and past many of
        # the watcher's 5 s polls.
        machine.succeed("sleep 100")
        machine.succeed("true")
        canonical_deactivate(CONFIG, "deactivate-quiet")

    with subtest("one sector written to the decoy disk powers the machine off"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "activate-write")
        oracle = blockwrites.oracle_of(machine)
        assert oracle is not None and oracle.window is not None
        drive = oracle.window.decoy[0].device
        oracle.allowed[drive] = [(sector * 512, 512)]
        rewrite(sector)
        session.wait_for_real_power_off(machine, 120)
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")

    with subtest("with the tripwire off the same write leaves the session running"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        write_config(False)
        canonical_activate(CONFIG, "--overlay-only", "activate-off")
        rewrite(sector)
        machine.succeed("sleep 20")
        machine.succeed("true")
        canonical_deactivate(CONFIG, "deactivate-off")
  '';
}
