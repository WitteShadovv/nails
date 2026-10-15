# Disks mounted during the hidden session: the watcher alert, the
# opt-in read-only guard, and the way back.
#
# The fstab policy covers every filesystem the decoy knows about at entry. A
# disk the hidden session mounts itself is a real disk. Here a second disk
# (serial "extra", formatted and used by the decoy, absent from its fstab) and
# a disk hot-plugged during the session stand in for a USB drive.
#
#   1. Without the opt-in: mounting the disk read-write in the hidden session
#      raises the watcher's neutral desktop alert. The disk is left mounted and
#      busy; `nails deactivate` still returns to the decoy, nothing holds the
#      disk afterwards, and the decoy mounts it read-write as usual.
#   2. With `[session_mounts] read_only = true`: the disk is read-only at the
#      block layer from the hidden boot on, a disk hot-plugged during the
#      session is made read-only by the udev rule alone (the watcher, the
#      fallback, is stopped first), a mount comes up read-only and every write
#      fails, and the decoy root and the hidden backend stay writable. After
#      the way back both disks are writable again, the second disk is byte for
#      byte as before the session, and the decoy mounts it read-write.
#
# notify-send is shadowed by a logging stub on the system PATH so the alert is
# observable headlessly (as in faults-backend-watch-alert); it logs under /run.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-disk-mounts";
  meta.tags = [
    "session"
    "security"
  ];
  # Two sessions, four soft-reboots.
  globalTimeout = 1500;

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      virtualisation.emptyDiskImages = [
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "extra";
        }
      ];
      # The test VMs are q35 machines, whose root bus takes no hot-plugged
      # device: the disk attached during the session goes into this port.
      virtualisation.qemu.options = [ "-device pcie-root-port,id=hotplug-port,chassis=1" ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        (pkgs.writeShellScriptBin "notify-send" ''
          log=/run/notify-stub/notify-send.log
          mkdir -p "$(dirname "$log")"
          {
            printf '__CALL__\n'
            for arg in "$@"; do
              printf '%s\n' "$arg"
            done
          } >> "$log"
          exit 0
        '')
      ];
    };

  testScript = _: ''
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    EXTRA = "/dev/disk/by-id/virtio-extra"
    HOTPLUG = "/dev/disk/by-id/virtio-hotplug"
    STUB = "/run/notify-stub/notify-send.log"
    WATCH_UNIT = "overlay-runtime-monitor.service"
    RULE = "/run/udev/rules.d/60-overlay-runtime.rules"
    RECORD = "/run/overlay-runtime/read-only-devices"


    def write_config(read_only):
        machine.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "\n"
            "[backend_watch]\n"
            "poll_interval_secs = 2\n"
            "\n"
            "[session_mounts]\n"
            f"read_only = {'true' if read_only else 'false'}\n"
            "EOF"
        )


    def is_read_only(device):
        return machine.succeed(f"blockdev --getro {device}").strip() == "1"


    def alerts():
        rc, text = machine.execute(f"cat {STUB}")
        if rc != 0:
            return []
        return [
            [line for line in call.splitlines() if line]
            for call in text.split("__CALL__\n")
            if call.strip()
        ]


    def decoy_root_device():
        return machine.succeed("findmnt -no SOURCE /").strip()


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(f"mkfs.ext4 -q -L extra {EXTRA}")
    machine.succeed(
        f"mkdir -p /mnt/extra && mount {EXTRA} /mnt/extra "
        "&& echo decoy > /mnt/extra/decoy-file && umount /mnt/extra"
    )
    root_device = decoy_root_device()

    with subtest("without the opt-in, a read-write disk mount raises the alert"):
        write_config(False)
        canonical_activate(CONFIG, "--overlay-only", "activate-1")
        machine.wait_for_unit(WATCH_UNIT)
        assert not is_read_only(EXTRA), "the disk must stay writable without the opt-in"
        machine.fail(f"test -e {RULE}")
        machine.succeed(f"mkdir -p /mnt/extra && mount {EXTRA} /mnt/extra")
        machine.wait_until_succeeds(f"grep -q 'Disk mounted with write access' {STUB}", timeout=30)
        calls = [c for c in alerts() if "Disk mounted with write access" in c]
        assert len(calls) == 1, f"one alert per mount: {calls}"
        assert any("/mnt/extra" in token for token in calls[0]), calls
        assert "critical" in calls[0], calls
        assert not any("nails" in token.lower() for token in calls[0]), calls
        # Without the opt-in the write reaches the disk: that is what the alert
        # is about.
        machine.succeed("echo session-1 > /mnt/extra/hidden-1 && sync")
        # Keep the mount busy across the way back.
        machine.succeed(
            "systemd-run --unit hold-extra -p WorkingDirectory=/mnt/extra "
            "-E PATH=/run/current-system/sw/bin \"$(command -v sleep)\" infinity"
        )

    with subtest("the way back leaves the busy disk free for the decoy"):
        canonical_deactivate(CONFIG, "deactivate-1")
        machine.fail(f"findmnt -S \"$(readlink -f {EXTRA})\"")
        assert not is_read_only(EXTRA)
        machine.succeed(f"mkdir -p /mnt/extra && mount {EXTRA} /mnt/extra")
        machine.succeed("grep -Fx decoy /mnt/extra/decoy-file && grep -Fx session-1 /mnt/extra/hidden-1")
        machine.succeed("echo decoy-2 > /mnt/extra/decoy-2 && umount /mnt/extra")
        extra_before = machine.succeed(f"sha256sum < {EXTRA}")

    with subtest("with the opt-in, unused disks are read-only from the hidden boot on"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        write_config(True)
        canonical_activate(CONFIG, "--overlay-only", "activate-2")
        machine.wait_for_unit(WATCH_UNIT)
        machine.succeed(f"test -s {RULE}")
        machine.wait_until_succeeds(f"test \"$(blockdev --getro {EXTRA})\" = 1", timeout=30)
        machine.succeed(f"test -s {RECORD}")
        # The session's own devices stay writable.
        for device in (root_device, "/dev/disk/by-id/virtio-data", "/dev/mapper/data"):
            assert not is_read_only(device), f"{device} must stay writable"
        machine.succeed("touch /mnt/data/probe-2 && rm /mnt/data/probe-2")

    with subtest("a mount comes up read-only and every write fails"):
        out = machine.succeed(f"mkdir -p /mnt/extra && mount {EXTRA} /mnt/extra 2>&1")
        machine.log(out)
        machine.succeed("findmnt -no OPTIONS /mnt/extra | tr , '\\n' | grep -qx ro")
        machine.succeed("grep -Fx decoy-2 /mnt/extra/decoy-2")
        machine.fail("touch /mnt/extra/hidden-2")
        machine.fail("mount -o remount,rw /mnt/extra")
        machine.fail(f"dd if=/dev/zero of={EXTRA} bs=512 count=1 seek=1 conv=notrunc oflag=direct")

    with subtest("a disk attached during the session is read-only through udev alone"):
        # Stop the watcher, so only the udev rule can set the new disk read-only.
        machine.succeed(f"systemctl stop {WATCH_UNIT}")
        image = machine.state_dir / "hotplug.img"
        with open(image, "wb") as handle:
            handle.truncate(32 * 1024 * 1024)
        machine.log(machine.send_monitor_command(f"drive_add 0 file={image},if=none,id=hot,format=raw"))
        machine.log(
            machine.send_monitor_command(
                "device_add virtio-blk-pci,drive=hot,id=hotdev,serial=hotplug,bus=hotplug-port"
            )
        )
        machine.wait_until_succeeds(f"test -b {HOTPLUG}", timeout=60)
        machine.succeed("udevadm settle")
        machine.wait_until_succeeds(f"test \"$(blockdev --getro {HOTPLUG})\" = 1", timeout=10)
        machine.fail(f"dd if=/dev/zero of={HOTPLUG} bs=512 count=1 conv=notrunc oflag=direct")

    with subtest("the way back makes the disks writable again and changes nothing on them"):
        canonical_deactivate(CONFIG, "deactivate-2")
        machine.fail(f"findmnt -S \"$(readlink -f {EXTRA})\"")
        machine.fail(f"test -e {RULE}")
        assert not is_read_only(EXTRA), "the disk must be writable again on the decoy"
        assert not is_read_only(HOTPLUG), "the hot-plugged disk must be writable again"
        assert machine.succeed(f"sha256sum < {EXTRA}") == extra_before, (
            "the read-only session wrote to the disk"
        )
        machine.succeed(f"mount {EXTRA} /mnt/extra")
        machine.succeed("findmnt -no OPTIONS /mnt/extra | tr , '\\n' | grep -qx rw")
        machine.succeed("echo decoy-3 > /mnt/extra/decoy-3 && sync")
        machine.fail("test -e /mnt/extra/hidden-2")
        machine.succeed("umount /mnt/extra")
        machine.succeed(f"dd if=/dev/zero of={HOTPLUG} bs=512 count=1 conv=notrunc oflag=direct")
  '';
}
