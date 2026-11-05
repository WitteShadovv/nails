# The daily routine with an automounter: a USB drive attached to a running
# desktop and unlocked from a terminal there.
#
# A desktop that mounts drives by itself (gnome-shell through gvfs and udisks2,
# KDE's device notifier, udiskie) can mount the filesystem of a volume unlocked
# from a terminal a second time, under /media/<user> or /run/media/<user>.
# Whether it does for a mapping that cryptsetup opened, rather than one it
# unlocked itself, is what this test records. udisks2 and udiskie stand in for
# the desktop: udiskie runs as a root service, without a display, and mounts
# what udisks2 offers it, as its default rules decide. The drive is a LUKS
# volume with ext4 inside, prepared while no automounter runs, then detached
# and attached again through the QEMU monitor (lib/external-disk.nix):
#
#   1. With udiskie automounting, the drive is attached and unlocked with
#      cryptsetup. A FINDING line records whether udiskie mounted the opened
#      filesystem, and where; the same is kept in the test's output as
#      automount-finding.json, so a run served from the binary cache still
#      shows it. When it mounted it, `nails check` exits 4 naming that mount
#      point next to the routine's own mount at /mnt/data; otherwise it passes.
#   2. A second mount of the opened filesystem made by hand under /run/media
#      fails `check` the same way, whatever udiskie did.
#   3. Once each second mount is unmounted with `umount`, as the refusal says,
#      `check` passes.
#   4. With udiskie started with --no-automount, unlocking the drive again
#      mounts it nowhere, and `check` passes.
#
# The deterministic proof of the refusal is the preflight-hidden-root batch,
# which runs in every pull request's shards; this test is in the `heavy`
# group, which they leave out.
{ self, pkgs, ... }:
let
  externalDisk = import ./../../lib/external-disk.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  udiskie =
    flags:
    "${pkgs.udiskie}/bin/udiskie --no-config --no-notify --no-tray --no-password-prompt "
    + "--no-file-manager --verbose ${flags}";
in
{
  name = "routine-automount";
  meta.tags = [
    "preflight"
    "heavy"
  ];

  nodes.machine = _: {
    imports = [
      ./../../lib/vm-config.nix
      externalDisk.module
    ];
    environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
    services.udisks2.enable = true;
    # Started by the test, one at a time: an automounting one, and one that
    # only watches.
    systemd.services = {
      udiskie = {
        description = "udiskie, mounting drives as a desktop would";
        after = [ "udisks2.service" ];
        serviceConfig.ExecStart = udiskie "--automount";
      };
      udiskie-watch = {
        description = "udiskie with automounting off";
        after = [ "udisks2.service" ];
        serviceConfig.ExecStart = udiskie "--no-automount";
      };
    };
  };

  testScript = _: ''
    import json
    import os
    import time

    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${externalDisk.plugFns}

    PASSPHRASE = "test-passphrase"
    CONFIG = "/run/routine-automount.toml"
    MANUAL = "/run/media/testuser/data"
    finding = {}


    def keep(key, value):
        """Record what udiskie did, in the log and in the test's output."""
        finding[key] = value
        machine.log(f"FINDING: {key}: {json.dumps(value)}")
        out_dir = getattr(machine, "out_dir", None)
        if out_dir:
            with open(os.path.join(out_dir, "automount-finding.json"), "w") as fh:
                json.dump(finding, fh, indent=2, sort_keys=True)


    def unlock(drive):
        machine.succeed(
            f"echo -n {PASSPHRASE} | cryptsetup open --key-file - {drive} data && udevadm settle"
        )


    def cleartext_object():
        """The udisks2 object path of the opened mapping, as udiskie names it."""
        kernel = machine.succeed("basename \"$(readlink -f /dev/mapper/data)\"").strip()
        return "/org/freedesktop/UDisks2/block_devices/" + kernel.replace("-", "_2d")


    def seen_by(unit, cleartext):
        """Wait until udiskie in `unit` was told the mapping appeared."""
        machine.wait_until_succeeds(
            f"journalctl -u {unit} -o cat | grep -F '+++ device_added: {cleartext}'",
            timeout=60,
        )


    def other_mounts():
        """Where the opened filesystem is mounted, but at /mnt/data: every
        mount with the device number of the mapping, whatever source it
        names."""
        dev = machine.succeed("lsblk -dno MAJ:MIN /dev/mapper/data").strip()
        table = machine.succeed("findmnt -rn -o TARGET,MAJ:MIN").splitlines()
        rows = [row.rsplit(" ", 1) for row in table]
        return [target for target, number in rows if number == dev and target != "/mnt/data"]


    def mounts_within(seconds):
        """The other mounts of the opened filesystem once one appears, or none
        after `seconds`."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            found = other_mounts()
            if found:
                return found
            machine.sleep(1)
        return other_mounts()


    def check():
        return run_command_capture(
            "routine-check", f"nails --config {CONFIG} check --overlay-only --ascii"
        )


    def joined(places):
        """`places` as the refusal names them: `a`, `a and b`, `a, b and c`."""
        if len(places) < 2:
            return "".join(places)
        return ", ".join(places[:-1]) + " and " + places[-1]


    def assert_refused_naming(result, places):
        """`check` refused, naming every one of `places`, in the order of the
        mount table, and the line that unmounts them, the deepest first."""
        assert_exit_code(result, 4)
        deepest_first = sorted(places, key=lambda place: -place.count("/"))
        assert_result_contains(
            result,
            [
                f"the volume at /mnt/data is also mounted at {joined(places)}: "
                "a desktop may have mounted it there by itself",
                f"Run `sudo umount {' '.join(deepest_first)}`, then run the command again.",
            ],
            stream="stdout",
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed(
        f"printf 'hidden_volume_root = \"/mnt/data\"\\nminimum_space_mb = 100\\n' > {CONFIG}"
    )

    with subtest("prepare the drive while no automounter runs"):
        drive = plug_usb_drive("stick")
        machine.succeed(
            f"echo -n {PASSPHRASE} | cryptsetup luksFormat -q --iter-time=1 {drive} -"
        )
        unlock(drive)
        machine.succeed(
            "mkfs.ext4 -q /dev/mapper/data && mkdir -p /mnt/data && "
            "mount /dev/mapper/data /mnt/data && nails init /mnt/data && "
            "umount /mnt/data && cryptsetup close data"
        )
        unplug_usb_drive("stick")

    with subtest("attached and unlocked from a terminal while udiskie automounts"):
        machine.succeed("systemctl start udiskie.service")
        machine.wait_until_succeeds(
            "journalctl -u udiskie.service -o cat | grep -F 'Daemon version'", timeout=60
        )
        drive = plug_usb_drive("stick")
        unlock(drive)
        cleartext = cleartext_object()
        seen_by("udiskie.service", cleartext)
        # A person types the mount line after the unlock; udiskie waits 1.5 s
        # before it handles an unlocked mapping.
        mounted = mounts_within(30)
        keep("udiskie_mounted_the_mapping", bool(mounted))
        keep("udiskie_mount_points", mounted)
        machine.log(machine.succeed("journalctl -u udiskie.service -o cat"))
        machine.succeed("mount /dev/mapper/data /mnt/data")
        result = check()
        if mounted:
            assert_refused_naming(result, mounted)
        else:
            assert_exit_code(result, 0)

    with subtest("a second mount made by hand under /run/media is refused too"):
        machine.succeed(f"mkdir -p {MANUAL} && mount /dev/mapper/data {MANUAL}")
        assert_refused_naming(check(), mounted + [MANUAL])

    with subtest("once every second mount is unmounted, check passes"):
        for place in mounted + [MANUAL]:
            machine.succeed(f"umount {place}")
        assert other_mounts() == [], other_mounts()
        result = check()
        assert_exit_code(result, 0)
        assert_result_contains(result, ["Ready to activate"], stream="stdout")

    with subtest("with automounting off, unlocking mounts the drive nowhere else"):
        machine.succeed(
            "systemctl stop udiskie.service && umount /mnt/data && cryptsetup close data"
        )
        machine.succeed("systemctl start udiskie-watch.service")
        machine.wait_until_succeeds(
            "journalctl -u udiskie-watch.service -o cat | grep -F 'Daemon version'", timeout=60
        )
        unlock(drive)
        seen_by("udiskie-watch.service", cleartext_object())
        assert mounts_within(15) == [], other_mounts()
        machine.succeed("mount /dev/mapper/data /mnt/data")
        result = check()
        assert_exit_code(result, 0)
        machine.succeed("umount /mnt/data && cryptsetup close data")
        unplug_usb_drive("stick")
  '';
}
