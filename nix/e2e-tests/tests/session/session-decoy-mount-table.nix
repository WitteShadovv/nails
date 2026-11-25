# The decoy's mount table across a session, on a NixOS decoy that boots
# through a bootloader, so its Nix store lives on its root disk as on a real
# install: NixOS binds the store over itself, read-only, nosuid and nodev, once
# the initrd has mounted the root. The decoy also has an fstab filesystem at
# /srv/data, a directory of a store path bound at /opt/pkg after the store
# bind, and its ESP at /boot behind an automount (x-systemd.automount), which
# an access mounts. The hidden session has the ESP read-only and the
# automount skipped: local-fs.target requires it, and a mask would leave the
# target unreached without a failure.
#
# A hidden session never goes back to the decoy: deactivate powers the machine
# off, and the decoy's next start is a cold boot. After it the decoy's mount
# table is that of its first boot: the store is a read-only bind of the root
# filesystem's again, /opt/pkg and /srv/data are there with the decoy's files
# only, the automount on /boot is active and an access mounts the ESP on it,
# every utab line names the mount it was written for, and libmount marks the
# same mounts x-initrd.mount as at the first boot.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-decoy-mount-table";
  meta.tags = [
    "forensic"
    "session"
  ];
  # Two boots through the firmware and a bootloader, a LUKS setup and one
  # session (a soft-reboot in, a power-off out).
  globalTimeout = 1200;

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # A real bootloader on a real ESP: the store is on the root disk.
      virtualisation = {
        useBootLoader = true;
        useEFIBoot = true;
        efi.keepVariables = true;
        emptyDiskImages = [
          {
            size = 64;
            driveConfig.deviceExtraOpts.serial = "extra";
          }
        ];
        fileSystems = {
          "/srv/data" = {
            device = "/dev/disk/by-id/virtio-extra";
            fsType = "ext4";
            autoFormat = true;
          };
          "/opt/pkg" = {
            device = "${pkgs.hello}/share";
            fsType = "none";
            options = [ "bind" ];
          };
          "/boot".options = [ "x-systemd.automount" ];
        };
      };
      boot.loader = {
        systemd-boot.enable = true;
        efi.canTouchEfiVariables = true;
        timeout = lib.mkForce 1;
      };
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
    };

  testScript = _: ''
    from nails_e2e import mounts, utab

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"


    def leave_out(point):
        # /run is the boot's own, and the hidden volume goes with the
        # session. The automount on /boot is a new autofs at every boot.
        return (
            point.startswith("/run/")
            or point in ("/mnt/data", "/boot")
            or point.startswith("/mnt/data/")
        )


    def boot_stack(table):
        # The mounts at /boot, bottom first.
        return mounts.shape(table, lambda point: point != "/boot")


    def mount_boot():
        # An access mounts the ESP on its automount point.
        machine.succeed("ls /boot/loader >/dev/null")
        machine.wait_for_unit("boot.mount")


    def mount_table():
        return (
            machine.succeed("cat /proc/self/mountinfo"),
            machine.succeed("cat /run/mount/utab 2>/dev/null || true"),
        )


    def initrd_mounts():
        # The mount points libmount, joining utab to the mount table, marks
        # x-initrd.mount: systemd leaves them out of the shutdown order.
        marked = set()
        for line in machine.succeed("findmnt --mtab -rn -o TARGET,OPTIONS").splitlines():
            target, _, options = line.partition(" ")
            if "x-initrd.mount" in options.split(","):
                marked.add(target)
        return marked


    def assert_store_and_binds(where):
        table = machine.succeed("cat /proc/self/mountinfo")
        shapes = {mount.place: mount for mount in mounts.shape(table, leave_out)}
        store, root = shapes[("/", "/nix/store")], shapes[("/",)]
        assert (store.dev, store.root) == (root.dev, "/nix/store"), (where, store)
        assert {"ro", "nosuid", "nodev"} <= set(store.options.split(",")), (where, store)
        machine.fail("touch /nix/store/.write-probe")
        pkg = shapes[("/", "/opt/pkg")]
        assert pkg.dev == root.dev and pkg.root.startswith("/nix/store/"), (where, pkg)
        assert ("/", "/srv/data") in shapes, (where, sorted(shapes))


    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("the decoy's store is a read-only bind of its root filesystem's"):
        assert_store_and_binds("the first boot")

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )
    machine.succeed("echo decoy > /srv/data/decoy-file && sync")
    mount_boot()
    before, before_utab = mount_table()
    before_marked = initrd_mounts()
    machine.log(f"the decoy's mount table before the entry:\n{before}\nutab:\n{before_utab}")
    assert "/nix/store" in before_marked, before_marked
    assert [m.fstype for m in boot_stack(before)] == ["autofs", "vfat"], before

    canonical_activate(CONFIG, "--overlay-only", "activate")

    with subtest("the hidden session skips the decoy's automount on /boot"):
        # /boot holds the read-only bind of the ESP: a started automount would
        # find it taken, fail, and take local-fs.target down with it. The
        # target requires the automount, so it is skipped, and the target is
        # reached.
        out = machine.succeed(
            "systemctl show -p LoadState -p ActiveState -p ConditionResult boot.automount"
        )
        state = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        assert state == {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "ConditionResult": "no",
        }, state
        machine.fail("systemctl is-failed --quiet boot.automount")
        assert machine.succeed("systemctl is-active local-fs.target").strip() == "active"
        machine.fail("touch /boot/.write-probe")
        # A write to the decoy's disk from the session is refused or lands
        # in the session's overlay: never on the disk.
        machine.succeed("echo hidden > /srv/data/hidden-file || true")

    # Powers off for real; the decoy then boots cold.
    canonical_deactivate(CONFIG, "deactivate")

    with subtest("the decoy's boot sets up the automount on /boot again"):
        machine.fail("test -e /run/systemd/system/boot.automount.d")
        machine.succeed("systemctl is-active boot.automount")
        machine.fail("systemctl is-failed --quiet boot.automount")
        mount_boot()

    with subtest("the decoy's mount table after the cold boot is its first boot's"):
        after, after_utab = mount_table()
        machine.log(f"the decoy's mount table after the cold boot:\n{after}\nutab:\n{after_utab}")
        assert_store_and_binds("the cold boot")
        machine.succeed("nix-store --verify-path $(readlink -f /run/current-system)")
        boot = boot_stack(after)
        assert [m.fstype for m in boot] == ["autofs", "vfat"], boot
        wrong = utab.wrong_lines(after_utab, after)
        assert not wrong, f"utab lines naming no live mount or another: {wrong}"
        assert initrd_mounts() == before_marked, sorted(initrd_mounts())

    with subtest("/srv/data holds the decoy's files only"):
        assert machine.succeed("cat /srv/data/decoy-file").strip() == "decoy"
        machine.fail("test -e /srv/data/hidden-file")
  '';
}
