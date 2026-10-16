# The decoy's mount table across a session, on a NixOS decoy that boots
# through a bootloader, so its Nix store lives on its root disk as on a real
# install: NixOS binds the store over itself, read-only, nosuid and nodev, once
# the initrd has mounted the root. The decoy also has an fstab filesystem at
# /srv/data with a read-only bind of itself stacked on it, the way NixOS stacks
# a store that is a filesystem of its own; a directory of a store path bound
# at /opt/pkg after the store bind, so the way back reaches it on the root
# filesystem below a mount it made a moment before; and its ESP at /boot
# behind an automount (x-systemd.automount), which an access mounts. The
# hidden session has the ESP read-only and the automount masked.
#
# Before the first entry the test records the decoy's mount table and utab.
# After the way back every mount outside /run, /boot and the hidden volume is
# there again, in the order the decoy made it: the same filesystem and
# directory at the same place in the tree, with the same source, type, options
# and propagation type (only the IDs and peer groups are new), and no mount
# more. The decoy's utab lines are back under the new mount IDs, libmount
# marks the same mounts x-initrd.mount as before, and the store is read-only
# again. The decoy's own start sets up the automount on /boot again, as after
# a plain soft-reboot, and the next access mounts the same ESP on it. Before
# the way back made the decoy's mounts again, the store bind and the bottom
# layer at /srv/data never came back, and the store stayed writable until the
# next boot; a way back that put the ESP straight back on /boot left
# boot.automount failed.
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
  # A boot through the firmware and a bootloader, a LUKS setup and one
  # soft-reboot round trip.
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
        # A soft-reboot into a new root carries /run without the mounts below
        # it, and the hidden volume goes with the session. The automount on
        # /boot is the decoy's start's own, a new autofs every time.
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


    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("the decoy's store is a read-only bind of its root filesystem's"):
        table = machine.succeed("cat /proc/self/mountinfo")
        shapes = {mount.place: mount for mount in mounts.shape(table, leave_out)}
        store, root = shapes[("/", "/nix/store")], shapes[("/",)]
        assert (store.dev, store.root) == (root.dev, "/nix/store"), store
        assert {"ro", "nosuid", "nodev"} <= set(store.options.split(",")), store
        machine.fail("touch /nix/store/.write-probe")
        pkg = shapes[("/", "/opt/pkg")]
        assert pkg.dev == root.dev and pkg.root.startswith("/nix/store/"), pkg

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )
    machine.succeed(
        "echo decoy > /srv/data/decoy-file && "
        "mount --bind /srv/data /srv/data && mount -o remount,bind,ro /srv/data"
    )
    mount_boot()
    before, before_utab = mount_table()
    before_marked = initrd_mounts()
    machine.log(f"the decoy's mount table before the entry:\n{before}\nutab:\n{before_utab}")
    assert "/nix/store" in before_marked, before_marked
    assert [m.fstype for m in boot_stack(before)] == ["autofs", "vfat"], before

    canonical_activate(CONFIG, "--overlay-only", "activate")

    with subtest("the hidden session keeps the decoy's automount on /boot masked"):
        # /boot holds the read-only bind of the ESP: a started automount would
        # find it taken, fail, and take local-fs.target down with it.
        state = machine.succeed("systemctl show -P LoadState boot.automount").strip()
        assert state == "masked", state
        machine.fail("systemctl is-failed --quiet boot.automount")
        machine.fail("touch /boot/.write-probe")

    canonical_deactivate(CONFIG, "deactivate")

    with subtest("the decoy's start sets up the automount on /boot again"):
        machine.succeed("systemctl is-active boot.automount")
        machine.fail("systemctl is-failed --quiet boot.automount")
        mount_boot()

    with subtest("the decoy has every mount back as it had it before the entry"):
        after, after_utab = mount_table()
        machine.log(f"the decoy's mount table after the way back:\n{after}\nutab:\n{after_utab}")
        found = mounts.differences(
            mounts.shape(before, leave_out), mounts.shape(after, leave_out)
        )
        assert not found, "mounts not as before the entry:\n" + "\n".join(found)
        # The automount is new; the ESP an access mounted on it is the same.
        boot = boot_stack(after)
        assert [m.fstype for m in boot] == ["autofs", "vfat"], boot
        assert boot[1] == boot_stack(before)[1], (boot_stack(before), boot)

    with subtest("its utab lines are back with its mounts"):
        wrong = utab.wrong_lines(after_utab, after)
        assert not wrong, f"utab lines naming no live mount or another: {wrong}"
        foreign, lost = utab.not_given_back(before_utab, before, after_utab, after)
        assert not foreign and not lost, (
            f"the decoy's utab after the way back:\n{after_utab}\n"
            f"lines not its own: {foreign}; its lines not given back: {lost}"
        )
        assert initrd_mounts() == before_marked, sorted(initrd_mounts())

    with subtest("the store is read-only again and the stack at /srv/data is the decoy's"):
        machine.fail("touch /nix/store/.write-probe")
        machine.succeed("nix-store --verify-path $(readlink -f /run/current-system)")
        machine.fail("touch /srv/data/hidden-file")
        assert machine.succeed("cat /srv/data/decoy-file").strip() == "decoy"
  '';
}
