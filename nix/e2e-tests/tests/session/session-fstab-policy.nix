# The fstab policy: every decoy filesystem the hidden systemd would mount gets
# a safe decision before the switch (ADR 0008, section 2).
#
# The decoy here has an ESP at /boot, a separate ext4 filesystem at /srv/data
# and a swap partition in its fstab, besides the root and the VM's own Nix
# store. In the hidden session:
#
#   - /boot is a read-only bind: a write fails with EROFS and the ESP is
#     unchanged afterwards;
#   - /srv/data is an overlay whose upper is on the hidden volume: a hidden
#     write lands there and never on the extra disk;
#   - the swap unit is masked, so the hidden systemd never swaps onto a decoy
#     disk;
#   - the VM's /nix/store (an overlay of a 9p share) is overlaid too, which is
#     what lets PID 1 find its own binary in the hidden root.
#
# Back on the decoy, both filesystems are mounted by the decoy's own fstab
# again, without a trace of the hidden writes.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-fstab-policy";
  meta.tags = [
    "forensic"
    "session"
  ];
  globalTimeout = 1200;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        pkgs.dosfstools
      ];
      virtualisation.emptyDiskImages = [
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "esp";
        }
        {
          size = 256;
          driveConfig.deviceExtraOpts.serial = "extra";
        }
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "swap";
        }
      ];
      boot.supportedFilesystems = [ "vfat" ];
      virtualisation.fileSystems = {
        "/boot" = {
          device = "/dev/disk/by-id/virtio-esp";
          fsType = "vfat";
          autoFormat = true;
        };
        "/srv/data" = {
          device = "/dev/disk/by-id/virtio-extra";
          fsType = "ext4";
          autoFormat = true;
        };
      };
    };

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    SWAP_UNIT = "dev-disk-by\\x2did-virtio\\x2dswap.swap"


    def esp_hashes():
        return machine.succeed(
            "cd /boot && find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum"
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mountpoint -q /boot && mountpoint -q /srv/data")
    # A swap partition in the decoy's fstab, never activated by the decoy
    # itself (the swap pre-flight check refuses active swap); the hidden
    # systemd must not activate it either. The VM profile overrides
    # swapDevices, so the line is added to the decoy's fstab directly.
    machine.succeed("mkswap /dev/disk/by-id/virtio-swap")
    machine.succeed(
        "cp --remove-destination \"$(readlink -f /etc/fstab)\" /etc/fstab && "
        "echo '/dev/disk/by-id/virtio-swap none swap defaults,noauto 0 0' >> /etc/fstab && "
        "systemctl daemon-reload"
    )
    machine.succeed("echo decoy > /boot/decoy-file && echo decoy > /srv/data/decoy-file && sync")
    esp_before = esp_hashes()

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    with subtest("check reports the decision for every decoy filesystem"):
        out = machine.succeed(f"nails --config {CONFIG} check --overlay-only")
        machine.log(out)
        assert "/boot: read-only" in out, out
        assert "/srv/data: overlaid" in out, out
        assert "masked" in out, out

    canonical_activate(CONFIG, "--overlay-only", "activate")

    with subtest("the ESP is read-only in the hidden root"):
        assert machine.succeed("cat /boot/decoy-file").strip() == "decoy"
        machine.fail("touch /boot/hidden-write")
        assert "ro" in machine.succeed("findmnt -no OPTIONS /boot").split(",")

    with subtest("a separate decoy filesystem is overlaid with a hidden upper"):
        assert session.root_fstype(machine) == "overlay"
        assert machine.succeed("findmnt -no FSTYPE /srv/data").strip() == "overlay"
        assert machine.succeed("cat /srv/data/decoy-file").strip() == "decoy"
        machine.succeed("echo hidden > /srv/data/hidden-file && sync")
        machine.succeed("test -s /mnt/data/root/mounts/srv-data/upper/hidden-file")
        machine.succeed(
            "mkdir -p /run/peek && mount /dev/disk/by-id/virtio-extra /run/peek "
            "&& mount -o remount,bind,ro /run/peek"
        )
        machine.fail("test -e /run/peek/hidden-file")
        machine.succeed("umount /run/peek && rmdir /run/peek")

    with subtest("decoy swap is masked and never active"):
        state = machine.succeed(f"systemctl show -p LoadState --value '{SWAP_UNIT}'").strip()
        assert state == "masked", f"{SWAP_UNIT}: {state}"
        machine.fail(f"systemctl start '{SWAP_UNIT}'")
        assert machine.succeed("swapon --show --noheadings").strip() == ""

    with subtest("the Nix store of the VM is overlaid too"):
        assert machine.succeed("findmnt -no FSTYPE /nix/store").strip() == "overlay"
        machine.succeed("test -x /run/current-system/systemd/lib/systemd/systemd")

    canonical_deactivate(CONFIG, "deactivate")

    with subtest("back on the decoy, nothing of the hidden writes is on its disks"):
        machine.succeed("mountpoint -q /boot && mountpoint -q /srv/data")
        machine.fail("test -e /srv/data/hidden-file")
        machine.fail("test -e /boot/hidden-write")
        assert machine.succeed("cat /srv/data/decoy-file").strip() == "decoy"
        assert esp_hashes() == esp_before, "the ESP changed"
        state = machine.succeed(f"systemctl show -p LoadState --value '{SWAP_UNIT}'").strip()
        assert state != "masked", f"the swap mask leaked into the decoy: {state}"
  '';
}
