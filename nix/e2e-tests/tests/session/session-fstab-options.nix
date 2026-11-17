# The fstab policy reads each option of a line by its name, as systemd's fstab
# generator reads it, and leaves a line alone as never mounted only where
# NAILS reads every option it gives.
#
# Four disks stand in for decoy disks the decoy does not mount now, three
# with a decoy filesystem and one empty:
#
#   - "optauto", whose line says noauto,auto=1: the generator takes the last of
#     noauto and auto by name, whatever the value, and links its mount into
#     local-fs.target.requires;
#   - "optautomount", whose line says noauto,x-systemd.automount=0: the
#     generator sets up its automount whatever the value;
#   - "optmakefs", empty, whose line says x-systemd.makefs=1: the generator
#     has the mount pull in systemd-makefs@, which formats a disk it finds
#     empty, before the skip's condition is tested;
#   - "optprobe", whose line says noauto,x-nails.probe, an option NAILS does
#     not read.
#
# The lines go into the hidden session's own /etc/fstab, which the next entry
# without a build decides as the decoy's: the decoy's own boot never read
# them, so no unit its generator made stands for them. In that second hidden
# session the hidden systemd mounts none of the disks, formats none and
# changes none, local-fs.target is reached, and the noauto line with the
# unknown option is masked with a reason that names it. Back on the decoy
# every disk is byte for byte as before, and `check` reads a decoy line with
# noauto,auto=1, written without a reload, as one the boot mounts.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-fstab-options";
  meta.tags = [
    "forensic"
    "session"
  ];
  # Two sessions, four soft-reboots.
  globalTimeout = 1500;

  nodes.machine = _: {
    imports = [ ./../../lib/vm-config.nix ];
    virtualisation.emptyDiskImages = [
      {
        size = 64;
        driveConfig.deviceExtraOpts.serial = "optauto";
      }
      {
        size = 64;
        driveConfig.deviceExtraOpts.serial = "optautomount";
      }
      {
        size = 64;
        driveConfig.deviceExtraOpts.serial = "optmakefs";
      }
      {
        size = 64;
        driveConfig.deviceExtraOpts.serial = "optprobe";
      }
    ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    import shlex

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    AUTO = "/dev/disk/by-id/virtio-optauto"
    AUTOMOUNT = "/dev/disk/by-id/virtio-optautomount"
    MAKEFS = "/dev/disk/by-id/virtio-optmakefs"
    PROBE = "/dev/disk/by-id/virtio-optprobe"
    DISKS = (AUTO, AUTOMOUNT, MAKEFS, PROBE)
    LINES = (
        f"{AUTO} /srv/auto ext4 noauto,auto=1 0 0",
        f"{AUTOMOUNT} /srv/automount ext4 noauto,x-systemd.automount=0 0 0",
        f"{MAKEFS} /srv/makefs ext4 x-systemd.makefs=1 0 0",
        f"{PROBE} /srv/probe ext4 noauto,x-nails.probe 0 0",
    )


    def hashes():
        return {disk: machine.succeed(f"sha256sum < {disk}").split()[0] for disk in DISKS}


    def load_state(unit):
        return machine.succeed(f"systemctl show -p LoadState --value '{unit}'").strip()


    def with_lines(lines):
        # /etc/fstab as a file of its own, NixOS's link into the store
        # replaced, with lines after it.
        machine.succeed(
            'cp --remove-destination "$(readlink -f /etc/fstab)" /etc/fstab && '
            + " && ".join(f"echo {shlex.quote(line)} >> /etc/fstab" for line in lines)
        )


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )
    # Three disks with a decoy filesystem and a file on it; the makefs one
    # stays empty.
    for disk in (AUTO, AUTOMOUNT, PROBE):
        machine.succeed(
            f"mkfs.ext4 -q {disk} && mkdir -p /run/fill && mount {disk} /run/fill && "
            "echo decoy > /run/fill/decoy-file && umount /run/fill"
        )
    before = hashes()

    canonical_activate(CONFIG, "--overlay-only", "activate-1")

    with subtest("the hidden session writes the lines into its own fstab"):
        with_lines(LINES)
        machine.log(machine.succeed("cat /etc/fstab"))

    canonical_deactivate(CONFIG, "deactivate-1")
    assert hashes() == before, "the first session changed a disk"
    machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
    canonical_activate(CONFIG, "--overlay-only", "activate-2")

    with subtest("the hidden systemd mounts, formats and changes none of the disks"):
        printed = machine.succeed("cat /mnt/data/activate-2.log")
        machine.log(printed)
        # Every form is looked at before the subtest fails, so that the log
        # shows each one the policy misread.
        problems = []
        if machine.succeed("systemctl is-active local-fs.target || true").strip() != "active":
            problems.append("local-fs.target is not active")
        if machine.execute("mountpoint -q /srv/auto")[0] == 0:
            problems.append("noauto,auto=1: the disk is mounted")
        machine.execute("ls /srv/automount")
        if machine.execute("mountpoint -q /srv/automount")[0] == 0:
            problems.append("noauto,x-systemd.automount=0: the disk is mounted on access")
        if machine.execute(f"blkid {MAKEFS}")[0] == 0:
            problems.append("x-systemd.makefs=1: the empty disk was formatted")
        if load_state("srv-probe.mount") != "masked":
            problems.append("noauto,x-nails.probe: the mount is not masked")
        if (
            "/srv/probe: masked (noauto, but NAILS does not read its option x-nails.probe as "
            "the line gives it, so the boot may mount it)"
        ) not in printed:
            problems.append("noauto,x-nails.probe: no reason that names the option")
        after = hashes()
        problems += [f"{disk} changed" for disk in DISKS if after[disk] != before[disk]]
        machine.log(f"forms the policy misread: {problems}")
        assert not problems, problems
        assert load_state("srv-auto.mount") == "loaded", "skipped, as local-fs.target requires it"
        assert load_state("srv-automount.mount") == "masked"
        # What a session that wants its own lines gone does: NixOS's link.
        machine.succeed("ln -sfn /etc/static/fstab /etc/fstab")

    canonical_deactivate(CONFIG, "deactivate-2")

    with subtest("back on the decoy, every disk is as before"):
        assert hashes() == before, "a session changed a disk"
        for disk in (AUTO, AUTOMOUNT, PROBE):
            machine.succeed(
                f"mkdir -p /run/fill && mount -o ro {disk} /run/fill && "
                "grep -Fx decoy /run/fill/decoy-file && umount /run/fill"
            )
        machine.fail(f"blkid {MAKEFS}")

    with subtest("check reads noauto,auto=1 on a decoy line as mounted at boot"):
        # Written without a reload: the decoy's generator never read it, and
        # check reads the fstab itself. Left as noauto, the line would not
        # show; kept off, it is skipped, as local-fs.target requires it.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        with_lines(LINES[:1])
        _, out = machine.execute(f"nails --config {CONFIG} check --overlay-only 2>&1")
        machine.log(out)
        assert "/srv/auto: skipped" in out, out
        machine.succeed("ln -sfn /etc/static/fstab /etc/fstab")
  '';
}
