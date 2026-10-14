# Test 25: the attach gate on the decoy's own storage
#
# The decoy here lists two more filesystems in its fstab: ext4 at /srv and
# btrfs at /pool. A hidden root that lives on either is not a volume of its
# own, whatever is mounted there, because everything written to it lands on
# the decoy's disk:
#
#   1. a folder of /srv: init, `activate -y --overlay-only` (with and without
#      --no-preflight) and check refuse it with not_separate_volume (exit 4),
#      and the folder stays empty with its mtime and ctime unchanged;
#   2. a btrfs subvolume of /pool mounted on its own is refused; its mount
#      table line shows the same device as /pool's, while stat shows another
#      (the judge relies on the first);
#   3. a bind mount of a folder of /srv is refused;
#   4. `init --allow-unmounted` uses the folder of /srv with a warning;
#   5. a LUKS volume on the separate data disk passes the hidden-volume check;
#   6. a tmpfs mounted over that volume is refused with root_covered;
#   7. a decoy crypttab line that opens the data disk, then one with
#      tcrypt-hidden, fails the backend-entries check (exit 4); a line for
#      another device passes it.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-decoy-filesystem";
  meta.tags = [
    "preflight"
    "security"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        pkgs.btrfs-progs
      ];
      virtualisation.emptyDiskImages = [
        {
          size = 256;
          driveConfig.deviceExtraOpts.serial = "srv";
        }
        {
          size = 512;
          driveConfig.deviceExtraOpts.serial = "pool";
        }
      ];
      boot.supportedFilesystems = [ "btrfs" ];
      virtualisation.fileSystems = {
        "/srv" = {
          device = "/dev/disk/by-id/virtio-srv";
          fsType = "ext4";
          autoFormat = true;
        };
        "/pool" = {
          device = "/dev/disk/by-id/virtio-pool";
          fsType = "btrfs";
          autoFormat = true;
        };
      };
    };

  testScript = _: ''
    import json

    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}


    def config_for(root):
        path = f"/run/gate-{root.strip('/').replace('/', '-')}.toml"
        write_text_file(path, f'hidden_volume_root = "{root}"\nminimum_space_mb = 100\n')
        return path


    def last_json(result):
        return json.loads(result["stdout"].strip().splitlines()[-1])


    def times(path):
        return machine.succeed(f"stat -c '%Y %Z' {path}").strip()


    def check_row(report, name):
        rows = [row for row in report["data"]["checks"] if row["name"] == name]
        assert len(rows) == 1, report
        return rows[0]


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mountpoint -q /srv && mountpoint -q /pool")
    machine.succeed("grep -q ' /srv ' /etc/fstab && grep -q ' /pool ' /etc/fstab")

    with subtest("a folder of a decoy filesystem is refused and left untouched"):
        machine.succeed("mkdir -p /srv/x && touch -m -d '2001-02-03 04:05:06' /srv/x")
        before = times("/srv/x")
        config = config_for("/srv/x")

        result = run_command_capture("gate-init", "nails init --no-hardware-config /srv/x")
        assert_exit_code(result, 4)
        assert_result_contains(
            result,
            [
                "error: /srv/x is not a volume of its own: it is a folder on the filesystem "
                "mounted at /srv. Nothing was written.",
                "Where setup happens",
            ],
        )
        for flags in ["", " --no-preflight"]:
            result = run_command_capture(
                "gate-activate",
                f"nails --config {config} --json activate -y --overlay-only{flags}",
            )
            assert_exit_code(result, 4)
            assert last_json(result)["error"]["code"] == "not_separate_volume", result
        result = run_command_capture(
            "gate-check", f"nails --config {config} --json check --overlay-only"
        )
        assert_exit_code(result, 4)
        report = last_json(result)
        assert report["data"]["refusal"]["code"] == "not_separate_volume", report
        assert check_row(report, "hidden-volume")["status"] == "fail", report
        assert check_row(report, "backend-entries")["status"] == "skipped", report

        machine.succeed('test -z "$(ls -A /srv/x)"')
        assert times("/srv/x") == before, (before, times("/srv/x"))

    with subtest("a btrfs subvolume of a decoy filesystem is refused"):
        machine.succeed(
            "btrfs subvolume create /pool/vol && mkdir -p /mnt/sub && "
            "mount -o subvol=vol /dev/disk/by-id/virtio-pool /mnt/sub"
        )
        # The judge compares the mount table's device, which a subvolume
        # shares with its filesystem; stat reports another one.
        sub_dev = machine.succeed("findmnt -no MAJ:MIN /mnt/sub").strip()
        pool_dev = machine.succeed("findmnt -no MAJ:MIN /pool").strip()
        assert sub_dev == pool_dev, (sub_dev, pool_dev)
        assert machine.succeed("stat -c %d /mnt/sub") != machine.succeed("stat -c %d /pool")
        result = run_command_capture("gate-subvol", "nails init --no-hardware-config /mnt/sub")
        assert_exit_code(result, 4)
        assert_result_contains(
            result, ["it is a subvolume of the btrfs filesystem at /pool"]
        )
        machine.succeed('test -z "$(ls -A /mnt/sub)"')
        machine.succeed("umount /mnt/sub")

    with subtest("a bind mount of a decoy folder is refused"):
        machine.succeed("mkdir -p /mnt/bind && mount --bind /srv/x /mnt/bind")
        result = run_command_capture("gate-bind", "nails init --no-hardware-config /mnt/bind")
        assert_exit_code(result, 4)
        assert_result_contains(result, ["it is a bind mount of a folder of /srv"])
        machine.succeed("umount /mnt/bind")
        machine.succeed('test -z "$(ls -A /srv/x)"')

    with subtest("--allow-unmounted uses a decoy folder with a warning"):
        result = run_command_capture(
            "gate-allow", "nails init --no-hardware-config --allow-unmounted /srv/x"
        )
        assert_exit_code(result, 0)
        assert_result_contains(
            result,
            [
                "warning: --allow-unmounted: using /srv/x although it is a folder on the "
                "filesystem mounted at /srv; every file nails writes there lands on that storage"
            ],
        )
        machine.succeed("test -f /srv/x/state.json")
        machine.succeed("rm -rf /srv/x")

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    data_config = config_for("/mnt/data")

    with subtest("a volume of its own on the separate disk passes"):
        result = run_command_capture(
            "gate-volume", f"nails --config {data_config} --json check --overlay-only"
        )
        report = last_json(result)
        assert "refusal" not in report["data"], report
        assert check_row(report, "hidden-volume")["status"] == "pass", report
        assert check_row(report, "backend-entries")["status"] == "pass", report

    with subtest("a second filesystem over the volume is refused"):
        machine.succeed("mount -t tmpfs cover /mnt/data")
        result = run_command_capture(
            "gate-covered", f"nails --config {data_config} --json check --overlay-only"
        )
        assert_exit_code(result, 4)
        report = last_json(result)
        assert report["data"]["refusal"]["code"] == "root_covered", report
        assert check_row(report, "hidden-volume")["status"] == "fail", report
        result = run_command_capture(
            "gate-covered-activate",
            f"nails --config {data_config} --json activate -y --overlay-only",
        )
        assert_exit_code(result, 4)
        assert last_json(result)["error"]["code"] == "root_covered", result
        machine.succeed('test -z "$(ls -A /mnt/data)"')
        machine.succeed("umount /mnt/data")

    with subtest("a decoy crypttab entry for the volume fails backend-entries"):
        for line in [
            "data /dev/disk/by-id/virtio-data none luks,noauto",
            "vault /dev/disk/by-id/virtio-srv none tcrypt-hidden,noauto",
        ]:
            write_text_file("/etc/crypttab", line + "\n")
            result = run_command_capture(
                "gate-entries", f"nails --config {data_config} --json check --overlay-only"
            )
            assert_exit_code(result, 4)
            row = check_row(last_json(result), "backend-entries")
            assert row["status"] == "fail", row
            assert line.split()[0] + " /dev/" in row["message"], row
        write_text_file(
            "/etc/crypttab", "backup /dev/disk/by-id/virtio-pool none luks,noauto\n"
        )
        result = run_command_capture(
            "gate-entries-other", f"nails --config {data_config} --json check --overlay-only"
        )
        row = check_row(last_json(result), "backend-entries")
        assert row["status"] == "pass", row
        machine.succeed("rm -f /etc/crypttab")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
