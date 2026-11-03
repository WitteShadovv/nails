# Test 27: the attach gate on a ZFS volume
#
# A ZFS volume keeps its data in its pool, on disks the attach gate does not
# read. A pool made from an image file on the decoy's /srv holds a volume
# (/dev/zd0), with ext4 on it mounted at /mnt/zvol:
#
#   1. /proc/devices lists the zvol driver, which is how the gate tells the
#      volume;
#   2. init refuses it with storage_unjudged (exit 4), with and without
#      --allow-decoy-storage, and leaves it untouched;
#   3. check refuses it as well, and names no override for it, neither in its
#      report nor in its hidden-volume row.
{ self, pkgs, ... }:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-decoy-zvol";
  meta.tags = [
    "preflight"
    "security"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      boot.supportedFilesystems = [ "zfs" ];
      # No pool is the root's: the import at boot forces nothing.
      boot.zfs.forceImportRoot = false;
      # ZFS refuses to run without a host id.
      networking.hostId = "4e98920d";
      virtualisation.emptyDiskImages = [
        {
          size = 512;
          driveConfig.deviceExtraOpts.serial = "srv";
        }
      ];
      virtualisation.fileSystems."/srv" = {
        device = "/dev/disk/by-id/virtio-srv";
        fsType = "ext4";
        autoFormat = true;
      };
    };

  testScript = _: ''
    import json

    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}


    def times(path):
        return machine.succeed(f"stat -c '%Y %Z' {path}").strip()


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mountpoint -q /srv && grep -q ' /srv ' /etc/fstab")

    with subtest("a ZFS volume in a pool on a decoy filesystem is refused"):
        machine.succeed(
            "truncate -s 256M /srv/pool.img && zpool create -f tank /srv/pool.img && "
            "zfs create -V 64M tank/vol && udevadm settle && "
            "grep -Eq '^ *[0-9]+ zvol$' /proc/devices && "
            "mkfs.ext4 -q /dev/zvol/tank/vol && mkdir -p /mnt/zvol && "
            "mount /dev/zvol/tank/vol /mnt/zvol && "
            "touch -m -d '2001-02-03 04:05:06' /mnt/zvol"
        )
        before = times("/mnt/zvol")
        listing = machine.succeed("ls -A /mnt/zvol")
        for flags in ["", " --allow-decoy-storage"]:
            result = run_command_capture(
                "gate-zvol", f"nails init --no-hardware-config{flags} /mnt/zvol"
            )
            assert_exit_code(result, 4)
            assert_result_contains(
                result,
                [
                    "error: /mnt/zvol is stored on a ZFS volume, which shows no disk it "
                    "stores its data on, so where it lives cannot be told. Nothing was "
                    "written."
                ],
            )
            assert_result_not_contains(result, ["warning: --allow-decoy-storage"])

        write_text_file(
            "/run/gate-zvol.toml",
            'hidden_volume_root = "/mnt/zvol"\nminimum_space_mb = 10\n',
        )
        result = run_command_capture(
            "gate-zvol-check", "nails --config /run/gate-zvol.toml --json check --overlay-only"
        )
        assert_exit_code(result, 4)
        report = json.loads(result["stdout"].strip().splitlines()[-1])
        refusal = report["data"]["refusal"]
        assert refusal["code"] == "storage_unjudged", report
        assert "allowable" not in refusal, report
        rows = [row for row in report["data"]["checks"] if row["name"] == "hidden-volume"]
        assert len(rows) == 1, report
        assert rows[0]["status"] == "fail", rows
        assert "allowable" not in rows[0], rows

        assert machine.succeed("ls -A /mnt/zvol") == listing
        assert times("/mnt/zvol") == before, (before, times("/mnt/zvol"))
        machine.succeed("umount /mnt/zvol && zpool destroy tank && rm -f /srv/pool.img")
  '';
}
