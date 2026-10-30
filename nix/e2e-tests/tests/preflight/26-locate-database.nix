# Test 26: the locate-database check and the leak it guards against
#
# updatedb writes the name of every file it finds into the locate database on
# the decoy disk, so a run while the hidden volume is mounted lists the
# volume's files there. Two NixOS decoys run services.locate, whose timer is
# enabled:
#
#   1. unpruned, with NixOS's default prunePaths, which do not skip /mnt:
#      `check` refuses (exit 4) on the locate-database row, and a real run of
#      update-locatedb.service with the volume mounted lists the volume's
#      files in /var/cache/locatedb on the decoy disk;
#   2. pruned, with the fix the check prints,
#      `services.locate.prunePaths = lib.mkOptionDefault [ "/mnt" ];`, which
#      its /etc/nixos holds too: `check` passes, the locate-database row names
#      the rule, the check of the decoy's /etc/nixos passes that line, and
#      the same run lists nothing below /mnt. A timer of its own that is not
#      enabled, whose updatedb prunes /tmp alone, refuses once
#      `systemctl start` runs it, and so does a transient one
#      `systemd-run --on-calendar` makes: systemd leaves no file that says a
#      timer runs, so the check asks `systemctl list-units`, and reads
#      /run/systemd/transient. Once they stop, `check` passes again.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;

  # The fix, as the check prints it, for the decoy's configuration and for
  # its /etc/nixos.
  fixText = ''
    { lib, ... }:
    {
      services.locate.prunePaths = lib.mkOptionDefault [ "/mnt" ];
    }
  '';
  fix =
    { lib, ... }:
    {
      services.locate.prunePaths = lib.mkOptionDefault [ "/mnt" ];
    };

  decoy =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      services.locate.enable = true;
    };

  # A timer of the decoy's own, not enabled, whose updatedb prunes /tmp alone.
  reindex =
    { lib, ... }:
    {
      systemd.services.reindex = {
        description = "Index the decoy again";
        serviceConfig.ExecStart = "${pkgs.plocate}/bin/updatedb --prunepaths /tmp --output /var/cache/reindex.db";
      };
      systemd.timers.reindex = {
        wantedBy = lib.mkForce [ ];
        timerConfig.OnCalendar = "hourly";
      };
    };
in
{
  name = "locate-database";
  meta.tags = [
    "preflight"
    "security"
  ];

  nodes = {
    unpruned = decoy;
    pruned =
      { ... }:
      {
        imports = [
          decoy
          fix
          reindex
        ];
        environment.etc."nixos/locate.nix" = {
          mode = "0644";
          text = fixText;
        };
      };
  };

  testScript = _: ''
    import json
    import shlex

    CONFIG = "/run/locate-check.toml"
    DATABASE = "/var/cache/locatedb"


    def prepare(node):
        node.wait_for_unit("multi-user.target")
        node.succeed("systemctl is-enabled update-locatedb.timer")
        node.succeed("""${hiddenVolume.setupHiddenVolume}""")
        node.succeed(
            "mkdir -p /mnt/data/notes && echo kept > /mnt/data/notes/plan.txt && "
            + "printf 'hidden_volume_root = \"/mnt/data\"\\nminimum_space_mb = 100\\n' > "
            + CONFIG
        )
        print(node.succeed("cat /etc/updatedb.conf"))
        print(node.succeed("systemctl cat update-locatedb.service"))


    def check(node):
        stem = "/run/locate-check"
        node.succeed(
            "bash -c "
            + shlex.quote(
                f"set +e; nails --config {CONFIG} --json check --overlay-only "
                + f"> {stem}.out 2> {stem}.err; echo $? > {stem}.rc"
            )
        )
        rc = int(node.succeed(f"cat {stem}.rc").strip())
        report = json.loads(node.succeed(f"cat {stem}.out").strip().splitlines()[-1])
        rows = {row["name"]: row for row in report["data"]["checks"]}
        print(json.dumps(rows["locate-database"], indent=2))
        return rc, rows


    def index(node):
        # A real run of updatedb with the volume mounted. The database lies on
        # the decoy's own disk.
        node.succeed("mountpoint -q /mnt/data")
        # The unit runs updatedb as its main process (Type=simple): --wait
        # returns once it has ended, with its result.
        node.succeed("systemctl start --wait update-locatedb.service")
        node.succeed(f"test $(stat -c %d {DATABASE}) = $(stat -c %d /)")
        # It indexed the decoy itself.
        node.succeed(f"plocate -d {DATABASE} /etc/nixos/configuration.nix")
        # plocate exits 1 when nothing matches.
        return node.execute(f"plocate -d {DATABASE} /mnt/")


    start_all()

    with subtest("without /mnt pruned, check refuses and a run lists the volume"):
        prepare(unpruned)
        rc, rows = check(unpruned)
        row = rows["locate-database"]
        assert rc == 4, (rc, row)
        assert row["status"] == "fail", row
        for part in [
            "update-locatedb.timer schedules updatedb",
            "does not skip the hidden volume at /mnt/data",
            "into /var/cache/locatedb on the decoy disk",
        ]:
            assert part in row["message"], (part, row)
        assert "services.locate.prunePaths = lib.mkOptionDefault [ \"/mnt\" ];" in row[
            "remediation"
        ], row
        assert "unmount /mnt/data" in row["remediation"], row
        status, listed = index(unpruned)
        assert status == 0, (status, listed)
        for name in ["/mnt/data/notes/plan.txt", "/mnt/data/root/work", "/mnt/data/config/nixos"]:
            assert name in listed.splitlines(), (name, listed)

    with subtest("with the printed fix, check passes and a run lists nothing below /mnt"):
        prepare(pruned)
        pruned.succeed("grep -q 'lib.mkOptionDefault \\[ \"/mnt\" \\]' /etc/nixos/locate.nix")
        rc, rows = check(pruned)
        row = rows["locate-database"]
        assert row["status"] == "pass", row
        assert "lists /mnt" in row["message"], row
        assert rows["suspicious-nails-reference"]["status"] == "pass", rows[
            "suspicious-nails-reference"
        ]
        failed = [name for name, check_row in rows.items() if check_row["status"] == "fail"]
        assert rc == 0 and not failed, (rc, failed, rows)
        status, listed = index(pruned)
        assert status == 1 and listed == "", (status, listed)

    with subtest("a timer started by hand or by systemd-run schedules a run"):
        def locate_row():
            _, rows = check(pruned)
            return rows["locate-database"]

        # Nothing starts it at boot.
        pruned.fail("systemctl is-active reindex.timer")
        pruned.succeed("systemctl start reindex.timer")
        row = locate_row()
        assert row["status"] == "fail", row
        assert "reindex.timer schedules updatedb" in row["message"], row
        pruned.succeed("systemctl stop reindex.timer")
        row = locate_row()
        assert row["status"] == "pass", row

        probe = "nails-locate-probe"
        pruned.succeed(
            f"systemd-run --unit={probe} --on-calendar=hourly "
            + "/run/current-system/sw/bin/updatedb --prunepaths /tmp --output /var/cache/probe.db"
        )
        print(pruned.succeed(f"cat /run/systemd/transient/{probe}.timer /run/systemd/transient/{probe}.service"))
        row = locate_row()
        assert row["status"] == "fail", row
        assert f"{probe}.timer schedules updatedb" in row["message"], row
        pruned.succeed(f"systemctl stop {probe}.timer")
        pruned.wait_until_fails(f"test -e /run/systemd/transient/{probe}.timer")
        row = locate_row()
        assert row["status"] == "pass", row
  '';
}
