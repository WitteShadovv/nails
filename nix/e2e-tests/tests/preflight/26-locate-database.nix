# Test 26: the locate-database check and the leak it guards against
#
# updatedb writes the name of every file it finds into the locate database on
# the decoy disk, so a run while the hidden volume is mounted lists the
# volume's files there. The check refuses while anything on the decoy may run
# updatedb, whatever the run prunes:
#
#   1. indexed, a NixOS decoy that runs services.locate, whose timer is
#      enabled, with /mnt in prunePaths: `check` refuses (exit 4) on the
#      locate-database row, naming update-locatedb's units and the fix
#      `services.locate.enable = false;`. A real run of
#      update-locatedb.service with the volume mounted shows what is at
#      stake: with NixOS's default prunePaths, which do not skip /mnt, it
#      lists the volume's files in /var/cache/locatedb on the decoy disk.
#   2. bare, with services.locate off and plocate installed: `check` warns
#      of a run by hand and passes the rest. A timer `systemd-run
#      --on-calendar` makes refuses, by its transient unit's file and by what
#      `systemctl show` gives of the unit the system manager has loaded. Once
#      it stops and systemd has collected it, the warning is back.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;

  decoy =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
    };
in
{
  name = "locate-database";
  meta.tags = [
    "preflight"
    "security"
  ];

  nodes = {
    indexed =
      { ... }:
      {
        imports = [ decoy ];
        services.locate.enable = true;
      };
    pruned =
      { lib, ... }:
      {
        imports = [ decoy ];
        services.locate.enable = true;
        services.locate.prunePaths = lib.mkOptionDefault [ "/mnt" ];
      };
    bare =
      { ... }:
      {
        imports = [ decoy ];
        environment.systemPackages = [ pkgs.plocate ];
      };
  };

  testScript = _: ''
    import json
    import shlex

    CONFIG = "/run/locate-check.toml"
    DATABASE = "/var/cache/locatedb"


    def prepare(node):
        node.wait_for_unit("multi-user.target")
        node.succeed("""${hiddenVolume.setupHiddenVolume}""")
        node.succeed(
            "mkdir -p /mnt/data/notes && echo kept > /mnt/data/notes/plan.txt && "
            + "printf 'hidden_volume_root = \"/mnt/data\"\\nminimum_space_mb = 100\\n' > "
            + CONFIG
        )


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

    with subtest("services.locate refuses, and a run lists the volume"):
        prepare(indexed)
        indexed.succeed("systemctl is-enabled update-locatedb.timer")
        rc, rows = check(indexed)
        row = rows["locate-database"]
        assert rc == 4, (rc, row)
        assert row["status"] == "fail", row
        for part in [
            "/etc/systemd/system/update-locatedb.timer names updatedb",
            "/etc/systemd/system/update-locatedb.service names updatedb",
        ]:
            assert part in row["message"], (part, row)
        for part in [
            "services.locate.enable = false;",
            "unmount /mnt/data",
            "does not lift this refusal",
        ]:
            assert part in row["remediation"], (part, row)
        status, listed = index(indexed)
        assert status == 0, (status, listed)
        for name in ["/mnt/data/notes/plan.txt", "/mnt/data/config/nixos"]:
            assert name in listed.splitlines(), (name, listed)

    with subtest("a prunePaths that skips the volume still refuses"):
        prepare(pruned)
        rc, rows = check(pruned)
        row = rows["locate-database"]
        assert rc == 4, (rc, row)
        assert row["status"] == "fail", row
        assert "update-locatedb.service names updatedb" in row["message"], row

    with subtest("plocate alone warns of a run by hand"):
        prepare(bare)
        rc, rows = check(bare)
        row = rows["locate-database"]
        assert row["status"] == "warn", row
        assert "/run/current-system/sw/bin/updatedb" in row["message"], row
        failed = [name for name, check_row in rows.items() if check_row["status"] == "fail"]
        assert rc != 4 and not failed, (rc, failed, rows)

    with subtest("a timer systemd-run makes refuses until systemd collects it"):
        probe = "nails-locate-probe"
        bare.succeed(
            f"systemd-run --unit={probe} --on-calendar=hourly "
            + "/run/current-system/sw/bin/updatedb --output /var/cache/probe.db"
        )
        bare.succeed(f"systemctl is-active {probe}.timer")
        _, rows = check(bare)
        row = rows["locate-database"]
        assert row["status"] == "fail", row
        for part in [
            f"/run/systemd/transient/{probe}.service names updatedb",
            f"the system manager has {probe}.service loaded",
        ]:
            assert part in row["message"], (part, row)
        # systemctl stop returns once the timer has stopped; systemd removes
        # the transient files when it collects the units, which takes no set
        # time. A `systemctl show` of the unit by name would load it again.
        bare.succeed(f"systemctl stop {probe}.timer")
        bare.wait_until_succeeds(
            f"! test -e /run/systemd/transient/{probe}.timer "
            + f"&& ! test -e /run/systemd/transient/{probe}.service",
            timeout=120,
        )
        _, rows = check(bare)
        row = rows["locate-database"]
        assert row["status"] == "warn", row
  '';
}
