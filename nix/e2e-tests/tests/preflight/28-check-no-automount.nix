# Test 28: check makes no lookup that would mount an automount point
#
# A lookup that passes an automount point that nothing is mounted on yet
# mounts it: systemd's for an x-systemd.automount line as the lookup goes
# into it, an automounter's indirect map as the lookup looks up a name in
# its directory. `nails check` leaves no mount behind, so the checks ask the
# mount table before each lookup on the decoy and make none that would mount
# one. One NixOS decoy with the hidden volume mounted has, nothing mounted
# on any of them:
#
#   - x-systemd.automount tmpfs at /usr/local, where journald's drop-ins,
#     systemd's units and an updatedb can be, and at /home/carol, carol's
#     home;
#   - an autofs indirect map at /auto, whose name dave is dave's home;
#   - an x-systemd.automount tmpfs at /srv/archive that no check reads, the
#     null control, whose fstab line fstab-policy resolves without a lookup.
#
# The store is no overlay here, so the overlay module is not loaded: trying
# the overlay would load it, and the kernel's modprobe and udevd would then
# read their settings below /usr/local/lib.
#
# `nails check --json` as root, again with --allow-persistent-decoy, and as
# carol (SUDO_USER) leaves the mount table outside /run as it found it and
# the mount units inactive, no automount request reaches systemd or the
# automounter, and the overlay module stays unloaded. decoy-persistence,
# fstab-policy and upper-fs-capability refuse (the override turns the first
# into a warning), sleep-policy and locate-database warn, and as carol
# inherited-autostart and incremental-history-flush warn, each naming the
# automount point with the line that says to mount it, and inherited.not_read
# lists carol's autostart directory; no row names /srv/archive. A listing of
# /auto, the indirect map's directory, mounts nothing either. As the positive
# control, ls mounts each point, and the next check names none of them and
# reads what they hold: an updatedb in /usr/local/bin and carol's
# sync.desktop, and its trial overlay loads the module.
#
# The decoy's own daemons read their settings below /usr/local/lib, and so
# can mount /usr/local themselves: systemd-udevd did as it handled device
# events, in one run while check ran, and the journal named it. What they
# mounted is unmounted before each run, and udevd's queue of events is held
# from the first run on, so that an event of the setup handled late mounts
# nothing while check runs. A module check loaded would still be listed in
# /proc/filesystems.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;

  # A tmpfs that systemd mounts on the first lookup that goes into it. With
  # no idle timeout it never expires while the test runs.
  onDemand = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [
      "noauto"
      "x-systemd.automount"
      "mode=0755"
    ];
  };

  # The indirect map at /auto: its name dave is a bind of /srv/dave.
  homes = pkgs.writeText "auto.homes" ''
    dave -fstype=bind :/srv/dave
  '';
in
{
  name = "check-no-automount";
  meta.tags = [
    "preflight"
    "security"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      # No overlay over the store, so nothing loads the overlay module at
      # boot: check's trial overlay would be what loads it.
      virtualisation.writableStore = false;
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      virtualisation.fileSystems = {
        "/usr/local" = onDemand;
        "/home/carol" = onDemand;
        "/srv/archive" = onDemand;
      };
      # Homes behind automount points: nothing may make them at boot, which
      # would mount the points.
      users.users = {
        carol = {
          isNormalUser = true;
          home = "/home/carol";
          createHome = false;
        };
        dave = {
          isNormalUser = true;
          home = "/auto/dave";
          createHome = false;
        };
      };
      services.autofs = {
        enable = true;
        # Nothing it mounts expires.
        timeout = 0;
        # It logs each lookup it serves.
        debug = true;
        autoMaster = ''
          /auto file:${homes} --timeout=0
        '';
      };
      systemd.tmpfiles.rules = [ "d /srv/dave 0755 root root -" ];
    };

  testScript = _: ''
    import json
    import shlex

    from nails_e2e import mounts

    CONFIG = "/run/automount-check.toml"
    # The direct automount points systemd makes for the fstab lines, with
    # the units of the mount and of the automount.
    DIRECT = {
        "/usr/local": ("usr-local.mount", "usr-local.automount"),
        "/home/carol": ("home-carol.mount", "home-carol.automount"),
        "/srv/archive": ("srv-archive.mount", "srv-archive.automount"),
    }
    MAP = "/auto"
    DAVE = "/auto/dave"
    ARCHIVE = "/srv/archive"
    # The places the checks would read, behind points nothing is mounted on.
    READ = ("/usr/local", "/home/carol", DAVE)
    AUTOSTART = "/home/carol/.config/autostart"


    def table():
        return machine.succeed("cat /proc/self/mountinfo")


    def stack(text, point):
        # The mounts at point, bottom first.
        return [mount for mount in mounts.parse(text) if mount.point == point]


    def outside_run(text):
        # Every mount but those below /run, where a unit the checks ask
        # about may get a mount of its own.
        return mounts.shape(text, lambda point: point.startswith("/run/"))


    def cursor():
        # Where the journal ends now.
        last = machine.succeed("journalctl -q -n 1 --show-cursor -o cat").strip()
        return last.splitlines()[-1].removeprefix("-- cursor: ")


    def requests(since):
        # The automount requests systemd and the automounter logged after
        # the cursor since, each with the process that made it.
        units = " ".join(
            f"-u {automount}" for _, automount in DIRECT.values()
        )
        logged = machine.succeed(
            f"journalctl -q --no-pager -o cat --after-cursor={shlex.quote(since)} "
            + f"{units} -u autofs.service"
        )
        return [
            line
            for line in logged.splitlines()
            if "automount request" in line or "dave" in line
        ]


    def inactive(points):
        # The mount units of points, each with its state, where it is not
        # inactive.
        states = {}
        for point in points:
            unit = DIRECT[point][0]
            states[unit] = machine.succeed(f"systemctl show -P ActiveState {unit}").strip()
        return {unit: state for unit, state in states.items() if state != "inactive"}


    def unmount(points):
        # What the decoy's daemons mounted on points is unmounted again, the
        # automounts kept, with the journal lines that say who asked.
        for point in points:
            if point in DIRECT and inactive([point]):
                unit, automount = DIRECT[point]
                print(machine.succeed(f"journalctl -q -o cat -u {automount}"))
                machine.succeed(f"systemctl stop {unit}")


    def overlay_loaded():
        # Whether the kernel lists the overlay filesystem: once its module
        # is loaded.
        filesystems = machine.succeed("cat /proc/filesystems").splitlines()
        return any(line.split()[-1:] == ["overlay"] for line in filesystems)


    def left_nothing(label, before, since, points):
        # Since the table before and the cursor since, the mount table is
        # the same outside /run, the mount units of the points nothing was
        # mounted on stay inactive, and nobody asked for an automount.
        changed = mounts.differences(outside_run(before), outside_run(table()))
        asked = requests(since)
        active = inactive([point for point in points if point in DIRECT])
        assert not changed and not asked and not active, (label, changed, asked, active)


    def check(label, unmounted, env="", flags=""):
        # One nails check --json, with nothing mounted on the points
        # unmounted: its exit code, its rows by name and its data, and the
        # mount table and the journal's cursor from before it.
        stem = f"/run/automount-check-{label}"
        unmount(unmounted)
        before, since = table(), cursor()
        machine.succeed(
            "bash -c "
            + shlex.quote(
                f"set +e; {env} nails --config {CONFIG} --json check --overlay-only {flags} "
                + f"> {stem}.out 2> {stem}.err; echo $? > {stem}.rc"
            )
        )
        rc = int(machine.succeed(f"cat {stem}.rc").strip())
        report = json.loads(machine.succeed(f"cat {stem}.out").strip().splitlines()[-1])
        data = report["data"]
        return rc, {row["name"]: row for row in data["checks"]}, data, before, since


    def text(row):
        return row["message"] + "\n" + (row.get("remediation") or "")


    def fixes(row, point):
        # Whether the row says to mount point and run check again.
        return any(
            line.startswith("Mount ")
            and point in line.split(" (for example `ls ")[0]
            and line.endswith(" check` again.")
            for line in text(row).splitlines()
        )


    def names(rows, name, points, status):
        # The row of check name, which ends in status and names each of
        # points as an automount point, with the fix.
        row = rows[name]
        print(json.dumps(row, indent=2))
        assert row["status"] == status, (name, status, row)
        for point in points:
            assert f"the automount point {point}" in text(row), (name, point, row)
            assert fixes(row, point), (name, point, row)
        return row


    def no_row_names(rows, places):
        for name, row in rows.items():
            for place in places:
                assert place not in text(row), (name, place, row)


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("autofs.service")
    # The automounter sets its map up after its start returns.
    machine.wait_until_succeeds(f"findmnt -n -t autofs {MAP}")
    for _, automount in DIRECT.values():
        machine.wait_for_unit(automount)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(
        "printf 'hidden_volume_root = \"/mnt/data\"\\nminimum_space_mb = 100\\n' > " + CONFIG
    )

    with subtest("the points are automount points nothing is mounted on"):
        # Once the device events of the boot and of the hidden volume's
        # setup are handled, udevd's queue is held, and what the daemons
        # mounted before is unmounted.
        machine.succeed("udevadm settle")
        machine.succeed("udevadm control --stop-exec-queue")
        unmount(list(DIRECT))
        baseline = table()
        for point in DIRECT:
            found = stack(baseline, point)
            assert [mount.fstype for mount in found] == ["autofs"], (point, found)
            assert "direct" in found[0].super_options.split(","), found
        found = stack(baseline, MAP)
        assert [mount.fstype for mount in found] == ["autofs"], (MAP, found)
        assert "indirect" in found[0].super_options.split(","), found
        assert not stack(baseline, DAVE), stack(baseline, DAVE)
        assert not inactive(list(DIRECT)), inactive(list(DIRECT))
        assert not overlay_loaded(), machine.succeed("cat /proc/filesystems")

    with subtest("check as root names each automount point and mounts none"):
        rc, rows, data, before, since = check("root", (*READ, ARCHIVE))
        left_nothing("root", before, since, (*READ, ARCHIVE))
        assert not overlay_loaded(), "the trial loaded the overlay module"
        assert rc == 4, rc
        persistence = names(rows, "decoy-persistence", ["/usr/local"], "fail")
        assert persistence.get("allowable") == "persistent_decoy", persistence
        names(rows, "fstab-policy", ["/usr/local"], "fail")
        names(rows, "upper-fs-capability", ["/usr/local"], "fail")
        names(rows, "sleep-policy", ["/usr/local"], "warn")
        names(rows, "locate-database", READ, "warn")
        no_row_names(rows, [ARCHIVE])

    with subtest("--allow-persistent-decoy turns the refusal into a warning"):
        rc, rows, data, before, since = check(
            "allowed", (*READ, ARCHIVE), flags="--allow-persistent-decoy"
        )
        left_nothing("allowed", before, since, (*READ, ARCHIVE))
        assert not overlay_loaded(), "the trial loaded the overlay module"
        row = names(rows, "decoy-persistence", ["/usr/local"], "warn")
        assert "allowed via --allow-persistent-decoy" in row["message"], row
        names(rows, "fstab-policy", ["/usr/local"], "fail")

    with subtest("check as carol looks up nothing in her home"):
        rc, rows, data, before, since = check("carol", (*READ, ARCHIVE), env="SUDO_USER=carol")
        left_nothing("carol", before, since, (*READ, ARCHIVE))
        assert not overlay_loaded(), "the trial loaded the overlay module"
        assert rc == 4, rc
        names(rows, "decoy-persistence", ["/usr/local"], "fail")
        names(rows, "fstab-policy", ["/usr/local"], "fail")
        names(rows, "inherited-autostart", ["/home/carol"], "warn")
        names(rows, "incremental-history-flush", ["/home/carol"], "warn")
        no_row_names(rows, [ARCHIVE])
        inherited = data["inherited"]
        print(json.dumps(inherited, indent=2))
        assert inherited["inspected"], inherited
        autostart = [place for place in inherited["not_read"] if place["path"] == AUTOSTART]
        assert autostart == [
            {
                "path": AUTOSTART,
                "reason": f"NAILS does not look up {AUTOSTART}, since the lookup would mount the "
                + "automount point /home/carol",
                "automount_point": "/home/carol",
            }
        ], inherited
        assert all(ARCHIVE not in json.dumps(place) for place in inherited["not_read"]), inherited

    with subtest("a listing of the indirect map's directory mounts nothing"):
        unmount((*READ, ARCHIVE))
        before, since = table(), cursor()
        print(machine.succeed(f"ls -a {MAP}"))
        left_nothing("ls", before, since, (*READ, ARCHIVE))

    with subtest("once ls mounts the points, check reads what they hold"):
        machine.succeed(f"ls {' '.join(READ)}")
        mounted = table()
        for point in ("/usr/local", "/home/carol"):
            found = [mount.fstype for mount in stack(mounted, point)]
            assert found == ["autofs", "tmpfs"], (point, found)
        assert len(stack(mounted, DAVE)) == 1, stack(mounted, DAVE)
        machine.succeed(
            "mkdir -p /usr/local/bin " + AUTOSTART
            + " && printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/updatedb"
            + " && chmod 0755 /usr/local/bin/updatedb"
            + " && printf '[Desktop Entry]\\nType=Application\\nName=Sync\\nExec=true\\n' > "
            + AUTOSTART
            + "/sync.desktop"
        )
        rc, rows, data, before, since = check("mounted", [ARCHIVE], env="SUDO_USER=carol")
        left_nothing("mounted", before, since, [ARCHIVE])
        print(json.dumps(rows, indent=2))
        no_row_names(rows, [f"automount point {point}" for point in (*READ, ARCHIVE)])
        for name in ("decoy-persistence", "fstab-policy", "upper-fs-capability"):
            assert rows[name]["status"] != "fail", rows[name]
        assert overlay_loaded(), "the trial did not load the overlay module"
        locate = rows["locate-database"]
        assert "updatedb can be started by hand (/usr/local/bin/updatedb)" in locate["message"], locate
        inherited = data["inherited"]
        print(json.dumps(inherited, indent=2))
        assert inherited["not_read"] == [], inherited
        sync = [entry["source"] for entry in inherited["entries"] if entry["name"] == "sync"]
        assert sync == ["user-autostart"], inherited

    machine.succeed("udevadm control --start-exec-queue")
  '';
}
