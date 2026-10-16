# Desktop alerts reach the operator's desktop: a notification server on the
# operator's own session bus receives them.
#
# NAILS runs as root, from sudo or from the session watcher's system unit,
# while a desktop session bus admits only the account that owns it. So each
# alert runs as the operator: their uid and primary gid, no supplementary
# groups. Nothing here stubs that path. A user service of testuser owns
# org.freedesktop.Notifications on testuser's bus (lib/notification-server.nix)
# and records each call with the uid and the program that made it.
#
# The same scenario runs on two decoys, one after the other:
#
#   - notify_send has libnotify installed, so the alerts go out through
#     notify-send;
#   - bus_only has no notify-send, as on Debian's GNOME and KDE desktops and a
#     NixOS desktop without libnotify, so they go out through busctl.
#
# Each call comes from a process with testuser's uid and primary gid in every
# slot, no supplementary groups, no capabilities and no_new_privs set, leading
# a session of its own without a controlling terminal.
#
# In the hidden session testuser logs in on the console, which makes them the
# owner of the active session on seat0. Then:
#
#   1. `sudo nails rehearse plant`, run by testuser, shows its notification
#      canary: the server receives it from testuser's uid, through the
#      expected program, and plant records the channel as planted;
#   2. a disk mounted read-write makes the session watcher, a root system
#      unit, alert the owner of seat0's active session: the server receives
#      the critical "Disk mounted with write access" from testuser's uid.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;

  decoy =
    { withNotifySend }:
    { lib, pkgs, ... }:
    {
      imports = [
        ./../../lib/vm-config.nix
        ./../../lib/notification-server.nix
      ];
      # A disk the hidden session mounts read-write, for the watcher's alert.
      virtualisation.emptyDiskImages = [
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "extra";
        }
      ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
      ]
      ++ lib.optional withNotifySend pkgs.libnotify;
    };
in
{
  name = "session-alert-delivery";
  meta.tags = [
    "session"
    "notification"
    "security"
  ];
  # Two decoys one after the other, each one session (two soft-reboots).
  globalTimeout = 1800;

  nodes = {
    notify_send = decoy { withNotifySend = true; };
    bus_only = decoy { withNotifySend = false; };
  };

  testScript = _: ''
    import json
    import shlex

    from nails_e2e import desktop

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    EXTRA = "/dev/disk/by-id/virtio-extra"
    WATCH_UNIT = "overlay-runtime-monitor.service"
    # The node the shared helpers drive; scenario() switches it.
    machine = notify_send


    def write_config():
        machine.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "\n"
            "[backend_watch]\n"
            "poll_interval_secs = 2\n"
            "EOF"
        )


    def assert_from_the_operator(record, uid, program):
        # Sent by the operator's own process, through the expected program,
        # under the neutral application name and with no product name on
        # screen.
        assert record["uid"] == uid, record
        assert program in record.get("comm", ""), record
        assert record["app_name"] == "System", record
        text = (record["summary"] + " " + record["body"]).lower()
        assert "nails" not in text, record
        # Nothing of root's is left: the operator's primary group in every
        # slot, no supplementary group, no capability, no way to gain
        # privileges again, and a session of its own with no terminal.
        gid = machine.succeed("id -g testuser").strip()
        assert record.get("gids") == [gid] * 4, record
        assert record.get("groups") == [], record
        assert record.get("cap_eff") == 0, record
        assert record.get("no_new_privs") == 1, record
        assert record.get("sid") == record.get("pid"), record
        assert record.get("tty_nr") == 0, record


    def scenario(node, program):
        global machine
        machine = node
        machine.start()
        machine.wait_for_unit("multi-user.target")
        if program == "notify-send":
            machine.succeed("test -x /run/current-system/sw/bin/notify-send")
        else:
            machine.fail("command -v notify-send")
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"mkfs.ext4 -q -L extra {EXTRA}")
        write_config()

        with subtest(f"{program}: enter a hidden session and log in on its console"):
            canonical_activate(CONFIG, "--overlay-only", f"activate-{node.name}")
            machine.wait_for_unit(WATCH_UNIT)
            uid = desktop.login_on_console(machine)

        with subtest(f"{program}: the rehearsal's notification reaches the operator's bus"):
            nails = machine.succeed("readlink -f /run/current-system/sw/bin/nails").strip()
            out = machine.succeed(
                "runuser -u testuser -- /run/wrappers/bin/sudo -n "
                + f"{nails} --config {shlex.quote(CONFIG)} --json rehearse plant"
                + " 2>/run/plant.err"
            )
            channels = json.loads(out)["data"]["channels"]
            notification = [c for c in channels if c["kind"] == "notification"]
            assert len(notification) == 1, channels
            assert "skipped" not in notification[0], notification
            assert notification[0]["location"] == "the operator's notification daemon", notification
            [reminder] = desktop.wait_for(machine, uid, "Reminder")
            assert_from_the_operator(reminder, uid, program)
            assert reminder["body"].startswith("rehearse-"), reminder
            assert reminder["hints"]["urgency"] == 0, reminder

        with subtest(f"{program}: the watcher's alert reaches the owner of seat0's session"):
            machine.succeed(f"mkdir -p /mnt/extra && mount {EXTRA} /mnt/extra")
            alerts = desktop.wait_for(machine, uid, "Disk mounted with write access")
            assert len(alerts) == 1, alerts
            alert = alerts[0]
            assert_from_the_operator(alert, uid, program)
            assert "/mnt/extra" in alert["body"], alert
            assert alert["hints"]["urgency"] == 2, alert
            assert alert["expire_timeout"] == -1, alert
            machine.succeed("umount /mnt/extra")

        with subtest(f"{program}: the session ends as usual"):
            canonical_deactivate(CONFIG, f"deactivate-{node.name}")

        machine.shutdown()


    scenario(notify_send, "notify-send")
    scenario(bus_only, "busctl")
  '';
}
