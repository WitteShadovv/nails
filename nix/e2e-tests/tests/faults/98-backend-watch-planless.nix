# Fault test: a session watcher that cannot read the session plan powers the
# machine off when the backend fails past the debounce, where its settings ask
# for the automatic emergency.
#
# A return to the decoy needs the session plan in /run/overlay-runtime, and
# without it does nothing at all. This test makes the plan unreadable in a
# hidden session (it no longer parses) and starts the watcher again, so it
# takes the hidden root from its copy of the settings. One neutral desktop
# alert then says that a failure powers the machine off. The backing device is
# yanked: the backend alert comes, and once the failure outlasts the debounce
# the machine powers off, where a watcher that took no action would leave the
# session running on a dead volume. A cold boot comes up on the plain decoy.
#
# The alerts go to testuser, logged in on the console, and the notification
# server on testuser's session bus (lib/notification-server.nix) records them
# in testuser's runtime directory under /run, as in faults-backend-watch-alert.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  backendFault = import ./../../lib/backend-fault.nix;
in
{
  name = "faults-backend-watch-planless";
  meta.tags = [
    "faults"
    "security"
  ];
  globalTimeout = 1200;

  nodes.machine = _: {
    imports = [
      ./../../lib/vm-config.nix
      ./../../lib/notification-server.nix
    ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    from nails_e2e import desktop, session

    ${testHelpers.canonicalActivateFn}
    ${backendFault.emergencyOutcomeFn}
    ${backendFault.assertFaultExitFn}

    CONFIG = "/mnt/data/config/nails.toml"
    runtime_dir = "/run/overlay-runtime"
    watch_unit = "overlay-runtime-monitor.service"
    POWER_OFF_MODE = "Storage monitor in power-off mode"
    # Words that would tell a bystander reading the screen what this is.
    REVEALING = ("hidden", "nails", "decoy", "session", "overlay", "emergency")


    def assert_neutral(alert):
        text = (alert["summary"] + " " + alert["body"]).lower()
        for word in REVEALING:
            assert word not in text, (word, alert)


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    # Poll fast; the debounce leaves time to read the backend alert before
    # the watcher powers the machine off.
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "\n"
        "[backend_watch]\n"
        "enabled = true\n"
        "auto_emergency = true\n"
        "poll_interval_secs = 2\n"
        "debounce_secs = 30\n"
        "EOF"
    )
    run_before = session.run_entries(machine)

    with subtest("activate a hidden session"):
        canonical_activate(CONFIG, "--overlay-only", "activate")
        machine.wait_for_unit(watch_unit)

    with subtest("the operator logs in on the hidden session's console"):
        uid = desktop.login_on_console(machine)

    with subtest("a watcher that cannot read the session plan says it powers off"):
        # The plan no longer parses, so a return to the decoy has nothing to
        # go by. Started again, the watcher takes the hidden root from its
        # copy of the settings.
        machine.succeed(f"printf 'not a plan' > {runtime_dir}/plan.json")
        machine.succeed(f"systemctl restart {watch_unit}")
        machine.wait_for_unit(watch_unit)
        alert = desktop.wait_for(machine, uid, POWER_OFF_MODE, timeout=60)[0]
        assert alert["uid"] == uid, alert
        assert alert["hints"]["urgency"] == 2, alert
        assert alert["app_name"] == "System", alert
        assert "turns the computer off" in alert["body"], alert
        assert_neutral(alert)

    with subtest("the backing device is yanked out from under the hidden root"):
        wall = session.wall_clock(machine)
        console_mark = len(machine.full_console_log)
        machine.succeed("dmsetup wipe_table --force data")

    with subtest("the watcher alerts the operator about the failed backend"):
        desktop.wait_for(machine, uid, "Storage unavailable", timeout=30)
        titles = [record["summary"] for record in desktop.received(machine, uid)]
        # The power-off mode was told once; no alert says the watcher takes
        # no action.
        assert titles.count(POWER_OFF_MODE) == 1, titles
        assert "Storage monitor in alert-only mode" not in titles, titles

    with subtest("past the debounce the watcher powers the machine off"):
        # Nothing is run here: the watcher powers off on its own. Follow the
        # console from before the yank, so a fast power-off is not missed.
        outcome = emergency_outcome(None, "watcher-power-off", console_index=console_mark)
        machine.log(f"the watcher's emergency ended: {outcome}")
        assert outcome == "off", outcome
        assert_fault_exit(outcome, run_before, wall)
  '';
}
