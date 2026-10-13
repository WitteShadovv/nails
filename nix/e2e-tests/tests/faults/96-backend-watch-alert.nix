# Fault test (g): the hidden session's backend watcher alerts when the backend
# fails and, with auto_emergency, takes the machine out of the hidden session on
# its own.
#
# With `[backend_watch] enabled = true` the entry transition installs
# overlay-runtime-monitor.service in the hidden root's /run: a runtime unit of
# the hidden session that runs the RAM copy (/run/overlay-runtime/control
# watch), so it keeps working once the hidden volume is gone. It polls the
# hidden root and, the moment a probe fails, raises a neutral desktop alert.
# With `auto_emergency = true` a failure that outlasts the debounce runs the
# emergency itself. This test drives that whole path: activate, check the RAM
# copy and the watcher unit, yank the backing device, check the alert, then
# wait (bounded) for the watcher's emergency to land the machine on the plain
# decoy, or powered off, with nothing of the watcher left behind.
#
# notify-send is shadowed by a logging stub on the system PATH so the alert is
# observable headlessly; the stub stands in for the operator's real session
# bus. It logs under /run, because every root-filesystem path is backed by the
# failed upper in the hidden session.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  backendFault = import ./../../lib/backend-fault.nix;
in
{
  name = "faults-backend-watch-alert";
  meta.tags = [
    "faults"
    "security"
  ];
  globalTimeout = 1200;

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        # A notify-send that records its arguments instead of talking to a bus,
        # on the system PATH so the watcher (a system unit) resolves it the way
        # it resolves the real one.
        (pkgs.writeShellScriptBin "notify-send" ''
          log=/run/notify-stub/notify-send.log
          mkdir -p "$(dirname "$log")"
          {
            printf '__CALL__\n'
            for arg in "$@"; do
              printf '%s\n' "$arg"
            done
          } >> "$log"
          exit 0
        '')
      ];
    };

  testScript = _: ''
    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}
    ${backendFault.emergencyOutcomeFn}
    ${backendFault.assertFaultExitFn}

    CONFIG = "/mnt/data/config/nails.toml"
    # The neutral names the runtime copy and the watcher use: nothing here may
    # name the product on screen or in systemctl.
    runtime_dir = "/run/overlay-runtime"
    watch_unit = "overlay-runtime-monitor.service"
    stub_log = "/run/notify-stub/notify-send.log"


    def read_stub_calls(path):
        text = machine.succeed(f"cat {path}")
        return [
            [line for line in call.splitlines() if line]
            for call in text.split("__CALL__\n")
            if call.strip()
        ]


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    # Poll fast; the debounce leaves time to read the alert before the
    # watcher's own emergency ends the session.
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

    with subtest("the entry left a private RAM-backed copy under /run"):
        assert machine.succeed(f"stat -c %a {runtime_dir}").strip() == "700", "runtime copy must be 0700"
        machine.succeed(f"test -x {runtime_dir}/control")
        machine.succeed(f"test -f {runtime_dir}/plan.json")
        assert machine.succeed(f"stat -c %a {runtime_dir}/plan.json").strip() == "600", "the plan must be 0600"
        # No mirrored name may reveal the product.
        machine.fail(f"ls -R {runtime_dir} | grep -i nails")

    with subtest("the watcher runs as a neutral runtime unit of the hidden session"):
        machine.wait_for_unit(watch_unit)
        unit_path = machine.succeed(f"systemctl show -p FragmentPath --value {watch_unit}").strip()
        assert unit_path.startswith("/run/systemd/"), unit_path
        exec_start = machine.succeed(f"systemctl show -p ExecStart --value {watch_unit}")
        assert f"{runtime_dir}/control" in exec_start, exec_start
        assert "nails" not in exec_start.lower(), exec_start

    with subtest("the backing device is yanked out from under the hidden root"):
        # Swap the dm table for an error target in place so the hidden
        # filesystem returns EIO; the node stays because the hidden mounts hold
        # it open.
        wall = session.wall_clock(machine)
        console_mark = len(machine.full_console_log)
        machine.succeed("dmsetup wipe_table --force data")

    with subtest("the watcher alerts the operator about the failed backend"):
        machine.wait_until_succeeds(f"test -s {stub_log}", timeout=30)
        calls = read_stub_calls(stub_log)
        assert calls, "watcher raised no desktop alert"
        alert = calls[0]
        # The alert is critical and worded to reveal nothing about a hidden
        # environment to anyone watching the screen.
        assert "--urgency" in alert and "critical" in alert, alert
        assert not any("nails" in token.lower() for token in alert), alert
        assert any("Storage unavailable" in token for token in alert), alert

    with subtest("auto_emergency takes the machine out of the hidden session on its own"):
        # Nothing is run here: the watcher's emergency fires after the debounce.
        # Follow the console from before the yank, so a fast switch is not
        # missed.
        outcome = emergency_outcome(None, "watcher-emergency", console_index=console_mark)
        machine.log(f"the watcher's emergency ended: {outcome}")
        assert_fault_exit(outcome, run_before, wall)
        if outcome == "decoy":
            machine.fail(f"systemctl is-active {watch_unit}")
  '';
}
