# The unattended-upgrades scenario: what unattended-upgrades' shutdown helper
# does at a switch, and the refusals that keep it off the decoy disk.
#
# unattended-upgrades' shutdown helper waits for logind's shutdown signal,
# which a switch through logind sends as `systemctl soft-reboot` does. When
# the signal comes while a run of unattended-upgrade holds its lock, the
# helper sends the run SIGTERM and writes `Unattended-upgrade in progress
# during shutdown` to its log on the decoy disk, whatever
# `Unattended-Upgrade::InstallOnShutdown` says. With that setting on, it runs
# an install of the pending updates on the signal instead.
#
# The scenario, on each image with unattended-upgrades:
#
#   - checks the stock decoy: both rows pass, its apt configuration read as
#     apt reads it;
#   - starts a daily run the way apt-daily-upgrade.timer does
#     (`apt-daily-upgrade.service`) and holds it at its first step, the power
#     check, with a stand-in for powermgmt-base's `on_ac_power` that waits
#     until the test lets it go: the run holds its lock and runs no dpkg.
#     `check` and `activate` refuse while it runs, and the helper's log and
#     the run's gain no line. As the positive control, a plain `systemctl
#     soft-reboot` during the same run, the call a switch makes, makes the
#     helper write its line on the decoy disk. Once the run has ended, the
#     row passes again;
#   - turns the setting on in a file of `/etc/apt/apt.conf.d`: `check` and
#     `activate` refuse, naming the file and its line. With
#     `--allow-persistent-decoy` the activation goes through, and the decoy's
#     helper logs its shutdown-mode run on the decoy disk at the switch, the
#     positive control;
#   - stops the decoy's helper and leaves it enabled, the setting still on:
#     `check` only warns, the activation goes through, and the way back
#     (`deactivate`, through logind) has the session's own copy of the helper
#     log its shutdown-mode run into the upper on the hidden volume, while the
#     decoy's log gains no such line.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  distroVm = import ../lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ../lib/hidden-root.nix;

  # The canonical static musl binary, the exact artifact a user installs.
  inherit (self.packages.x86_64-linux) nails;

  # The binary is shared read-only over 9p onto the /run tmpfs, never on the
  # decoy disk. The tag and the path are neutral: both show in the mount
  # table.
  binShare = {
    tag = "tools";
    target = "/run/tools";
  };
in
# `name` and `entry` are one name and value of images.nix.
_name: entry:
distroVm.buildVmTest {
  inherit entry;

  sharedDirs.${binShare.tag} = {
    source = "${nails}/bin";
    inherit (binShare) target;
  };

  memorySize = entry.memory;

  testScript = ''
    import json
    import os
    import shlex
    import sys

    # The NixOS suite's in-VM helper package, for following a soft-reboot.
    sys.path.insert(0, "${../../e2e-tests/py}")
    from nails_e2e import session  # noqa: E402

    nails = "${binShare.target}/nails"
    # On the /run tmpfs: never on the decoy disk; carried across soft-reboots.
    config = "/run/nails-apt-shutdown.toml"
    nails_cmd = f"{nails} --config {shlex.quote(config)}"
    # The RAM copy of the binary the session keeps in /run.
    ram_nails_cmd = f"/run/overlay-runtime/control --config {shlex.quote(config)}"

    # unattended-upgrades' logs: its shutdown helper's, and the one its runs
    # write.
    helper_log = "/var/log/unattended-upgrades/unattended-upgrades-shutdown.log"
    run_log = "/var/log/unattended-upgrades/unattended-upgrades.log"
    IN_PROGRESS = "Unattended-upgrade in progress during shutdown"
    RUN_STOPS = "SIGTERM received, will stop"
    SHUTDOWN_MODE = "Running unattended-upgrades in shutdown mode"
    # The lock a run holds from its start to its end, as unattended-upgrade
    # names it (/var/run is a link to /run).
    uu_lock = "/var/run/unattended-upgrades.lock"
    # Where the session's copy of the helper logs: in the upper.
    upper_helper_log = "/mnt/data/root/upper" + helper_log

    # The stand-in for on_ac_power: on its own tmpfs, as /run is mounted
    # noexec, and first in the run's PATH through a runtime drop-in, so
    # nothing of it lands on the decoy disk.
    hook_dir = "/run/uu-hook"
    hold = "/run/uu-hold"
    held = "/run/uu-held"
    on_ac_power = "\n".join(
        (
            "#!/bin/sh",
            f"touch {held}",
            f"while [ -e {hold} ]; do sleep 0.2; done",
            "exit 0",
            "",
        )
    )
    hold_dropin_dir = "/run/systemd/system/apt-daily-upgrade.service.d"
    hold_dropin = "\n".join(
        (
            "[Service]",
            f"Environment=PATH={hook_dir}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "",
        )
    )

    # The setting turned on, in a file of its own.
    setting_file = "/etc/apt/apt.conf.d/99local-install-on-shutdown"
    setting_on = 'Unattended-Upgrade::InstallOnShutdown "true";\n'

    # What the package's debconf answer writes when unattended upgrades are
    # turned on (data/20auto-upgrades).
    auto_upgrades = "\n".join(
        (
            'APT::Periodic::Update-Package-Lists "1";',
            'APT::Periodic::Unattended-Upgrade "1";',
            "",
        )
    )


    def write_config():
        vm.succeed(
            "printf '%s\\n' 'hidden_volume_root = \"/mnt/data\"' "
            + "'minimum_space_mb = 100' > "
            + shlex.quote(config)
        )


    def prepare_boot():
        # Everything a fresh boot loses: the 9p share (nix-vm-test mounts it
        # only once, before this script) and the /run config. The apt timers
        # are stopped, so that no daily run starts but the scenario's own.
        vm.wait_for_unit("multi-user.target")
        vm.succeed(
            "mkdir -p ${binShare.target} && "
            + "{ mountpoint -q ${binShare.target} || "
            + "mount -t 9p -o defaults,trans=virtio,version=9p2000.L,cache=loose,msize=268435456 "
            + "${binShare.tag} ${binShare.target}; }"
        )
        vm.succeed(f"test -x {nails}")
        write_config()
        vm.succeed("systemctl stop apt-daily.timer apt-daily-upgrade.timer")


    def follow(trigger, label):
        timings = session.follow_soft_reboot(vm, trigger, label)
        print(f"{label}: {timings}")
        prepare_boot()


    def count(path, text):
        _, out = vm.execute(f"grep -c -F {shlex.quote(text)} {path} 2>/dev/null || true")
        return int(out.strip() or "0")


    def tail(path, lines=20):
        _, out = vm.execute(f"tail -n {lines} {path} 2>&1 || true")
        return out.rstrip()


    def row(name):
        # A row of `check`, read off the command's output, never written to
        # the decoy disk.
        _, out = vm.execute(f"{nails_cmd} check --overlay-only --json 2>/dev/null")
        found = next(r for r in json.loads(out)["data"]["checks"] if r["name"] == name)
        print(f"{name}: {json.dumps(found, indent=2)}")
        return found


    def assert_on_the_decoy():
        vm.fail("mountpoint -q /run/nextroot")
        vm.fail("test -e /run/overlay-runtime")
        session.assert_decoy_root(vm)


    def lock_holders():
        # The processes /proc/locks lists as holding a lock on the run's lock
        # file, found by the file's device and inode, as NAILS finds them.
        rc, out = vm.execute(f"stat -L -c '%d %i' {uu_lock}")
        if rc != 0:
            return []
        dev, ino = (int(field) for field in out.split())
        holders: list[int] = []
        for line in vm.succeed("cat /proc/locks").splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[1] not in ("POSIX", "OFDLCK"):
                continue
            for i, field in enumerate(fields):
                parts = field.split(":")
                if len(parts) != 3 or i == 0:
                    continue
                try:
                    major, minor, inode = int(parts[0], 16), int(parts[1], 16), int(parts[2])
                except ValueError:
                    continue
                if (major, minor, inode) == (os.major(dev), os.minor(dev), ino):
                    holders.append(int(fields[i - 1]))
        return holders


    def start_daily_run():
        # A daily run as apt-daily-upgrade.timer starts one, held at its
        # power check with its lock taken.
        vm.succeed(
            f"mkdir -p {hook_dir} && {{ mountpoint -q {hook_dir} || "
            + f"mount -t tmpfs -o size=1m,mode=0755 hook {hook_dir}; }}"
        )
        vm.succeed(
            f"printf %s {shlex.quote(on_ac_power)} > {hook_dir}/on_ac_power && "
            + f"chmod 0755 {hook_dir}/on_ac_power"
        )
        vm.succeed(
            f"mkdir -p {hold_dropin_dir} && printf %s {shlex.quote(hold_dropin)} "
            + f"> {hold_dropin_dir}/hold.conf && systemctl daemon-reload"
        )
        vm.succeed(f"touch {hold} && rm -f {held} /var/lib/apt/periodic/upgrade-stamp")
        vm.succeed("systemctl start --no-block apt-daily-upgrade.service")
        vm.wait_until_succeeds(f"test -e {held}", timeout=600)
        holders = lock_holders()
        state = vm.succeed("systemctl show -P ActiveState apt-daily-upgrade.service").strip()
        print(f"the run's lock is held by {holders}; apt-daily-upgrade.service is {state}")
        assert holders, "the held run holds no lock on its lock file"
        assert state == "activating", f"apt-daily-upgrade.service is {state}"
        # No dpkg runs: nothing blocks shutdown.
        inhibitors = vm.succeed("systemd-inhibit --list --no-pager --no-legend || true")
        assert not any(" block" in line for line in inhibitors.splitlines()), inhibitors


    def release_when_seen():
        # A switch kills the driver's shell and waits for logind, so a unit
        # lets the run go once the helper has logged that it found it: the
        # run then stops, and the helper with it.
        release = (
            f"until grep -q -F {shlex.quote(IN_PROGRESS)} {helper_log} 2>/dev/null; "
            + f"do sleep 0.2; done; rm -f {hold}"
        )
        vm.succeed(f"systemd-run --unit=uu-release --collect sh -c {shlex.quote(release)}")


    vm.wait_for_unit("multi-user.target")
    prepare_boot()

    with subtest("the stock decoy passes both rows"):
        print(vm.succeed("dpkg-query -W unattended-upgrades apt systemd"))
        vm.succeed("systemctl is-active unattended-upgrades.service")
        print(vm.succeed("ls -la /etc/apt/apt.conf.d"))
        interval = vm.succeed(
            "apt-config shell V APT::Periodic::Unattended-Upgrade; true"
        ).strip()
        if interval in ("", "V='0'"):
            vm.succeed(
                f"printf %s {shlex.quote(auto_upgrades)} > /etc/apt/apt.conf.d/20auto-upgrades"
            )
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        assert row("unattended-upgrade-run")["status"] == "pass"
        persistence = row("decoy-persistence")
        assert "unattended-upgrades" not in persistence["message"], persistence
        vm.succeed(f"{nails_cmd} check --overlay-only")

    with subtest("a daily unattended-upgrade run refuses check and activation"):
        lines_before = count(helper_log, IN_PROGRESS)
        stops_before = count(run_log, RUN_STOPS)
        start_daily_run()
        refusal = row("unattended-upgrade-run")
        assert refusal["status"] == "fail", refusal
        assert "apt-daily-upgrade.service is active" in refusal["message"], refusal
        assert "holds /run/unattended-upgrades.lock" in refusal["message"], refusal
        rc, out = vm.execute(f"{nails_cmd} activate -y 2>&1")
        print(out)
        assert rc != 0, out
        assert "a daily unattended-upgrade run is in progress" in out, out
        assert "Try again in a few minutes" in out, out
        assert_on_the_decoy()
        # The refused activation sent no shutdown signal: the helper and the
        # run logged nothing on the decoy disk.
        assert count(helper_log, IN_PROGRESS) == lines_before, tail(helper_log)
        assert count(run_log, RUN_STOPS) == stops_before, tail(run_log)

    with subtest("positive control: a soft-reboot during the run writes the helper's line"):
        # The call a switch makes, without NAILS, into the same root.
        release_when_seen()
        follow("systemctl --no-wall soft-reboot", "soft-reboot")
        assert_on_the_decoy()
        print(f"the helper's log on the decoy disk:\n{tail(helper_log)}")
        print(f"the runs' log on the decoy disk:\n{tail(run_log)}")
        assert count(helper_log, IN_PROGRESS) > lines_before, tail(helper_log)
        # The run ended with the old userspace: once its unit is no longer
        # active, the row passes again. The unit keeps the ID of its last
        # run, so its state is what tells.
        vm.wait_until_succeeds(
            "systemctl show -P ActiveState apt-daily-upgrade.service | grep -qx -e inactive -e failed",
            timeout=300,
        )
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        assert row("unattended-upgrade-run")["status"] == "pass"

    with subtest("InstallOnShutdown on refuses check and activation"):
        vm.succeed(f"printf %s {shlex.quote(setting_on)} > {setting_file}")
        refusal = row("decoy-persistence")
        assert refusal["status"] == "fail", refusal
        assert f"is on in {setting_file}:1" in refusal["message"], refusal
        mode_before = count(helper_log, SHUTDOWN_MODE)
        rc, out = vm.execute(f"{nails_cmd} activate -y 2>&1")
        print(out)
        assert rc != 0, out
        assert f"Unattended-Upgrade::InstallOnShutdown is on in {setting_file}:1" in out, out
        assert "--allow-persistent-decoy" in out, out
        assert_on_the_decoy()
        assert count(helper_log, SHUTDOWN_MODE) == mode_before, tail(helper_log)

    with subtest("positive control: with the override the helper runs its install at the switch"):
        follow(
            f"{nails_cmd} activate -y --allow-persistent-decoy > /mnt/data/activate.log 2>&1",
            "activate",
        )
        print(vm.succeed("cat /mnt/data/activate.log || true"))
        session.assert_hidden_root(vm)
        follow(f"{ram_nails_cmd} emergency --json > /dev/null", "emergency")
        assert_on_the_decoy()
        print(f"the helper's log on the decoy disk:\n{tail(helper_log)}")
        print(f"the runs' log on the decoy disk:\n{tail(run_log)}")
        assert count(helper_log, SHUTDOWN_MODE) > mode_before, tail(helper_log)

    with subtest("a helper stopped but enabled only warns, and logs its shutdown-mode run at the way back"):
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed("systemctl stop unattended-upgrades.service")
        vm.succeed("systemctl is-enabled unattended-upgrades.service")
        warning = row("decoy-persistence")
        assert warning["status"] == "warn", warning
        assert "stopped on the decoy but enabled" in warning["message"], warning
        decoy_mode = count(helper_log, SHUTDOWN_MODE)
        follow(f"{nails_cmd} activate -y > /mnt/data/activate-2.log 2>&1", "activate-2")
        session.assert_hidden_root(vm)
        vm.succeed("systemctl is-active unattended-upgrades.service")
        follow(f"{nails_cmd} deactivate -y", "deactivate")
        assert_on_the_decoy()
        assert count(helper_log, SHUTDOWN_MODE) == decoy_mode, tail(helper_log)
        # As the operator would: unlock and mount the hidden volume again.
        # The upper's copy of the log starts with what the decoy's held when
        # the session first wrote to it, so the session's own line is one
        # more than the decoy's.
        vm.succeed("""${hiddenRoot.reopenHiddenRoot}""")
        print(f"the session's helper log in the upper:\n{tail(upper_helper_log)}")
        assert count(upper_helper_log, SHUTDOWN_MODE) > decoy_mode, tail(upper_helper_log)
        vm.succeed("""${hiddenRoot.closeHiddenRoot}""")
        vm.succeed(f"rm -f {setting_file}")
  '';
}
