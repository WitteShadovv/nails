# The unattended-upgrades scenario: an activation during a daily
# unattended-upgrade run.
#
# unattended-upgrades' shutdown helper waits for logind's shutdown signal,
# which a switch sends as `systemctl soft-reboot` does. When the signal comes
# while a run of unattended-upgrade holds its lock, the helper sends the run
# SIGTERM and writes `Unattended-upgrade in progress during shutdown` to its
# log on the decoy disk, whatever `Unattended-Upgrade::InstallOnShutdown`
# says. APT holds its shutdown block only while dpkg runs, so between two dpkg
# runs, and before the first, nothing blocks the switch.
#
# The scenario starts a daily run the way apt-daily-upgrade.timer does
# (`apt-daily-upgrade.service`) and holds it at its first step, the power
# check, with a stand-in for powermgmt-base's `on_ac_power` that waits until
# the test lets it go: the run then holds its lock and runs no dpkg. It
# activates during the run, and once the switch has gone through, it finds
# the helper's line in its log on the decoy disk.
#
# It also records, without asserting them, three facts of the image: whether
# python3-gi is installed, what the helper writes when it starts without it,
# and what it writes at an activation while an apt configuration file has a
# syntax error.
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

    # unattended-upgrades' logs on the decoy disk: its shutdown helper's, and
    # the one its runs write.
    helper_log = "/var/log/unattended-upgrades/unattended-upgrades-shutdown.log"
    run_log = "/var/log/unattended-upgrades/unattended-upgrades.log"
    IN_PROGRESS = "Unattended-upgrade in progress during shutdown"
    # The lock a run holds from its start to its end, as unattended-upgrade
    # names it (/var/run is a link to /run).
    uu_lock = "/var/run/unattended-upgrades.lock"

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


    def lines(path, text):
        _, out = vm.execute(f"grep -F {shlex.quote(text)} {path} 2>/dev/null || true")
        return [line for line in out.splitlines() if line]


    def tail(path, count=30):
        _, out = vm.execute(f"tail -n {count} {path} 2>&1 || true")
        return out.rstrip()


    def lock_holders():
        # The processes /proc/locks lists as holding a lock on the run's lock
        # file, found by the file's device and inode. Nothing is opened or
        # taken: a stat, and a read of /proc/locks.
        rc, out = vm.execute(f"stat -L -c '%d %i' {uu_lock}")
        if rc != 0:
            return []
        dev, ino = (int(field) for field in out.split())
        holders = []
        for line in vm.succeed("cat /proc/locks").splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[1] == "->":
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
        print(f"the run's lock is held by {holders}")
        print(vm.succeed("cat /proc/locks; systemd-inhibit --list --no-pager || true"))
        state = vm.succeed("systemctl show -P ActiveState apt-daily-upgrade.service").strip()
        print(f"apt-daily-upgrade.service is {state}")
        assert holders, "the held run holds no lock on its lock file"
        assert state == "activating", f"apt-daily-upgrade.service is {state}"
        # No dpkg runs: nothing blocks shutdown.
        inhibitors = vm.succeed("systemd-inhibit --list --no-pager --no-legend || true")
        assert not any(" block" in line for line in inhibitors.splitlines()), inhibitors


    def release_when_seen():
        # The activation kills the driver's shell and waits for logind, so a
        # unit lets the run go once the helper has logged that it found it:
        # the run then stops, and the helper with it.
        release = (
            f"until grep -q -F {shlex.quote(IN_PROGRESS)} {helper_log} 2>/dev/null; "
            + f"do sleep 0.2; done; rm -f {hold}"
        )
        vm.succeed(f"systemd-run --unit=uu-release --collect sh -c {shlex.quote(release)}")


    vm.wait_for_unit("multi-user.target")
    prepare_boot()

    with subtest("the decoy runs unattended-upgrades' shutdown helper"):
        print(vm.succeed("dpkg-query -W unattended-upgrades apt python3-apt systemd"))
        vm.succeed("systemctl is-active unattended-upgrades.service")
        print(vm.succeed("systemctl cat unattended-upgrades.service"))
        print(vm.succeed("ls -la /etc/apt/apt.conf.d"))
        interval = vm.succeed(
            "apt-config shell V APT::Periodic::Unattended-Upgrade; true"
        ).strip()
        print(f"APT::Periodic::Unattended-Upgrade on the stock image: {interval or 'unset'}")
        if interval in ("", "V='0'"):
            vm.succeed(
                f"printf %s {shlex.quote(auto_upgrades)} > /etc/apt/apt.conf.d/20auto-upgrades"
            )
        print(vm.succeed("apt-config dump Unattended-Upgrade::InstallOnShutdown; true"))
        print(f"the helper's log on the stock image:\n{tail(helper_log)}")

    with subtest("fact: python3-gi"):
        _, status = vm.execute("dpkg-query -s python3-gi 2>&1 | grep -E '^(Status|Version):'")
        print(f"python3-gi on ${entry.osId} ${entry.release}: {status.strip() or 'not installed'}")
        rc, where = vm.execute("python3 -c 'import gi, os; print(os.path.dirname(gi.__file__))'")
        print(f"import gi: rc {rc}, {where.strip()}")

    with subtest("activation during a daily run writes the helper's line on the decoy disk"):
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        vm.succeed(f"{nails_cmd} check --overlay-only")
        before = lines(helper_log, IN_PROGRESS)
        start_daily_run()
        release_when_seen()
        follow(f"{nails_cmd} activate -y > /mnt/data/activate.log 2>&1", "activate")
        print(vm.succeed("cat /mnt/data/activate.log || true"))
        session.assert_hidden_root(vm)
        follow(f"{ram_nails_cmd} emergency --json > /dev/null", "emergency")
        session.assert_decoy_root(vm)
        after = lines(helper_log, IN_PROGRESS)
        print(f"the helper's log on the decoy disk:\n{tail(helper_log)}")
        print(f"the runs' log on the decoy disk:\n{tail(run_log)}")
        assert len(after) > len(before), (
            f"the activation during the run left no {IN_PROGRESS!r} line in {helper_log}"
        )

    with subtest("fact: what the helper writes at an activation after a syntax error"):
        # The helper read the configuration at its start, before the file was
        # there; logind's signal makes it read it again.
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        mark = "NAILS_FACT_SYNTAX"
        vm.succeed(f"printf '%s\\n' 'Nails::Fact \"{mark}\"' > /etc/apt/apt.conf.d/99nails-fact")
        print(vm.succeed("apt-config dump Nails 2>&1 || true"))
        start = len(vm.succeed(f"cat {helper_log}").splitlines())
        follow(f"{nails_cmd} activate -y > /mnt/data/activate-2.log 2>&1", "activate-2")
        session.assert_hidden_root(vm)
        follow(f"{ram_nails_cmd} emergency --json > /dev/null", "emergency-2")
        session.assert_decoy_root(vm)
        written = vm.succeed(f"cat {helper_log}").splitlines()[start:]
        print("the helper's lines from the activation and the decoy's start after the way back:")
        print("\n".join(written))
        vm.succeed("rm -f /etc/apt/apt.conf.d/99nails-fact")

    with subtest("fact: what the helper writes when it starts without python3-gi"):
        rc, where = vm.execute("python3 -c 'import gi, os; print(os.path.dirname(gi.__file__))'")
        where = where.strip()
        if rc != 0 or not where:
            print("gi cannot be imported here: the helper always starts without it")
        else:
            start = len(vm.succeed(f"cat {helper_log}").splitlines())
            vm.succeed(f"mv {shlex.quote(where)} /run/gi-aside")
            vm.succeed("systemctl restart unattended-upgrades.service")
            vm.wait_until_succeeds("systemctl is-active unattended-upgrades.service", timeout=60)
            # Its start lines, if it writes any, within a few seconds.
            vm.execute(
                f"timeout 15 sh -c 'until [ $(wc -l < {helper_log}) -ge {start + 3} ]; "
                + "do sleep 0.5; done'"
            )
            written = vm.succeed(f"cat {helper_log}").splitlines()[start:]
            print("the helper's lines from a restart without gi:")
            print("\n".join(written))
            vm.succeed(f"mv /run/gi-aside {shlex.quote(where)}")
            vm.succeed("systemctl restart unattended-upgrades.service")
  '';
}
