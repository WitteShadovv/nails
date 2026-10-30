# After the way back, the decoy's getty and its login records carry process
# numbers a fresh boot of the same image gives them.
#
# A soft-reboot keeps the kernel's process-number counter, so the decoy's units
# would start on the way back with numbers that continue from everything the
# decoy and the hidden session ran. The getty on tty1 writes its number into
# /var/log/wtmp on the decoy disk, next to the low numbers of every earlier
# boot. As its last step the way back sets the counter by a measure: the entry
# records the number the decoy's boot gave its getty on tty1, and the hidden
# root's own start, which runs a getty on tty1 that nobody logs in to, shows how
# many numbers a start uses up to it. So this test takes the measured path. The
# fallback, just below the lowest number the decoy's own userspace held at
# entry, for a decoy without a getty or logind to measure by, has no VM test.
#
#   1. Two fresh boots of the image (the first start and a power cycle): the
#      number of the getty on tty1, its records in wtmp and logind's number,
#      the reference;
#   2. a session in which the hidden root starts thousands of processes, so
#      the counter is far past any fresh boot, then deactivate;
#   3. the getty the decoy starts on the way back, and its records in wtmp,
#      fall in the power-of-two range of a fresh boot's (the range the
#      forensic oracle keys a process number by), and below every number the
#      hidden session reached;
#   4. a second session, beside a unit that every soft-reboot leaves running
#      with the low number and the start it took before the first session:
#      the entry reads the decoy's start the first way back ran, not that
#      unit, so it anchors on the getty of that start, and the getty after
#      the second way back falls in the fresh boot's range again;
#   5. a plain soft-reboot with the counter just as far on (no NAILS): its
#      getty's number is outside that range, so the test can tell the two
#      apart.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-fresh-pids";
  meta.tags = [
    "forensic"
    "session"
  ];
  # A power cycle, four soft-reboots of two sessions and one plain one, and
  # about 35000 short processes.
  globalTimeout = 1800;

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      # A unit a soft-reboot leaves running, as a root storage daemon's can
      # be: it keeps its number and its start through every switch. The test
      # starts it.
      systemd.services.left-running = {
        description = "A unit a soft-reboot leaves running";
        unitConfig = {
          DefaultDependencies = false;
          IgnoreOnIsolate = true;
          SurviveFinalKillSignal = true;
        };
        serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };

  testScript = _: ''
    import json
    import os
    import re

    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/tmp/nails-headless.toml"
    # utmpdump: [type] [pid] [id] [user] [line] ...
    RECORD = re.compile(r"^\[(\d+)\] \[\s*(\d+)\] \[([^\]]*)\] \[([^\]]*)\] \[([^\]]*)\]")
    # INIT_PROCESS, LOGIN_PROCESS and DEAD_PROCESS: what a getty leaves.
    GETTY_TYPES = {5, 6, 8}


    def pid_range(pid):
        """The power-of-two range the forensic oracle keys a process number by."""
        low = 1 << (pid.bit_length() - 1)
        return (low, 2 * low - 1)


    def main_pid(unit):
        machine.wait_until_succeeds(f"systemctl is-active -q {unit}", timeout=60)
        pid = int(machine.succeed(f"systemctl show -P MainPID {unit}").strip())
        assert pid > 0, f"{unit} has no main process"
        return pid


    def tty1_records():
        """The getty records of tty1 in wtmp, as (type, pid), oldest first."""
        out = machine.succeed("utmpdump /var/log/wtmp 2>/dev/null")
        records = []
        for line in out.splitlines():
            match = RECORD.match(line)
            if match and int(match.group(1)) in GETTY_TYPES and match.group(5).strip() == "tty1":
                records.append((int(match.group(1)), int(match.group(2))))
        return records


    def numbers(label):
        """The getty's and logind's numbers now, and the wtmp records the
        getty of this start wrote."""
        getty = main_pid("getty@tty1.service")
        logind = main_pid("systemd-logind.service")
        machine.wait_until_succeeds(
            f"utmpdump /var/log/wtmp 2>/dev/null | grep -qE '^\\[[56]\\] \\[0*{getty}\\]'",
            timeout=60,
        )
        own = [record for record in tty1_records() if record[1] == getty]
        print(f"=== {label}: getty {getty} {pid_range(getty)}, logind {logind}, records {own} ===")
        return getty, logind, own


    # Every number the test read, kept in the test's output as
    # pid-numbers.json, so a passed run that comes from the binary cache still
    # shows them.
    results = {}


    def keep(key, value):
        results[key] = value
        out_dir = getattr(machine, "out_dir", None)
        if out_dir:
            with open(os.path.join(out_dir, "pid-numbers.json"), "w") as fh:
                json.dump(results, fh, indent=2, sort_keys=True)


    def churn(count):
        """Start `count` short processes; return the number the last one got."""
        machine.succeed(f"for i in $(seq {count}); do /bin/sh -c :; done")
        return int(machine.succeed("sh -c 'echo $$'").strip())


    def started(pid):
        """When process `pid` started, in seconds since the boot."""
        ticks = machine.succeed(f"sed 's/.*) //' /proc/{pid}/stat | cut -d' ' -f20").strip()
        return int(ticks) / 100


    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("two fresh boots of the image give the reference numbers"):
        first, first_logind, first_records = numbers("first boot")
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        second, second_logind, second_records = numbers("power cycle")
        fresh = {pid_range(first), pid_range(second)}
        keep("fresh boots", [
            {"getty": first, "logind": first_logind, "records": first_records},
            {"getty": second, "logind": second_logind, "records": second_records},
        ])
        assert first_records and second_records, "a fresh getty wrote no wtmp record"
        for _, pid in first_records + second_records:
            assert pid_range(pid) in fresh, f"a fresh getty record outside {fresh}"

    with subtest("a unit a soft-reboot leaves running takes a low number"):
        # The counter set to 1 hands out the lowest free numbers, which the
        # kernel threads and the initrd left: the unit's sits below every
        # number the decoy's start after the way back takes.
        machine.succeed("echo 1 > /proc/sys/kernel/ns_last_pid && systemctl start left-running")
        left = main_pid("left-running.service")
        left_start = started(left)
        keep("left running", {"pid": left, "started": left_start})
        print(f"=== the unit left running is {left}, started {left_start} s into the boot ===")

    with subtest("a session pushes the counter far past a fresh boot"):
        write_headless_config(CONFIG)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "activate")
        session.assert_hidden_root(machine)
        floor = json.loads(machine.succeed("cat /run/overlay-runtime/plan.json")).get("pids")
        print(f"=== the plan records {floor} ===")
        reached = churn(12000)
        print(f"=== the hidden session reached process number {reached} ===")
        keep("plan", floor)
        keep("hidden session reached", reached)
        assert reached > 4 * max(first, second), f"the counter only reached {reached}"
        # The decoy's start on the way back begins more than a minute after the
        # unit left running started, so a getty of that start lies outside the
        # minute after that unit.
        machine.wait_until_succeeds(
            f"awk '{{ exit !($1 > {left_start + 61}) }}' /proc/uptime", timeout=120
        )
        canonical_deactivate(CONFIG, "deactivate")

    with subtest("the decoy's getty and its records after the way back read like a fresh boot"):
        back, back_logind, back_records = numbers("way back")
        keep("way back", {"getty": back, "logind": back_logind, "records": back_records})
        assert pid_range(back) in fresh, (
            f"the getty after the way back is {back}, in {pid_range(back)}; "
            f"fresh boots gave {first} and {second}, in {sorted(fresh)}"
        )
        assert back_records, "the getty after the way back wrote no wtmp record"
        for kind, pid in back_records:
            assert pid_range(pid) in fresh, f"record type {kind} with pid {pid} outside {fresh}"
        assert back < reached and back_logind < reached, (back, back_logind, reached)
        print(
            f"=== logind: fresh {first_logind} and {second_logind}, way back {back_logind} ==="
        )
        assert machine.execute(f"test -d /proc/{left}")[0] == 0 and started(left) == left_start, (
            "the unit left running did not survive with its number"
        )

    with subtest("a second session measures by the decoy's start, not by the unit left running"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "activate-2")
        session.assert_hidden_root(machine)
        again = json.loads(machine.succeed("cat /run/overlay-runtime/plan.json")).get("pids")
        print(f"=== the second plan records {again} ===")
        keep("second plan", again)
        # The unit left running holds a number below every unit of the decoy's
        # start the way back ran, and a start from before it: left in, it
        # would be the floor, and the getty would fall outside the window.
        assert left < again["floor"], (
            f"the floor is {again['floor']}, and the unit left running {left}: "
            "the test needs that unit below the decoy's start"
        )
        assert any(
            anchor["comm"] == "agetty" and anchor["pid"] == back for anchor in again["anchors"]
        ), f"the second entry does not anchor on the getty {back}: {again}"
        reached_again = churn(3000)
        keep("second hidden session reached", reached_again)
        assert reached_again > 4 * max(first, second), reached_again
        canonical_deactivate(CONFIG, "deactivate-2")
        again_back, again_logind, again_records = numbers("second way back")
        keep("second way back", {
            "getty": again_back,
            "logind": again_logind,
            "records": again_records,
        })
        assert pid_range(again_back) in fresh, (
            f"the getty after the second way back is {again_back}, in {pid_range(again_back)}; "
            f"fresh boots gave {first} and {second}, in {sorted(fresh)}"
        )
        assert again_records, "the getty after the second way back wrote no wtmp record"
        for kind, pid in again_records:
            assert pid_range(pid) in fresh, f"record type {kind} with pid {pid} outside {fresh}"
        assert again_back < reached_again and again_logind < reached_again
        assert machine.execute(f"test -d /proc/{left}")[0] == 0 and started(left) == left_start, (
            "the unit left running did not survive with its number"
        )

    with subtest("a plain soft-reboot keeps the counter: the test tells the two apart"):
        reached = churn(12000)
        session.follow_soft_reboot(machine, "systemctl soft-reboot", "plain soft-reboot")
        machine.wait_for_unit("multi-user.target")
        plain, plain_logind, plain_records = numbers("plain soft-reboot")
        keep("plain soft-reboot", {
            "reached before": reached,
            "getty": plain,
            "logind": plain_logind,
            "records": plain_records,
        })
        assert plain > reached and pid_range(plain) not in fresh, (
            f"a plain soft-reboot gave the getty {plain} after the counter reached {reached}"
        )
  '';
}
