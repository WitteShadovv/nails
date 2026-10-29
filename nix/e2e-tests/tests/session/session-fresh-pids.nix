# After the way back, the decoy's getty and its login records carry process
# numbers a fresh boot of the same image gives them.
#
# A soft-reboot keeps the kernel's process-number counter, so the decoy's units
# would start on the way back with numbers that continue from everything the
# decoy and the hidden session ran. The getty on tty1 writes its number into
# /var/log/wtmp on the decoy disk, next to the low numbers of every earlier
# boot. The way back sets the counter to just below the lowest number the
# decoy's own userspace held at entry, as its last step.
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
#   4. a plain soft-reboot with the counter just as far on (no NAILS): its
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
  # A power cycle, two soft-reboots of the session and one plain one, and
  # about 30000 short processes.
  globalTimeout = 1500;

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
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
