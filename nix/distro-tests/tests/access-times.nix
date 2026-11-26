# The access-time scenario: what of the decoy disk NAILS reads.
#
# On a decoy root mounted `relatime`, any read of a file, a directory or a
# link whose access time is more than a day old updates that access time to
# the moment of the read. A program NAILS starts on the decoy, a file it reads
# without O_NOATIME, a unit file the service manager loads because NAILS asked
# about it, or a kernel module the kernel loads for it leaves the moment of the
# activation or of the session's end on the decoy disk, where a plain switch
# or power cycle leaves none. This scenario finds every such read, on the
# stock cloud image, in the way nix/distro-tests/py/access_times.py describes:
#
#   1. before each phase every entry of the decoy disk's filesystems is aged
#      two days, so that each read in the phase shows once;
#   2. four controls, with the hidden root mounted as for a session: a plain
#      soft-reboot of the decoy into itself and a plain power cycle (the
#      decoy's own power-off and a cold boot of the same disk), each before
#      and after the sessions, show what the decoy's own stop and start read;
#   3. `nails check` on the idle decoy: every read in its window is NAILS';
#   4. two sessions: an activation, work in the session and its end, once
#      with `deactivate` and once with the emergency, each of which powers
#      the machine off (a hidden session never goes back to the decoy), and
#      the decoy's next cold boot. A read before the end was asked for must
#      be one a control's stop made, a read after it one a control's stop or
#      start made.
#
# A power-off would end QEMU, and nix-vm-test's -snapshot disk with it, so
# QEMU pauses at each power-off instead and is reset into a cold boot of the
# same disk (py/power_off.py). Each cold boot loses /run and the share's
# mount: the walker reads the boot's access times first, and only then are
# the share, the binary in /run and the configuration made again.
#
# A read of a file or a directory that no control explains fails the
# scenario. A link NAILS' own lookups follow or read is listed and does not
# fail it: NAILS reads its own files with O_NOATIME and starts its programs
# with every mount noatime, but a lookup still updates the access time of a
# link on the way, which the operator guide names as what is left. Nor does
# a listing of udevd's rule and link directories: udevd lists them whenever
# it handles a uevent, every three seconds at most, whatever made the uevent.
#
# Every command of the scenario that reads the decoy disk runs through
# `noatime-run` (lib/noatime-run.c), which runs it in a mount namespace whose
# every mount is noatime: the walker itself (the guest's python3), the
# service manager queries and the plain soft-reboot of the controls. The one
# decoy program the driver itself starts for every command, base64 for its
# output, runs before each reference is taken, so its own access times, and
# those of the libraries it loads, are already new when a phase starts.
# Debian mounts /run noexec, and a switch keeps no mount below /run, so the
# helper and the walker are copied to a directory of the decoy disk that the
# walker leaves out (its own start reads the helper's file and nothing else).
#
# The scenario runs NAILS as an operator does: the binary from the hidden
# volume, the configuration in /run and the hidden root on a loop device
# backed by a tmpfs (lib/hidden-root.nix), for an operator account it adds,
# named by SUDO_UID and SUDO_USER as sudo names it, so that check and the
# activation read that account's entry and inspect its home as they do for a
# real operator. Starting sudo itself reads the decoy disk (its binary, PAM,
# sudoers, the account databases), which the operator guide names as what is
# left; the variables are set by the backdoor's shell, so nothing starts for
# them. The decoy is made amnesic, as NAILS requires, its
# timers are masked and cloud-init is turned off before the first measured
# phase, so nothing the decoy schedules runs into a phase.
# NetworkManager-dispatcher.service is masked too, where it exists (Fedora
# 44): the dispatcher runs its hooks, which read their scripts and
# libraries, at the decoy's stop and on each change of a connection, which a plain soft-reboot control hits only
# sometimes, so a hit in a session's window with clean controls would read
# as unexplained (decision 54). No path is allowlisted for it. The gate and
# the smoke keep the stock dispatcher. apt's configuration
# is not aged: NAILS compares its change times with the start of Debian's
# unattended-upgrades helper, and refuses where it changed after it (its
# entries still show a read, as their access times are older than a day).
# Nor is /etc/selinux/config, on Fedora: lsm-status compares its change time
# with the boot, and refuses where it changed after the boot, as SELinux may
# then run another policy than the one it names. A read of that one file may
# not show: under relatime a read updates its access time only where that is
# a day old, or older than the file's last change.
#
# Like the records scenarios it is a host driver: on a KVM host by hand, or in
# the records suite of distro-e2e.yml.
{
  pkgs,
  nix-vm-test,
}:
let
  distroVm = import ../lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ../lib/hidden-root.nix;

  # The helper that runs a command with every mount noatime, linked statically
  # with the musl toolchain the release binary is built with, so starting it
  # reads nothing of the guest's disk.
  noatimeRun = pkgs.pkgsCross.musl64.runCommandCC "noatime-run" { } ''
    mkdir -p $out/bin
    $CC -static -O2 -Wall -Werror -o $out/bin/noatime-run ${../lib/noatime-run.c}
  '';

  share = {
    tag = "tools";
    target = "/run/tools";
  };
in
# `cfg` is one scenario:
#   name   the image's name in images.json, for the report;
#   entry  its entry (images.nix);
#   nails  the package whose bin/nails the scenario runs.
cfg:
let
  tools = pkgs.runCommand "access-times-tools" { } ''
    mkdir -p $out
    cp ${cfg.nails}/bin/nails $out/nails
    cp ${noatimeRun}/bin/noatime-run $out/noatime-run
    cp ${../py/atime_walk.py} $out/atime_walk.py
  '';
in
distroVm.buildVmTest {
  inherit (cfg) entry;
  target = "driver";

  sharedDirs.${share.tag} = {
    source = "${tools}";
    inherit (share) target;
  };

  # A cloud image, an overlay root and a hidden volume on a tmpfs at once.
  memorySize = 3072;

  testScript = ''
    import json
    import shlex
    import signal
    import sys
    import time

    sys.path.insert(0, "${../../e2e-tests/py}")
    from nails_e2e import session  # noqa: E402

    sys.path.insert(0, "${../py}")
    import access_times as at  # noqa: E402
    import power_off  # noqa: E402

    image_name = "${cfg.name}"
    # The share's mount does not survive a switch: the binary is kept in /run,
    # which a soft-reboot carries, and copied to the hidden volume, where it
    # runs; the helper and the walker are kept on the decoy disk, in a
    # directory the walker leaves out (see the header). A cold boot loses
    # /run and the share's mount, which after_cold_boot() makes again.
    SHARE = "${share.target}"
    STORE = "/run/atime"
    TOOLS = "/var/lib/atime-harness"
    QUIET = f"{TOOLS}/noatime-run"
    NAILS = "/mnt/data/nails"
    CONFIG = "/run/nails-atime.toml"
    OPERATOR = "atimeop"
    # Filled in once the operator account exists (see the header).
    OPERATOR_ENV = ""
    NAILS_CMD = f"{NAILS} --config {CONFIG}"
    SERIAL = power_off.SERIAL_CONSOLE
    RAM_NAILS_CMD = f"/run/overlay-runtime/control --config {CONFIG}"
    UNRESOLVED = "Target user could not be resolved"
    AGE_SECONDS = 2 * 86400
    # What the aging leaves alone, as NAILS judges their change times (see
    # the header): apt's configuration, and SELinux's on Fedora.
    NOT_AGED = ("/etc/apt", "/etc/selinux/config")
    PID1 = (
        "org.freedesktop.systemd1 /org/freedesktop/systemd1 "
        "org.freedesktop.systemd1.Manager"
    )

    report = {"image": image_name, "phases": {}}
    findings = []


    def quiet(command):
        # The command, run by the decoy's /bin/sh with every mount noatime.
        return f"{QUIET} /bin/sh -c {shlex.quote(command)}"


    def walker(args, timeout=900, skip=()):
        skips = " ".join(f"--skip {shlex.quote(path)}" for path in (TOOLS, *skip))
        return vm.succeed(
            f"{QUIET} /usr/bin/python3 -I {TOOLS}/atime_walk.py {skips} {args}",
            timeout=timeout,
        )


    def now_ns():
        # bash's own clock: no program starts for it.
        return at.parse_epoch_ns(vm.succeed("echo $EPOCHREALTIME"))


    def pid1_time(prop):
        # One of PID 1's timestamps, in nanoseconds since the epoch; 0 where
        # this systemd does not keep it.
        out = vm.succeed(quiet(f"busctl get-property {PID1} {prop} || echo 't 0'"))
        values = at.parse_busctl_times(out)
        return values[0] if values else 0


    def pid1_times():
        # When the last stop began and when this userspace started.
        return pid1_time("ShutdownStartTimestamp"), pid1_time("UserspaceTimestamp")


    # What a freshly booted decoy still starts outside PID 1's job queue once
    # its network is up: NetworkManager's dispatcher (D-Bus activated, on each
    # change of a connection, with its scripts such as chrony's) and
    # console-login-helper-messages (issue snippets per link). After the cold
    # boot that ends every session they read the decoy disk for a while, as
    # after any boot, and a window opened before they are done counts their
    # reads.
    LATE_STARTERS = "NetworkManager-dispatcher.service 'console-login-helper-messages*'"


    def settle():
        vm.execute(
            quiet("timeout 300 systemctl is-system-running --wait >/dev/null 2>&1 || :"),
            timeout=330,
        )
        deadline = time.monotonic() + 300
        while True:
            jobs = vm.succeed(quiet(f"busctl call {PID1} ListJobs")).strip()
            if jobs.startswith("a(usssoo) 0"):
                break
            assert time.monotonic() < deadline, f"PID 1 still runs jobs: {jobs}"
            time.sleep(1)
        # NetworkManager's startup done, where it runs (all through QUIET,
        # so the waits read nothing of the disk).
        vm.execute(
            quiet(
                "if command -v nm-online >/dev/null 2>&1; then "
                + "timeout 130 nm-online -s -q --timeout=120 || :; fi"
            ),
            timeout=150,
        )
        # Then neither late starter runs, three looks in a row a second apart.
        idle = 0
        deadline = time.monotonic() + 180
        while idle < 3:
            busy, _ = vm.execute(
                quiet(
                    "systemctl list-units --all --plain --no-legend "
                    + f"--state=active,activating,deactivating {LATE_STARTERS} | grep -q ."
                )
            )
            idle = idle + 1 if busy != 0 else 0
            assert time.monotonic() < deadline, (
                "the decoy's late starters still run: "
                + vm.succeed(quiet(f"systemctl list-units --all --plain --no-legend {LATE_STARTERS} || :"))
            )
            time.sleep(1)


    def reconnect(label):
        def alarm(_signum, _frame):
            raise AssertionError(f"{label}: the backdoor announced itself but never connected")

        previous = signal.signal(signal.SIGALRM, alarm)
        signal.alarm(120)
        try:
            vm.connect()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)


    def switch(trigger, label, output=None, deadline_s=600.0):
        # Run the trigger in the background and follow the soft-reboot it
        # enqueues to the new backdoor, as session.follow_soft_reboot does,
        # with every query of the decoy's service manager through QUIET. Its
        # exit status, and the system's state when that is not 0, reach the
        # serial console, so a trigger that fails without switching fails here
        # at once. What it prints goes to `output`, where that names a file,
        # and a trigger that fails copies the file to the console before its
        # status (at.trigger_output), so the failure says what NAILS said.
        # Nothing asks the backdoor anything after a failed trigger: the
        # driver counts it as gone from the start of the trigger, and would
        # wait for a new one that never comes.
        console_index = len(vm.full_console_log)
        state = f"$({QUIET} /usr/bin/systemctl is-system-running 2>/dev/null)"
        copy = ""
        if output is not None:
            copy = (
                'if [ "$status" != 0 ] && [ "$state" != stopping ]; then '
                + f"{{ echo {at.OUTPUT_BEGIN}; {QUIET} /usr/bin/cat {output}; "
                + f"echo {at.OUTPUT_END}; }} > {session.SERIAL_CONSOLE} 2>&1; fi; "
            )
        vm.execute(
            f"(set +e; ({trigger}) </dev/null >{output or '/dev/null'} 2>&1; "
            + f'status=$?; state=; [ "$status" = 0 ] || state={state}; {copy}'
            + f'echo "{session.TRIGGER_EXIT_MARKER}$status $state" > {session.SERIAL_CONSOLE}) &',
            check_return=False,
            check_output=False,
        )
        vm.connected = False
        deadline = time.monotonic() + deadline_s
        while True:
            lines = vm.full_console_log[console_index:]
            stuck = session.stuck_lines(lines)
            assert not stuck, f"{label}: the new userspace is stuck: {stuck[0]}"
            failed = session.trigger_failure(lines)
            if failed is not None:
                vm.log(f"{label}: last console lines:\n" + "\n".join(lines[-80:]))
                said = at.trigger_output(lines) if output is not None else None
                raise AssertionError(
                    f"{label}: the trigger failed ({failed}) and never switched"
                    + ("" if said is None else f"; it printed:\n{said}")
                )
            if any(session.BACKDOOR_MARKER in line for line in lines):
                break
            exited = vm.process.poll() if vm.process is not None else None
            assert exited is None, f"{label}: QEMU exited ({exited})"
            assert time.monotonic() < deadline, f"{label}: no backdoor after {deadline_s} s"
            time.sleep(0.5)
        reconnect(label)
        settle()


    def write_config():
        vm.succeed(
            "printf '%s\\n' 'hidden_volume_root = \"/mnt/data\"' "
            + f"'minimum_space_mb = 100' > {CONFIG}"
        )


    def power_cycle(trigger, label):
        # The machine powers off (QEMU pauses, the disk kept) and boots cold
        # from the same disk; settled, the walker can read what it read.
        power_off.follow_power_off(vm, trigger, label)
        power_off.boot_again(vm, label)
        settle()


    def after_cold_boot():
        # What a cold boot lost, made again once its reads are read: the
        # share's mount, the binary in /run and the configuration.
        vm.succeed(
            "mkdir -p ${share.target} && "
            + "{ mountpoint -q ${share.target} || "
            + "mount -t 9p -o defaults,trans=virtio,version=9p2000.L,cache=loose,msize=268435456 "
            + "${share.tag} ${share.target}; }"
        )
        vm.succeed(f"mkdir -p {STORE} && cp {SHARE}/nails {STORE}/")
        write_config()


    def phase_start(label):
        # Age the decoy disk, let what the aging woke settle, start base64 once
        # (the driver's own program, see the header) and take the reference
        # past all of it.
        aged = json.loads(
            walker(f"age {AGE_SECONDS} {MOUNT_ARGS}", skip=NOT_AGED)
        )
        assert aged["aged"] > 1000, f"{label}: only {aged} entries aged"
        settle()
        vm.succeed("true")
        time.sleep(1.1)
        ref = now_ns()
        time.sleep(0.1)
        report["phases"][label] = {"aged": aged, "ref": ref}
        return ref


    def reads_of(label, ref):
        listing = at.parse_listing(walker(f"list {ref} {MOUNT_ARGS}"))
        reads = at.reads_since(listing)
        report["phases"][label].update(
            {
                "walked": listing.walked,
                "reads": [[s.path, s.atime, s.kind] for s in reads],
            }
        )
        return reads


    def on_decoy():
        out = vm.succeed(quiet("findmnt -no FSTYPE /")).strip()
        assert out != "overlay", f"the root is still the overlay: {out}"


    def control(label, cold=False):
        # The decoy with the hidden root mounted, as a session enters it, so
        # the control's stop handles that mount as the way in does. `cold`
        # takes a plain power cycle instead of a plain soft-reboot.
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        ref = phase_start(label)
        if cold:
            power_cycle(quiet("systemctl poweroff"), label)
        else:
            switch(quiet("systemctl soft-reboot"), label)
        on_decoy()
        shutdown, userspace = pid1_times()
        # The split of the control's reads needs the new userspace's start.
        assert userspace > ref, (
            f"{label}: this userspace started at {userspace}, before the switch ({ref})"
        )
        reads = reads_of(label, ref)
        report["phases"][label].update({"stop": shutdown, "userspace": userspace})
        if cold:
            after_cold_boot()
        # A mapping the plain soft-reboot left open would keep the next hidden
        # root from taking its name.
        vm.execute(quiet("if [ -e /dev/mapper/data ]; then cryptsetup close data; fi"))
        return at.control_of(reads, userspace)


    def flow(label, leave):
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed(f"cp {STORE}/nails {NAILS} && chmod 0755 {NAILS}")
        ref = phase_start(f"{label}-check")
        status, _ = vm.execute(
            f"{OPERATOR_ENV} {NAILS_CMD} check --overlay-only --json "
            + f"> {STORE}/{label}-check.json 2>&1"
        )
        end = now_ns()
        reads = reads_of(f"{label}-check", ref)
        checked = vm.succeed(quiet(f"cat {STORE}/{label}-check.json"))
        print(checked, flush=True)
        # The check inspected the operator's account, as it does under sudo.
        assert UNRESOLVED not in checked, f"{label}: check resolved no operator"
        report["phases"][f"{label}-check"].update({"status": status, "end": end})
        check_findings = at.judge_check(reads)
        findings.extend(check_findings)
        marks = [(f"{label} check", ref), (f"{label} check returned", end)]

        ref = phase_start(label)
        marks.append((f"{label} activate", ref))
        # PID 1 logs at debug level until the switch, and its journal from the
        # activation on is printed from the hidden session, so a read can be
        # lined up with what PID 1 did then. Neither reads the decoy disk.
        vm.succeed(quiet(f"busctl set-property {PID1} LogLevel s debug"))
        log = f"/mnt/data/{label}-activate.log"
        switch(f"{OPERATOR_ENV} {NAILS_CMD} activate -y", f"{label} in", output=log)
        session.assert_hidden_root(vm)
        print(vm.succeed(f"cat {log}"), flush=True)
        since = ref // 1_000_000_000 - 1
        journal = vm.succeed(
            quiet(f"journalctl _PID=1 -o short-unix --no-pager --since @{since}")
        )
        print(f"=== PID 1 JOURNAL {label} ===\n{journal}=== END ===", flush=True)
        stop_in, hidden_start = pid1_times()
        marks += [(f"{label} decoy stop", stop_in), (f"{label} hidden start", hidden_start)]
        vm.succeed(
            "echo session > /root/atime-session && echo session > /etc/atime-session "
            + f"&& {NAILS_CMD} status --json > /dev/null && sleep 15"
        )
        end = now_ns()
        marks.append((f"{label} {leave}", end))
        if leave == "deactivate":
            trigger = f"{OPERATOR_ENV} {NAILS_CMD} deactivate -y"
        else:
            trigger = f"{OPERATOR_ENV} {RAM_NAILS_CMD} emergency --json"
        # Either powers the machine off; the decoy then boots cold from the
        # same disk. The command's output reaches the console, where a failed
        # end shows it.
        power_cycle(f"{trigger} > {SERIAL} 2>&1", f"{label} {leave}")
        on_decoy()
        _, decoy_start = pid1_times()
        marks.append((f"{label} decoy cold boot", decoy_start))
        reads = reads_of(label, ref)
        report["phases"][label].update({"marks": marks, "end": end})
        after_cold_boot()
        return reads, end, marks


    # --- the scenario ---------------------------------------------------------

    vm.wait_for_unit("multi-user.target")
    vm.succeed(
        f"mkdir -p {STORE} {TOOLS} && cp {SHARE}/nails {STORE}/ && "
        + f"cp {SHARE}/noatime-run {SHARE}/atime_walk.py {TOOLS}/ && "
        + f"chmod 0755 {TOOLS}/noatime-run"
    )
    write_config()
    print(vm.succeed("cat /etc/os-release; uname -r; findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS"))

    with subtest("prepare the decoy: amnesic, no timers, no cloud-init, no NetworkManager dispatcher"):
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        vm.succeed(
            "for timer in $(systemctl list-units --type=timer --all --plain --no-legend "
            + "| awk '{print $1}'); do systemctl mask --now \"$timer\"; done; "
            + "if [ -d /etc/cloud ]; then touch /etc/cloud/cloud-init.disabled; fi"
        )
        # NetworkManager's dispatcher, where it exists (see the header).
        vm.succeed(
            "if systemctl cat NetworkManager-dispatcher.service >/dev/null 2>&1; then "
            + "systemctl mask --now NetworkManager-dispatcher.service; fi"
        )
        vm.succeed("""${hiddenRoot.stopAptTimers}""")
        # The operator account, with a home and a shell as useradd makes them.
        vm.succeed(f"useradd --create-home --shell /bin/bash {OPERATOR}")
        operator_uid = vm.succeed(f"id -u {OPERATOR}").strip()
        operator_gid = vm.succeed(f"id -g {OPERATOR}").strip()
        OPERATOR_ENV = (
            f"SUDO_UID={operator_uid} SUDO_GID={operator_gid} SUDO_USER={OPERATOR}"
        )
        vm.wait_until_succeeds("""${hiddenRoot.aptRunsEnded}""", timeout=900)
        # A first switch, measured by nothing, so that every later phase starts
        # from a decoy that booted with the timers masked.
        switch("systemctl soft-reboot", "warm-up")
        MOUNTS = json.loads(walker("mounts"))["mounts"]
        assert "/" in MOUNTS, f"the decoy disk's filesystems: {MOUNTS}"
        MOUNT_ARGS = " ".join(shlex.quote(m) for m in MOUNTS)
        report["mounts"] = MOUNTS
        print(f"the decoy disk's filesystems: {MOUNTS}")

    with subtest("control: a plain soft-reboot"):
        controls = [control("control-1")]

    with subtest("control: a plain power cycle"):
        controls.append(control("control-2", cold=True))

    with subtest("a session ended by deactivate, which powers off"):
        flows = [flow("session-1", "deactivate")]

    with subtest("a session ended by the emergency, which powers off"):
        flows.append(flow("session-2", "emergency"))

    with subtest("control: a plain soft-reboot after the sessions"):
        controls.append(control("control-3"))

    with subtest("control: a plain power cycle after the sessions"):
        controls.append(control("control-4", cold=True))

    with subtest("check, activation and the session's end read nothing a plain switch or power cycle does not"):
        merged = at.merge(controls)
        all_marks = []
        for reads, end, marks in flows:
            findings.extend(at.judge_flow(reads, end, merged))
            all_marks += marks
        others, links = at.split_links(findings)
        others, udevd = at.split_udevd(others)
        report["findings"] = at.as_json(others)
        report["links"] = at.as_json(links)
        report["udevd"] = at.as_json(udevd)
        # Flushed at once: a driver that fails exits without writing what its
        # output still holds.
        print("=== ACCESS-TIME REPORT ===", flush=True)
        print(json.dumps(report, sort_keys=True), flush=True)
        print("=== END OF ACCESS-TIME REPORT ===", flush=True)
        # The links NAILS' own lookups follow or read, which the operator
        # guide names: listed, not a failure (see access_times.py).
        print(
            f"{len(links)} links of the decoy disk NAILS' own lookups followed or read:\n"
            + at.describe(links, all_marks),
            flush=True,
        )
        print(
            f"{len(udevd)} listings of udevd's rule and link directories:\n"
            + at.describe(udevd, all_marks),
            flush=True,
        )
        assert not others, (
            f"{len(others)} reads of the decoy disk no plain soft-reboot or power cycle makes:\n"
            + at.describe(others, all_marks)
        )
  '';
}
