# The portable smoke scenario, generated once per distribution.
#
# nix/distro-tests/default.nix maps this function over the image table, so every
# distribution runs the same lifecycle on the NixOS test driver through
# nix-vm-test. The scenario proves the whole-root session end to end on a
# non-NixOS host (systemd >= 254): activation soft-reboots the stock cloud image
# into an overlay of its own root, every hidden write (including /usr) lands on
# the hidden root, every mounted boot filesystem stays read-only, and
# deactivation and emergency soft-reboot back to the plain decoy without a trace
# on the decoy disk. The
# decoy runs blk-availability.service as Debian's and Ubuntu's lvm2 ships it
# (the image's own unit where lvm2 is installed, a copy where only dmsetup
# is), and the second session, entered without /boot or the ESP mounted, keeps
# its hidden volume through that unit's stop. A decoy service that keeps a PID
# file in /run starts again after an emergency killed its hidden copy, and a
# Ctrl+C during the pre-flight checks cancels an activation. The second
# session is also a rehearsal, run the way `nails rehearse` guides it: plant in
# the session (a scan there is refused), a plain deactivate, then on the decoy,
# in the same boot, the hidden root opened again and a scan of the raw decoy
# devices that runs and finds nothing. On systemd 255 (Ubuntu 24.04), which
# reports no soft-reboot count, only the session's entry time tells the two
# apart. Where the image table lists what the image is known to fail
# (`knownFailedUnits`), the units failed on the decoy before the first switch,
# in each hidden session and after each way back must be exactly the listed
# ones, each failed with its known line, and the `platform` row of `check`
# must warn about every unit listed; without a list they are only printed.
#
# The host-side disk-image forensic scanners are shared verbatim with the NixOS
# suite (nix/e2e-tests/lib/disk_forensics.py): they run on the NixOS test driver,
# not in the guest, so they are distribution-agnostic.
#
# nix-vm-test specifics the script is built around (see lib/distro-vm.nix):
#
#   - The machine is `vm`.
#   - The disk is the store image under QEMU `-snapshot`: guest writes vanish
#     when QEMU exits. The lifecycle runs in one QEMU process (a soft-reboot
#     keeps the kernel and QEMU), and each forensic image is taken by first
#     mirroring the live disk into `<state_dir>/vm.qcow2` -- where
#     `disk_forensics.root_image` looks -- and then letting
#     `disk_forensics.snapshot` shut down and convert it as usual.
#   - The 9p share with the binary is mounted only once before the script runs.
#     A soft-reboot carries /run (the config file survives) but not the mounts
#     below it, so after every switch `prepare_boot()` mounts the share again.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  distroVm = import ../lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ../lib/hidden-root.nix;
  diskForensics = import ../../e2e-tests/lib/disk-forensics.nix { inherit pkgs; };

  # The canonical static musl binary, the exact artifact a user installs.
  inherit (self.packages.x86_64-linux) nails;

  # The binary is shared read-only over 9p onto the /run tmpfs, so neither the
  # binary nor its mount point ever lands on the decoy disk the forensic check
  # images, and it is never one of the trees the overlay or the read-only guard
  # touches -- the /usr write assertion stays about the decoy system. The tag
  # and the path are neutral: both are visible in the guest mount table.
  binShare = {
    tag = "tools";
    target = "/run/tools";
  };
in
# `name` and `entry` are one name and value of images.nix.
name: entry:
let
  # What the image is known to fail, or null, as a file the driver reads: a
  # line in it passes through neither Nix nor a shell.
  knownFailedUnits = pkgs.writeText "known-failed-units.json" (
    builtins.toJSON (entry.knownFailedUnits or null)
  );
in
distroVm.buildVmTest {
  inherit entry;

  sharedDirs.${binShare.tag} = {
    source = "${nails}/bin";
    inherit (binShare) target;
  };

  # Headroom for the RAM-backed hidden root next to a full cloud-image boot.
  # The value lives on the entry (images.nix); the enabled entries carry 2048.
  memorySize = entry.memory;

  testScript = ''
    import json
    import os
    import shlex
    import sys

    # The NixOS suite's in-VM helper package, for following a soft-reboot.
    sys.path.insert(0, "${../../e2e-tests/py}")
    from nails_e2e import session  # noqa: E402

    # The distribution-generic smoke helpers (nix/distro-tests/py), locked by
    # the `distro-checks` flake check: where a hidden write lands, which boot
    # filesystems to check, and the overlay feature-option read-back.
    sys.path.insert(0, "${../py}")
    import distro_checks  # noqa: E402
    import subprocess
    import time
    from typing import Any

    # The decoy's /etc/os-release ID, from the image-table entry. The scenario
    # is otherwise distribution-agnostic; this names the decoy in the log.
    os_id = "${entry.osId}"

    # The entry's name in images.json, and the units its image is known to
    # fail there (knownFailedUnits), or None to only print the failed units.
    image_name = "${name}"
    with open("${knownFailedUnits}") as handle:
        known_failed = json.load(handle)
    # Known failures that no longer happen, collected over the run and
    # asserted at its end, so one run names every phase where one is gone.
    gone_failures: list[str] = []

    ${diskForensics.pythonSetup}

    nails = "${binShare.target}/nails"
    # On the /run tmpfs: never on the decoy disk; carried across soft-reboots.
    config = "/run/nails-smoke.toml"
    nails_cmd = f"{nails} --config {shlex.quote(config)}"
    # The RAM copy of the binary the session keeps in /run: the 9p share is
    # not mounted in the hidden root until prepare_boot() mounts it again.
    ram_nails_cmd = f"/run/overlay-runtime/control --config {shlex.quote(config)}"

    # Trees a hidden write goes to. /usr is included: the whole root is
    # overlaid, so a hidden write there lands on the hidden root as well.
    canary_trees = ("home", "etc", "srv", "opt", "var", "usr", "root")

    # blk-availability.service as Debian's and Ubuntu's lvm2 package ships it,
    # enabled, with its stop as its only command. That stop, which every
    # soft-reboot runs, unmounts each filesystem on a device-mapper device
    # outside a few system paths (blkdeactivate -u): in the switch, the hidden
    # volume below /run/nextroot.
    blk_availability_unit = "\n".join(
        (
            "[Unit]",
            "Description=Availability of block devices",
            "Before=shutdown.target",
            "After=lvm2-activation.service iscsi-shutdown.service iscsi.service iscsid.service fcoe.service rbdmap.service",
            "DefaultDependencies=no",
            "Conflicts=shutdown.target",
            "",
            "[Service]",
            "Type=oneshot",
            "ExecStop=/usr/sbin/blkdeactivate -u -l wholevg -m disablequeueing -r wait",
            "RemainAfterExit=yes",
            "",
            "[Install]",
            "WantedBy=sysinit.target",
            "",
        )
    )
    blkdeactivate = "argv[]=/usr/sbin/blkdeactivate -u -l wholevg -m disablequeueing -r wait"

    # A decoy service that keeps a PID file in /run the way avahi-daemon does:
    # it removes the file when it stops, and refuses to start while one is
    # left. A copy killed by an emergency in the hidden session leaves its file
    # behind, which the way back must remove. The stop signal goes to the
    # shell alone (KillMode=mixed), as a daemon removes its file itself: sent
    # to every process, it can also reach the rm the trap starts.
    pidfile_probe_script = "\n".join(
        (
            "#!/bin/sh",
            "set -C",
            "mkdir -p /run/pidfile-probe",
            "if ! echo $$ > /run/pidfile-probe/pid; then",
            "  echo \"pid file left by $(cat /run/pidfile-probe/pid)\"",
            "  exit 1",
            "fi",
            "echo \"started as $$\"",
            "trap 'echo stopping; rm -f /run/pidfile-probe/pid; exit 0' TERM",
            "while :; do sleep 1 & wait $!; done",
            "",
        )
    )
    pidfile_probe_unit = "\n".join(
        (
            "[Unit]",
            "Description=PID file probe",
            "",
            "[Service]",
            "ExecStart=/usr/local/sbin/pidfile-probe",
            "KillMode=mixed",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        )
    )

    # Units whose job the hidden root does not need and which fail there or
    # do nothing (writes to the read-only boot filesystems, a remount or resize
    # of the root overlay), masked there where the decoy has them, as
    # session::hidden_masks::UNITS lists them.
    hidden_masked_units = (
        "systemd-boot-random-seed.service",
        "grub-common.service",
        "grub2-common.service",
        "grub-initrd-fallback.service",
        "systemd-remount-fs.service",
        "systemd-growfs-root.service",
    )
    # The generator every hidden root masks, so it never mounts a decoy
    # partition the fstab does not list.
    gpt_auto_mask = "/run/systemd/system-generators/systemd-gpt-auto-generator"


    def write_config():
        vm.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    minimum_space_mb = 100
    EOF"""
            % shlex.quote(config)
        )


    def prepare_boot():
        # Everything a fresh boot loses: the 9p share (nix-vm-test mounts it
        # only once, before this script) and the /run config.
        vm.wait_for_unit("multi-user.target")
        vm.succeed(
            "mkdir -p ${binShare.target} && "
            + "{ mountpoint -q ${binShare.target} || "
            + "mount -t 9p -o defaults,trans=virtio,version=9p2000.L,cache=loose,msize=268435456 "
            + "${binShare.tag} ${binShare.target}; }"
        )
        vm.succeed(f"test -x {nails}")
        write_config()


    def qmp(command: str, arguments: dict[str, Any] | None = None) -> Any:
        client = vm.qmp_client
        assert client is not None, "the QMP socket is not connected"
        reply: Any = client.send(command, arguments or {})
        return reply["return"]


    def persist_root_disk():
        # Mirror the running root disk -- the store image plus the -snapshot
        # layer holding every guest write -- into a standalone qcow2 at the path
        # disk_forensics.root_image() reads, and pivot QEMU onto it. Shutting the
        # machine down afterwards (disk_forensics.snapshot) then flushes the
        # guest into that file instead of discarding its writes.
        #
        # The target is created here and attached with blockdev-add rather than
        # left to drive-mirror: drive-mirror opens its target with the source's
        # flags, which under -snapshot include the temporary-file flag, so QEMU
        # would delete the mirror again when it exits.
        target = os.path.join(str(vm.state_dir), f"{vm.name}.qcow2")
        if os.path.exists(target):
            os.remove(target)
        blocks = qmp("query-block")
        roots = [
            block
            for block in blocks
            if block.get("inserted") and not block.get("removable", False)
        ]
        assert len(roots) == 1, f"cannot identify the root drive: {blocks}"
        device = roots[0]["device"]
        size = roots[0]["inserted"]["image"]["virtual-size"]
        subprocess.run(
            [disk_forensics.QEMU_IMG, "create", "-q", "-f", "qcow2", target, str(size)],
            check=True,
        )
        # Unique per call: a node name stays taken for the life of the QEMU process.
        job = f"persist-root-{time.monotonic_ns()}"
        qmp(
            "blockdev-add",
            {
                "driver": "qcow2",
                "node-name": job,
                "file": {"driver": "file", "filename": target},
            },
        )
        qmp("blockdev-mirror", {"job-id": job, "device": device, "target": job, "sync": "full"})
        deadline = time.monotonic() + 900
        while True:
            jobs = [entry for entry in qmp("query-block-jobs") if entry["device"] == job]
            assert jobs, f"the mirror of {device} ended before it was ready"
            if jobs[0].get("ready"):
                break
            assert time.monotonic() < deadline, f"the mirror of {device} never became ready"
            time.sleep(1)
        qmp("block-job-complete", {"device": job})
        while any(entry["device"] == job for entry in qmp("query-block-jobs")):
            assert time.monotonic() < deadline, f"the mirror of {device} never completed"
            time.sleep(1)
        active = [block for block in qmp("query-block") if block["device"] == device]
        assert active and active[0]["inserted"]["file"] == target, (
            f"QEMU did not pivot {device} onto {target}: {active}"
        )


    def image_decoy(label):
        persist_root_disk()
        return disk_forensics.snapshot(vm, label, restart=False)


    def follow(trigger, label):
        timings = session.follow_soft_reboot(vm, trigger, label)
        print(f"{label}: {timings}")
        prepare_boot()


    def blk_availability_stop():
        return vm.succeed("systemctl show -P ExecStop blk-availability.service").strip()


    def unit_state(unit):
        out = vm.succeed(f"systemctl show --property=LoadState --property=ActiveState {unit}")
        return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


    def assert_guarded_blk_availability(where):
        # Loaded and active, its stop cleared until the way back has switched:
        # a guard that left the unit without a command would make systemd
        # refuse to load it ("bad-setting").
        state = unit_state("blk-availability.service")
        assert state == {"LoadState": "loaded", "ActiveState": "active"}, f"{where}: {state}"
        stop = blk_availability_stop()
        assert stop == "", f"{where}: blk-availability.service still stops with {stop}"


    def load_states(units):
        return {unit: unit_state(unit)["LoadState"] for unit in units}


    def assert_nothing_requires(units):
        # A masked unit gets no start job, and neither does a unit that
        # requires it: such a unit would silently not start in the hidden root.
        for unit in units:
            out = vm.succeed(
                f"systemctl show --property=RequiredBy,RequisiteOf,BoundBy {unit}"
            )
            needed = {
                key: value
                for key, value in (
                    line.split("=", 1) for line in out.splitlines() if "=" in line
                )
                if value
            }
            assert not needed, f"{unit} is masked in the hidden root, but {needed} need it"


    def assert_gpt_auto_masked(where, masked):
        # Masked in every hidden root; gone with the session's /run on the way
        # back.
        rc, target = vm.execute(f"readlink {gpt_auto_mask}")
        if masked:
            assert rc == 0 and target.strip() == "/dev/null", (
                f"{where}: {gpt_auto_mask} -> {target!r}"
            )
        else:
            assert rc != 0, f"{where}: {gpt_auto_mask} is left: {target!r}"


    def check_failed_units(where, phase=None):
        # The units failed now. With a list, exactly the ones it names for
        # `phase` (none before the first switch), each failed with its known
        # line; a listed one that no longer fails is collected for the end.
        # Without one, they are only printed.
        failed = distro_checks.parse_failed_units(
            vm.succeed(
                "timeout 30 systemctl list-units --state=failed --all --plain "
                + "--no-legend --no-pager"
            )
        )
        print(f"=== failed units {where}: {', '.join(sorted(failed)) or 'none'} ===")
        if known_failed is None:
            return
        expected = known_failed[phase] if phase else {}
        unexpected, missing = distro_checks.failed_unit_mismatch(failed, expected)
        for unit in unexpected:
            _, out = vm.execute(
                f"timeout 30 systemctl status --no-pager -l -n 30 {shlex.quote(unit)}",
                check_return=False,
            )
            print(out.rstrip())
        assert not unexpected, distro_checks.unexpected_failures(
            where, image_name, unexpected
        )
        for unit in missing:
            gone = distro_checks.known_failure_gone(
                unit, where, image_name, phase, known_failed["notInImage"]
            )
            print(gone)
            gone_failures.append(gone)
        for unit in sorted(failed.intersection(expected)):
            # What the unit logged since its latest start: the failed start
            # must have logged the known line, so that another failure of the
            # same unit does not pass for the known one.
            quoted = shlex.quote(unit)
            since = int(
                vm.succeed(f"systemctl show -P InactiveExitTimestampMonotonic {quoted}")
            )
            assert since > 0, f"{unit} failed {where} without a start time"
            messages = distro_checks.messages_since(
                vm.succeed(f"timeout 30 journalctl -q -b -u {quoted} -o json --no-pager"),
                since,
            )
            print(f"--- {unit} since its start {where}:\n" + "\n".join(messages))
            problem = distro_checks.failure_not_known(
                unit, where, image_name, expected[unit], messages
            )
            assert problem is None, problem


    def assert_quiet_kernel_log(where):
        # Neither PID 1's warning that a session drop-in is not readable by
        # all (which names the file), nor a failed unmount of the hidden
        # volume at a switch, is in the kernel log.
        for command in (
            "dmesg | grep -F world-inaccessible | grep -F overlay-runtime",
            "dmesg | grep -F 'Failed unmounting mnt-data.mount'",
        ):
            rc, out = vm.execute(command)
            assert rc != 0, f"{where}: {command}:\n{out}"


    def rehearse(args):
        # Captured under /run (tmpfs): nothing the test reads back may land
        # on the decoy disk the scan reads.
        command = f"{nails_cmd} --json rehearse {args}"
        vm.succeed(
            "bash -c "
            + shlex.quote(
                f"set +e; {command} > /run/rehearse.out 2> /run/rehearse.err;"
                " printf '%s' $? > /run/rehearse.rc"
            )
        )
        rc = int(vm.succeed("cat /run/rehearse.rc"))
        out = vm.succeed("cat /run/rehearse.out")
        err = vm.succeed("cat /run/rehearse.err")
        vm.succeed("rm -f /run/rehearse.out /run/rehearse.err /run/rehearse.rc")
        return rc, out, err


    # Each probe is bounded on its own, so a wedged PID 1 or journald still lets
    # the next one (and the test's own failure) run.
    pid1_probes = (
        ("PID 1 round trip", "time -p timeout 30 systemctl show -p Version"),
        ("system state", "timeout 30 systemctl is-system-running"),
        ("queued jobs", "timeout 30 systemctl list-jobs --no-pager"),
        ("failed units", "timeout 30 systemctl --failed --no-pager"),
        ("soft-reboots", "timeout 30 systemctl show -p SoftRebootsCount"),
        ("PID 1 sockets", "ls -l /run/systemd/private /run/systemd/notify"),
        ("root and /usr mounts", "grep -E ' / (/|/usr|/run) ' /proc/self/mountinfo"),
        (
            "PID 1 messages",
            "timeout 30 journalctl -b _PID=1 -n 150 --no-pager -o short-monotonic",
        ),
        (
            "warnings",
            "timeout 30 journalctl -b -p warning -n 200 --no-pager -o short-monotonic",
        ),
        ("kernel tail", "dmesg | tail -n 40"),
    )


    def probe_report(where):
        # Where the PID-file probe stands, for the log. Never fails.
        _, out = vm.execute(
            "{ systemctl show --property=ActiveState --property=MainPID pidfile-probe.service; "
            + "ls -la /run/pidfile-probe; cat /run/pidfile-probe/pid; "
            + "journalctl -b -u pidfile-probe.service --no-pager -o short-monotonic | tail -n 20; } 2>&1",
            check_return=False,
        )
        print(f"=== PID-file probe: {where} ===\n{out.rstrip()}")


    def pid1_health(label):
        # A self-explaining log: what PID 1, its job queue and the journal looked
        # like at this point, and which units it started or stopped. Never fails.
        report = [f"=== PID 1 health: {label} ==="]
        for title, command in pid1_probes:
            _, out = vm.execute(f"{{ {command}; }} 2>&1", check_return=False, timeout=120)
            report.append(f"--- {title}: {command}\n{out.rstrip()}")
        print("\n".join(report))


    vm.wait_for_unit("multi-user.target")
    vm.succeed(f"test -x {nails}")

    with subtest("platform detection selects the overlay-only FHS backend"):
        # `nails init` reports the detected host. A supported FHS host has no
        # NixOS config layer, so init prints the overlay-only skip note naming
        # the host id -- proof the overlay-only backend was chosen and not NixOS
        # or the unsupported refusal path.
        print(f"decoy os-release id: {os_id}")
        # init refuses a target that is not a volume of its own, and anything
        # it writes must stay off the decoy disk that the forensic check below
        # images, so it gets a throwaway tmpfs of its own below /run.
        vm.succeed(
            "mkdir -p /run/nails-init-probe && "
            "mount -t tmpfs -o size=16m,mode=0700 probe /run/nails-init-probe"
        )
        init_out = vm.succeed(f"{nails} init /run/nails-init-probe 2>&1")
        vm.succeed("umount /run/nails-init-probe && rmdir /run/nails-init-probe")
        assert "overlay-only" in init_out, (
            f"expected the overlay-only backend to be selected, got: {init_out}"
        )

    with subtest("capture the decoy baseline image"):
        # The decoy as booted, before NAILS or any test preparation touched it.
        # A stock image legitimately contains some registry tokens (generic words
        # such as "reports"), so the leak check below diffs against this set,
        # exactly as the NixOS forensic tests do. Imaging ends this QEMU process;
        # the lifecycle restarts in a fresh one, which boots the pristine image
        # again: the same decoy. A soft-reboot never restarts QEMU.
        registry_tokens = load_registry_tokens()
        baseline = image_decoy("baseline")
        baseline_registry_hits = disk_forensics.run_strings_scan(baseline, registry_tokens)
        os.remove(baseline)
        vm.start()
        prepare_boot()

    with subtest("decoy-persistence preflight refuses a persistent journal"):
        # Prepare everything else first, so the only finding left is the decoy
        # posture: the check gates on a mounted hidden root and reads the config.
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        # The stock images keep a persistent journal (Storage=auto with an
        # on-disk /var/log/journal); create the directory in case an image ever
        # stops shipping it, so the refusal path is always exercised.
        vm.succeed("mkdir -p /var/log/journal")
        # check stages nothing, so its refusal is a non-zero exit with the
        # reason and leaves nothing to undo.
        refusal = vm.fail(f"{nails_cmd} check --overlay-only 2>&1")
        assert "journal" in refusal.lower() or "persist" in refusal.lower(), (
            f"expected a decoy-persistence refusal, got: {refusal}"
        )
        # Accepting the risk explicitly, or making the decoy amnesic, both make
        # the check pass; the suite exercises the real fix.
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        vm.succeed(f"{nails_cmd} check --overlay-only")

    with subtest("the platform row warns about every unit the image is known to fail"):
        # One way only: while the list names a unit, the row warns and names
        # it. The row never has to pass, so a warning broader than the list,
        # or one given for another reason, is fine.
        report = json.loads(vm.succeed(f"{nails_cmd} check --overlay-only --json"))
        row = next((r for r in report["data"]["checks"] if r["name"] == "platform"), None)
        print(f"platform row on {image_name}: {row}")
        if known_failed is not None:
            problem = distro_checks.platform_row_problem(row, known_failed, image_name)
            assert problem is None, problem

    with subtest("blk-availability.service runs on the decoy as lvm2 ships it"):
        # The image's own unit where lvm2 is installed (Ubuntu). Debian's
        # generic cloud image has dmsetup without lvm2: it gets the unit as
        # Debian's lvm2 package ships it. The choice goes by the unit file.
        ships_unit = vm.execute("systemctl cat blk-availability.service")[0] == 0
        blk_availability = ships_unit or vm.execute("test -x /usr/sbin/blkdeactivate")[0] == 0
        if blk_availability:
            if not ships_unit:
                vm.succeed(
                    "printf %s "
                    + shlex.quote(blk_availability_unit)
                    + " > /etc/systemd/system/blk-availability.service"
                )
            print(vm.succeed("systemctl cat blk-availability.service"))
            vm.succeed("systemctl daemon-reload && systemctl enable --now blk-availability.service")
            state = unit_state("blk-availability.service")
            assert state == {"LoadState": "loaded", "ActiveState": "active"}, state
            stop = blk_availability_stop()
            assert blkdeactivate in stop, stop
        else:
            print("this image has neither lvm2 nor dmsetup: no blk-availability.service")

    with subtest("a decoy service keeps a PID file in /run"):
        vm.succeed(
            "mkdir -p /usr/local/sbin && printf %s "
            + shlex.quote(pidfile_probe_script)
            + " > /usr/local/sbin/pidfile-probe && chmod 0755 /usr/local/sbin/pidfile-probe"
        )
        vm.succeed(
            "printf %s "
            + shlex.quote(pidfile_probe_unit)
            + " > /etc/systemd/system/pidfile-probe.service"
        )
        vm.succeed("systemctl daemon-reload && systemctl enable --now pidfile-probe.service")
        vm.wait_until_succeeds("test -s /run/pidfile-probe/pid", timeout=30)
        probe_report("the decoy")
        decoy_masked_units = load_states(hidden_masked_units)
        print(f"units the hidden root masks, on the decoy: {decoy_masked_units}")
        assert_nothing_requires(
            [unit for unit, state in decoy_masked_units.items() if state != "not-found"]
        )
        assert_gpt_auto_masked("the decoy", masked=False)

    with subtest("the decoy's failed units before the first switch"):
        # None where the image table lists what the image is known to fail.
        # Read before the Ctrl+C below, whose cancelled activation fails a
        # unit of its own.
        check_failed_units("on the decoy before the first switch")
        # The units the release's warning names that the image does not
        # install are still not in it, so the warning still covers what this
        # run cannot see.
        for unit in (known_failed or {}).get("notInImage", []):
            state = vm.succeed(f"systemctl show -P LoadState {shlex.quote(unit)}").strip()
            print(f"{unit} on the decoy: {state}")
            assert state == "not-found", distro_checks.now_in_image(unit, image_name)

    with subtest("Ctrl+C during the pre-flight checks cancels the activation"):
        # A CPU quota stretches the activation, so the interrupt reaches it
        # while it runs its checks; no child process of it dies with the
        # signal there, so only the activation's own checkpoints can stop it.
        log = "/run/cancelled-activation.log"
        vm.succeed(
            "systemd-run --unit=cancelled-activation --remain-after-exit "
            + "--property=CPUQuota=5% "
            + f"--property=StandardOutput=file:{log} --property=StandardError=file:{log} "
            + f"{nails_cmd} activate -y"
        )
        # The residue baseline, the last step before the checks, is written.
        vm.wait_until_succeeds("ls /mnt/data/reports/activation-residue-*.json", timeout=600)
        vm.succeed("systemctl kill --signal=SIGINT cancelled-activation.service")
        vm.wait_until_succeeds(
            "test \"$(systemctl show -P ExecMainExitTimestampMonotonic "
            + "cancelled-activation.service)\" != 0",
            timeout=600,
        )
        print(vm.succeed(f"cat {log}"))
        status = vm.succeed("systemctl show -P ExecMainStatus cancelled-activation.service").strip()
        assert status == "130", f"the cancelled activation exited {status}"
        vm.fail("mountpoint -q /run/nextroot")
        vm.fail("test -e /run/overlay-runtime")
        vm.fail("test -e /run/systemd/system/systemd-soft-reboot.service.d")
        session.assert_decoy_root(vm)
        place = json.loads(vm.succeed(f"{nails_cmd} status --json"))["data"]["place"]
        assert place == "decoy", f"after the cancel: {place}"
        vm.succeed("systemctl reset-failed cancelled-activation.service || true")
        vm.succeed("rm -f /mnt/data/reports/activation-residue-*.json")

    with subtest("activation soft-reboots into the whole-root overlay"):
        follow(f"{nails_cmd} activate -y > /mnt/data/activate.log 2>&1", "activate")
        print(vm.succeed("cat /mnt/data/activate.log || true"))
        pid1_health("after the first activation")
        session.assert_hidden_root(vm)
        check_failed_units("in the first hidden session", "hiddenSession")
        if blk_availability:
            assert_guarded_blk_availability("the first session")
        assert_quiet_kernel_log("the first session")
        # The units the hidden root does not need are masked there where the
        # decoy has them, and so is the GPT auto-generator.
        for unit, state in load_states(hidden_masked_units).items():
            if decoy_masked_units[unit] != "not-found":
                assert state == "masked", f"{unit} in the hidden root: {state}"
        assert_gpt_auto_masked("the first session", masked=True)
        vm.wait_until_succeeds("test -s /run/pidfile-probe/pid", timeout=30)
        probe_report("the first hidden session")
        # The hidden volume is still at its path, with the binary's log and
        # the upper on it.
        vm.succeed("mountpoint -q /mnt/data")
        status = json.loads(vm.succeed(f"{nails_cmd} status --json"))["data"]
        assert status["place"] == "hidden", f"expected the hidden session, got {status}"
        # Every hidden write, /usr included, lands on the hidden root. Where it
        # lands depends on the decoy's own shape: a tree that is a filesystem of
        # its own (a btrfs subvolume on Fedora or Arch) is overlaid separately,
        # so its upper is named after the mount unit rather than sitting under
        # the root upper. The mount-aware helper resolves that from the live
        # mount table, so on a single-root image (Debian, Ubuntu) it yields the
        # root upper exactly as before.
        hidden_mounts = distro_checks.parse_mount_targets(
            vm.succeed("findmnt -rn -o TARGET")
        )
        for tree in canary_trees:
            name = distro_checks.canary_name(tree)
            vm.succeed(f"echo NAILS_CANARY_{tree} > /{tree}/{name}")
            upper = distro_checks.canary_upper("/mnt/data", tree, hidden_mounts)
            vm.succeed(f"test -s {shlex.quote(upper)}")
        vm.succeed("sync")

    with subtest("the boot filesystems are read-only in the hidden root"):
        # Every mounted boot filesystem -- /boot, the ESP at /boot/efi and a
        # unified /efi -- must be read-only to the hidden session, so a hidden
        # write can never reach the decoy's boot partition. Which of them a
        # distribution mounts differs; the helper picks out the mounted ones.
        boot_mounts = distro_checks.boot_mounts(
            distro_checks.parse_mount_targets(vm.succeed("findmnt -rn -o TARGET"))
        )
        if boot_mounts:
            for target in boot_mounts:
                probe = f"{target}/nails-should-fail"
                err = vm.fail(f"touch {shlex.quote(probe)} 2>&1")
                assert "read-only" in err.lower(), (
                    f"{target} took a hidden write: {err}"
                )
            print(f"boot filesystems read-only in the hidden root: {boot_mounts}")
        else:
            print("this image mounts no separate boot filesystem")

    with subtest("the hidden overlays pin the forensic feature options"):
        # NAILS pins index=off,metacopy=off,redirect_dir=nofollow on every
        # overlay it mounts, so an overlay can never diverge from a plain
        # copy-up. The kernel echoes a feature option only when it differs from
        # its own compiled default, and no kernel of the image table defaults
        # redirect_dir to nofollow (Debian's and Ubuntu's default to follow,
        # Arch's to on): every overlay NAILS mounted, told apart by its upper
        # on the hidden volume, must show redirect_dir=nofollow, and none may
        # show a dangerous state (distro_checks.overlay_option_violations).
        # The kernel-tier twin is live_overlay_pins_the_feature_options_off.
        overlays = distro_checks.nails_overlays(
            distro_checks.parse_findmnt_pairs(
                vm.succeed("findmnt -rn -t overlay -o TARGET,OPTIONS")
            ),
            "/mnt/data",
        )
        # The root overlay was found and its options read back (not an empty
        # field), so the check below tests real option strings.
        assert "/" in dict(overlays), f"the root overlay is not NAILS's: {overlays}"
        violations = distro_checks.overlay_targets_with_violations(overlays)
        assert not violations, (
            f"overlays without the feature-option pins: {violations}"
        )
        print(f"overlay feature options pinned on: {[t for t, _ in overlays]}")

    with subtest("emergency soft-reboots back to the plain decoy"):
        follow(f"{ram_nails_cmd} emergency --json > /dev/null", "emergency")
        pid1_health("after emergency")
        session.assert_decoy_root(vm)
        check_failed_units("on the decoy after the emergency", "afterReturn")
        vm.fail("mountpoint -q /mnt/data")
        for tree in canary_trees:
            vm.fail(f"test -e /{tree}/nails-canary-{tree}")
        vm.succeed("touch /usr/rw-probe && rm -f /usr/rw-probe")
        # The emergency killed the hidden copy of the PID-file service, which
        # left its file; the way back removed it, so the decoy's copy starts.
        probe_report("after the emergency")
        vm.wait_for_unit("pidfile-probe.service")
        assert load_states(hidden_masked_units) == decoy_masked_units, (
            "the decoy's own units again"
        )
        assert_gpt_auto_masked("after the emergency", masked=False)
        assert_quiet_kernel_log("after the emergency")

    with subtest("a second session ends with deactivate"):
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        boot_mounts: list[str] = []
        if blk_availability:
            # The first session carried /boot and the ESP below the hidden
            # volume, and those binds kept blkdeactivate from unmounting it.
            # With neither mounted, as on a BIOS server without a separate
            # /boot (where the stop did unmount it), the session carries
            # nothing there. The decoy mounts both again from its fstab on the
            # way back.
            boot_mounts = [
                target
                for target in vm.succeed("findmnt -rn -o TARGET").split()
                if target in ("/boot", "/boot/efi", "/efi")
            ]
            for target in reversed(boot_mounts):
                vm.succeed(f"umount {target}")
        follow(f"{nails_cmd} activate -y > /mnt/data/activate-2.log 2>&1", "activate-2")
        session.assert_hidden_root(vm)
        check_failed_units("in the second hidden session", "hiddenSession")
        vm.succeed("mountpoint -q /mnt/data && test -s /mnt/data/activate-2.log")
        if blk_availability:
            # The unit runs in the hidden session too; its stop stays cleared
            # until the way back has switched.
            assert_guarded_blk_availability("the second session")
        probe_report("the second hidden session")
        assert_gpt_auto_masked("the second session", masked=True)
        # The rehearsal's first step, and the refusal of a scan in the
        # planting session.
        rc, out, err = rehearse("plant --user root")
        assert rc == 0, (rc, out, err)
        planted = json.loads(out)["data"]
        assert planted["next_step"].startswith("Step 2 of 3"), planted
        assert any(
            c["kind"] == "overlay-file" and "skipped" not in c for c in planted["channels"]
        ), planted["channels"]
        rc, out, err = rehearse("scan")
        assert rc == 6, (rc, out, err)
        assert json.loads(out)["error"]["code"] == "same_boot", out
        follow(f"{nails_cmd} deactivate -y", "deactivate")
        session.assert_decoy_root(vm)
        check_failed_units("on the decoy after deactivate", "afterReturn")
        vm.fail("mountpoint -q /mnt/data")
        vm.fail("test -e /run/overlay-runtime")
        # A LUKS-backed hidden root's mapping closed itself (a loop-backed one
        # has none).
        vm.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
        if blk_availability:
            # The decoy's own shutdown deactivates its block devices again.
            vm.fail("test -e /run/systemd/system/blk-availability.service.d")
            state = unit_state("blk-availability.service")
            assert state == {"LoadState": "loaded", "ActiveState": "active"}, state
            stop = blk_availability_stop()
            assert blkdeactivate in stop, stop
            for target in boot_mounts:
                vm.succeed(f"mountpoint -q {target}")
        probe_report("after deactivate")
        assert_gpt_auto_masked("after deactivate", masked=False)
        vm.wait_for_unit("pidfile-probe.service")
        assert_quiet_kernel_log("after deactivate")

    with subtest("the rehearsal's scan runs on the decoy in the planting boot"):
        # As the operator would: unlock and mount the hidden volume again.
        vm.succeed("""${hiddenRoot.reopenHiddenRoot}""")
        token = json.loads(vm.succeed("cat /mnt/data/rehearse/state.json"))["token"]
        print(vm.succeed("cat /proc/sys/kernel/random/boot_id; systemctl --version | head -1"))
        rc, out, err = rehearse("status")
        assert rc == 0, (rc, out, err)
        next_step = json.loads(out)["data"]["next_step"]
        assert next_step.startswith("Step 3 of 3"), next_step
        rc, out, err = rehearse("scan")
        assert token not in out + err, "scan printed the token"
        assert rc == 0, (rc, out, err)
        result = json.loads(out)["data"]["scan"]
        assert result["devices"], result
        for device in result["devices"]:
            assert "error" not in device, device
            assert device["hits"] == [], device
        assert any(d["bytes_scanned"] > 0 for d in result["devices"]), result
        print(f"clean rehearsal scan of {[d['device'] for d in result['devices']]}")
        # No `rehearse reset`: the root's image file sits on a tmpfs the
        # soft-reboot detached, so the attach gate cannot tell where it lives
        # and refuses writes there. The scan writes nothing to need it, and the
        # rehearsal state goes with the RAM-backed volume.
        vm.succeed("""${hiddenRoot.closeHiddenRoot}""")

    with subtest("decoy disk-image leak check: no hidden canaries, positive control caught"):
        canary_tokens = [f"NAILS_CANARY_{tree}" for tree in canary_trees]

        # Null control: image the decoy root after the whole lifecycle and prove
        # no canary leaked onto it, and no registry token appeared that the
        # baseline did not already carry.
        clean = image_decoy("clean")
        # One pass over the multi-GB image for both token sets.
        clean_hits = disk_forensics.run_strings_scan(clean, canary_tokens + registry_tokens)
        leaked = clean_hits & set(canary_tokens)
        assert not leaked, f"decoy disk leaked hidden canaries: {sorted(leaked)}"
        new_registry = (clean_hits & set(registry_tokens)) - baseline_registry_hits
        assert not new_registry, (
            f"the lifecycle introduced registry tokens onto the decoy image: "
            f"{sorted(new_registry)}"
        )
        os.remove(clean)

        # Positive control: a token written straight onto the decoy root (no
        # overlay) must be found, so a scanner that silently finds nothing fails.
        # This boot starts from the pristine image, so /var/tmp is a plain
        # decoy-disk directory.
        vm.start()
        vm.wait_for_unit("multi-user.target")
        poison = "NAILS_POSCTL_distro"
        vm.succeed(f"printf '%s\\n' {poison} > /var/tmp/{poison}")
        vm.succeed("sync")
        positive = image_decoy("positive")
        found = disk_forensics.run_strings_scan(positive, [poison])
        assert found == {poison}, (
            f"positive control failed: the scanner did not see the planted token ({found})"
        )

    with subtest("every failure the image is known to show still happens"):
        assert not gone_failures, "\n\n".join(gone_failures)
  '';
}
