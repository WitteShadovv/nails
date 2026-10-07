# The portable smoke scenario, generated once per distribution.
#
# nix/distro-tests/default.nix maps this function over the image table, so every
# distribution runs the same lifecycle on the NixOS test driver through
# nix-vm-test. The scenario proves the whole-root session end to end on a
# non-NixOS host (systemd >= 254): activation soft-reboots the stock cloud image
# into an overlay of its own root, every hidden write (including /usr) lands on
# the hidden root, the ESP stays read-only, and deactivation and emergency
# soft-reboot back to the plain decoy without a trace on the decoy disk.
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
# `entry` is one value from images.nix.
entry:
distroVm.buildVmTest {
  inherit entry;

  sharedDirs.${binShare.tag} = {
    source = "${nails}/bin";
    inherit (binShare) target;
  };

  # Headroom for the RAM-backed hidden root next to a full cloud-image boot.
  memorySize = 2048;

  testScript = ''
    import json
    import os
    import shlex
    import sys

    # The NixOS suite's in-VM helper package, for following a soft-reboot.
    sys.path.insert(0, "${../../e2e-tests/py}")
    from nails_e2e import session  # noqa: E402
    import subprocess
    import time
    from typing import Any

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

    with subtest("platform detection selects the overlay-only Debian-family backend"):
        # `nails init` reports the detected host. A supported FHS host (Debian or
        # Ubuntu) has no NixOS config layer, so init prints the overlay-only skip
        # note naming the host id -- proof the Debian-family backend was chosen
        # and not NixOS or the unsupported refusal path.
        # init refuses a missing target, and anything it writes must stay off
        # the decoy disk that the forensic check below images, so it gets a
        # throwaway directory on the /run tmpfs.
        vm.succeed("mkdir -p /run/nails-init-probe")
        init_out = vm.succeed(f"{nails} init /run/nails-init-probe 2>&1")
        vm.succeed("rm -rf /run/nails-init-probe")
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
        # The check is read-only, so a refusal is a non-zero exit, not a side
        # effect.
        refusal = vm.fail(f"{nails_cmd} check --overlay-only 2>&1")
        assert "journal" in refusal.lower() or "persist" in refusal.lower(), (
            f"expected a decoy-persistence refusal, got: {refusal}"
        )
        # Accepting the risk explicitly, or making the decoy amnesic, both make
        # the check pass; the suite exercises the real fix.
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        vm.succeed(f"{nails_cmd} check --overlay-only")

    with subtest("activation soft-reboots into the whole-root overlay"):
        follow(f"{nails_cmd} activate -y > /mnt/data/activate.log 2>&1", "activate")
        print(vm.succeed("cat /mnt/data/activate.log || true"))
        pid1_health("after the first activation")
        session.assert_hidden_root(vm)
        status = json.loads(vm.succeed(f"{nails_cmd} status --json"))["data"]
        assert status["posture"] == "active", f"expected the hidden session, got {status}"
        # Every hidden write, /usr included, lands on the hidden root.
        for tree in canary_trees:
            vm.succeed(f"echo NAILS_CANARY_{tree} > /{tree}/nails-canary-{tree}")
            vm.succeed(f"test -s /mnt/data/root/upper/{tree}/nails-canary-{tree}")
        vm.succeed("sync")

    with subtest("the ESP is read-only in the hidden root"):
        esp = vm.succeed("findmnt -rn -o TARGET /boot/efi || true").strip()
        if esp:
            err = vm.fail("touch /boot/efi/nails-should-fail 2>&1")
            assert "read-only" in err.lower(), f"the ESP took a hidden write: {err}"
        else:
            print("this image mounts no ESP at /boot/efi")

    with subtest("emergency soft-reboots back to the plain decoy"):
        follow(f"{ram_nails_cmd} emergency --json > /dev/null", "emergency")
        pid1_health("after emergency")
        session.assert_decoy_root(vm)
        vm.fail("mountpoint -q /mnt/data")
        for tree in canary_trees:
            vm.fail(f"test -e /{tree}/nails-canary-{tree}")
        vm.succeed("touch /usr/rw-probe && rm -f /usr/rw-probe")

    with subtest("a second session ends with deactivate"):
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        follow(f"{nails_cmd} activate -y > /mnt/data/activate-2.log 2>&1", "activate-2")
        session.assert_hidden_root(vm)
        follow(f"{nails_cmd} deactivate -y", "deactivate")
        session.assert_decoy_root(vm)
        vm.fail("mountpoint -q /mnt/data")
        vm.fail("test -e /run/overlay-runtime")

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
  '';
}
