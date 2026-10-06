# The portable smoke scenario, generated once per distribution.
#
# nix/distro-tests/default.nix maps this function over the image table, so every
# distribution runs the same lifecycle on the NixOS test driver through
# nix-vm-test. The scenario proves the overlay-only backend end to end on a
# non-NixOS host and -- the point of a VM tier over a container one -- that a
# hidden-session write cannot reach the decoy's read-only system trees.
#
# The host-side disk-image forensic scanners are shared verbatim with the NixOS
# suite (nix/e2e-tests/lib/disk_forensics.py): they run on the NixOS test driver,
# not in the guest, so they are distribution-agnostic.
#
# nix-vm-test specifics the script is built around (see lib/distro-vm.nix):
#
#   - The machine is `vm`.
#   - The disk is the store image under QEMU `-snapshot`: guest writes vanish
#     when QEMU exits. The lifecycle therefore runs in one QEMU process started
#     with `allow_reboot=True`, so the deactivation reboot keeps the disk, and
#     each forensic image is taken by first mirroring the live disk into
#     `<state_dir>/vm.qcow2` -- where `disk_forensics.root_image` looks -- and
#     then letting `disk_forensics.snapshot` shut down and convert it as usual.
#   - The 9p share with the binary is mounted only once before the script runs,
#     and /run (config, hidden-root backing) is wiped by every reboot, so every
#     boot goes through `prepare_boot()`.
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
    import subprocess
    import threading
    import time
    from typing import Any

    ${diskForensics.pythonSetup}

    nails = "${binShare.target}/nails"
    # On the /run tmpfs: never on the decoy disk, and gone after every reboot,
    # so prepare_boot() rewrites it.
    config = "/run/nails-smoke.toml"
    nails_cmd = f"{nails} --config {shlex.quote(config)}"

    # The trees the FHS backend overlays. /usr is deliberately absent: on a
    # Debian-family host /usr (and the other core binary roots) is never
    # overlaid -- activation refuses it -- but kept read-only by a bind-remount
    # for the whole session, which the /usr subtest below asserts.
    overlay_trees = ("home", "etc", "srv", "opt", "var", "tmp")


    def write_config():
        overlays = "".join(
            f"""
    [[overlays]]
    name = "{tree}"
    lower = "/{tree}"
    upper = "/mnt/data/{tree}"
    work = "/mnt/data/.work/{tree}"
    target = "/{tree}"
    """
            for tree in overlay_trees
        )
        vm.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"
    %s
    EOF"""
            % (shlex.quote(config), overlays)
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


    def wait_for_guest_reboot(start_index, unit, timeout=300):
        # The guest reboots inside the same QEMU process (allow_reboot), so
        # there is no process exit to wait on: watch the kernel's final console
        # line, then drop the stale shell so the next command reconnects to the
        # backdoor of the new boot.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if "reboot: Restarting system" in vm.get_console_log()[start_index:]:
                vm.connected = False
                return
            time.sleep(1)

        diagnostics: list[str] = []

        def collect():
            # The shell may be gone mid-shutdown and a read from it would block
            # forever, so this runs on a daemon thread with a bounded join.
            _, out = vm.execute(
                f"systemctl status {unit} --no-pager --full 2>&1; "
                + f"journalctl -u {unit} -b --no-pager -n 100 2>&1; "
                + "findmnt -rn -t overlay 2>&1 || true",
                check_return=False,
            )
            diagnostics.append(out)

        collector = threading.Thread(target=collect, daemon=True)
        collector.start()
        collector.join(60)
        raise AssertionError(
            f"the guest did not reboot within {timeout}s after {unit} started\n"
            + "".join(diagnostics)
            + "\n--- serial console tail ---\n"
            + "\n".join(vm.get_console_log().splitlines()[-80:])
        )


    def overlay_mounted(tree):
        return f"overlay on /{tree} type overlay" in vm.succeed("mount")


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
        # the lifecycle restarts with allow_reboot so the deactivation reboot
        # keeps the disk (a fresh start boots the pristine image again).
        registry_tokens = load_registry_tokens()
        baseline = image_decoy("baseline")
        baseline_registry_hits = disk_forensics.run_strings_scan(baseline, registry_tokens)
        os.remove(baseline)
        vm.start(allow_reboot=True)
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

    with subtest("overlay-only activation isolates the writable trees"):
        vm.succeed(f"{nails_cmd} activate --overlay-only --session keep -y")

        for tree in overlay_trees:
            assert overlay_mounted(tree), f"/{tree} is not overlaid"

        # /usr is kept read-only instead of overlaid.
        usr_options = vm.succeed("findmnt -rn -o OPTIONS /usr").split()
        assert usr_options and "ro" in usr_options[-1].split(","), (
            f"/usr is not mounted read-only: {usr_options}"
        )

        status = json.loads(vm.succeed(f"{nails_cmd} status --json"))["data"]
        assert status["state"]["kind"] == "active", f"expected active, got {status}"

        # Canaries written through the overlay land on the hidden root, never the
        # decoy disk; the forensic scan below proves they do not leak.
        for tree in overlay_trees:
            vm.succeed(f"echo NAILS_CANARY_{tree} > /{tree}/nails-canary-{tree}")

    with subtest("writes under /usr and /usr/local fail on the read-only system"):
        # The core binary roots are isolated: a hidden-session write there must
        # fail, or it would reach the decoy disk. EROFS is the expected errno.
        usr_err = vm.fail("touch /usr/nails-should-fail 2>&1")
        local_err = vm.fail("touch /usr/local/nails-should-fail 2>&1")
        for err in (usr_err, local_err):
            assert "read-only" in err.lower() or "erofs" in err.lower(), (
                f"expected a read-only-filesystem error, got: {err}"
            )

    with subtest("status, verify and emergency operate on the active session"):
        vm.succeed(f"{nails_cmd} status")

        # verify inspects the live host for NAILS artifacts; on an active session
        # it must report them (the active state and the mounted overlays) and
        # exit with the critical-findings code, 11.
        verify_rc, verify_out = vm.execute(f"{nails_cmd} verify --json")
        verify = json.loads(verify_out)["data"]
        assert verify_rc == 11 and verify["status"] == "critical", (
            f"expected verify to flag the active session, got rc={verify_rc}: {verify}"
        )
        messages = " ".join(finding["message"] for finding in verify["findings"])
        assert "ACTIVE" in messages or "overlay" in messages.lower(), (
            f"verify did not name the active session: {verify['findings']}"
        )

        # Emergency starts immediately; a countdown is opt-in. It detaches every
        # overlay and lifts the read-only guard but leaves the hidden root
        # mounted (no --lock-backend).
        emergency = json.loads(vm.succeed(f"{nails_cmd} emergency --json"))["data"]
        assert emergency["status"] == "complete", f"emergency did not complete: {emergency}"
        for tree in overlay_trees:
            assert not overlay_mounted(tree), f"/{tree} is still overlaid after emergency"
        status = json.loads(vm.succeed(f"{nails_cmd} status --json"))["data"]
        assert status["state"]["kind"] == "inactive", (
            f"expected inactive after emergency, got {status}"
        )

    with subtest("deactivation with a reboot restores the decoy"):
        # Re-activate so deactivate has a session to restore (the hidden root is
        # still mounted after the emergency, so setup reuses it), then deactivate
        # and let it reboot. Deactivation ends the session and reboots the
        # guest, so it runs as its own unit, not through the backdoor shell it
        # would take down mid-command. After the reboot no overlay is mounted.
        write_config()
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed(f"{nails_cmd} activate --overlay-only --session keep -y")
        assert overlay_mounted("home"), "re-activation did not overlay /home"
        console_mark = len(vm.get_console_log())
        vm.succeed(
            "systemd-run --unit smoke-teardown --no-block --service-type=exec "
            + f"{nails_cmd} deactivate -y"
        )
        wait_for_guest_reboot(console_mark, "smoke-teardown")
        prepare_boot()
        for tree in overlay_trees:
            assert not overlay_mounted(tree), f"an overlay on /{tree} survived the reboot"
        vm.fail("mountpoint -q /mnt/data")

    with subtest("negative control: a writable /usr is caught"):
        # Proves the /usr assertion above is real: with no read-only guard a write
        # succeeds, so the assertion would have failed had isolation failed. The
        # probe name is neutral, since it lands on the imaged decoy disk.
        vm.succeed("touch /usr/rw-probe && rm -f /usr/rw-probe")

    with subtest("decoy disk-image leak check: no hidden canaries, positive control caught"):
        canary_tokens = [f"NAILS_CANARY_{tree}" for tree in overlay_trees]

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
