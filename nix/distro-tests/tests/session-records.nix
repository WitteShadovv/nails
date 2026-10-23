# A cross-distro regression test for the decoy's login and boot records.
#
# A whole-root session returns to the decoy through a soft-reboot, and the
# decoy's own boot writers record that start. On Debian with wtmpdb the boot row
# would be named "soft-reboot" (or, kept from the bus within five minutes of
# uptime, dated to the decoy's cold boot); on a service manager that keeps the
# userspace start time across a soft-reboot (systemd 255 and earlier, classic
# wtmp), the boot record would carry the decoy's first boot time, so the file
# would hold a boot stamped before the shutdown that precedes it. Neither is
# written by an ordinary power cycle. The way back neutralises both; this test
# proves it the way the failure really happens.
#
# The flow on one QEMU process (so the records accumulate on one decoy disk):
#
#   1. install              -- the record package the distribution ships but the
#                              cloud image omits (wtmpdb on Debian);
#   2. a power cycle        -- a real reboot, with the record writers installed:
#                              the reference every assertion compares with;
#   3. a NAILS session      -- activate, stay in the hidden session until the
#                              kernel has been up for more than five minutes
#                              (wtmpdb's threshold), then deactivate;
#   4. assertions           -- the session added one boot, as a power cycle
#                              does: named reboot, stamped at the way back, no
#                              earlier than anything before it, and no crash; the
#                              pieces the way back left in /run are gone and /run
#                              is noexec again where the decoy had it so;
#   5. a plain soft-reboot  -- no NAILS: the positive control, which must still
#                              carry the trace, so a vacuous pass is impossible.
#
# Records are read live in the guest and carried to the host-side readers in
# nix/e2e-tests/lib/records.py (reading live keeps install, power cycle and
# session in one QEMU process; a disk image would end QEMU and the next boot would
# be the pristine cloud image again -- see lib/distro-vm.nix). Like the smoke
# suite it needs the guest's network to install a record package on Debian, so it
# runs on nix-vm-test's `driver` target, on a KVM host under the heavy-job lock,
# never in CI.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  distroVm = import ../lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  hiddenRoot = import ../lib/hidden-root.nix;

  # The record readers, shared verbatim with the fast-lane unit tests.
  recordsModule = pkgs.writeTextDir "records.py" (builtins.readFile ../../e2e-tests/lib/records.py);

  inherit (self.packages.x86_64-linux) nails;

  binShare = {
    tag = "tools";
    target = "/run/tools";
  };
in
# `cfg` is one scenario:
#   entry       {distro,image,release} as in images.nix;
#   install     shell run once after the first boot, to add the record package
#               the distribution ships but the cloud image omits (may be empty);
#   assertKind  "wtmpdb" (Debian's SQLite boot writer names soft-reboots) or
#               "classic-wtmp" (the boot record's time can be backdated).
cfg:
let
  install = cfg.install or "";
  inherit (cfg) assertKind;
in
distroVm.buildVmTest {
  inherit (cfg) entry;
  target = "driver";

  sharedDirs.${binShare.tag} = {
    source = "${nails}/bin";
    inherit (binShare) target;
  };

  # A full cloud-image boot, an overlay root in RAM and a hidden volume on a
  # tmpfs; 3 GiB leaves margin for all three at once.
  memorySize = 3072;

  testScript = ''
    import os
    import shlex
    import sys
    import tempfile
    from typing import Any

    sys.path.insert(0, "${../../e2e-tests/py}")
    from nails_e2e import session  # noqa: E402

    # Put the record readers on the path and import them (same module the
    # fast-lane unit tests lock).
    sys.path.insert(0, "${recordsModule}")
    import records  # ty: ignore[unresolved-import]  # noqa: E402

    nails = "${binShare.target}/nails"
    config = "/run/nails-records.toml"
    nails_cmd = f"{nails} --config {shlex.quote(config)}"
    assert_kind = ${builtins.toJSON assertKind}
    install_script = ${builtins.toJSON install}

    # wtmpdb names a boot soft-reboot, kept from the bus, once the kernel has
    # been up for more than this; the way back must happen past it.
    WTMPDB_UPTIME_LIMIT = 300.0

    # What the way back leaves in /run for the decoy's first start; the
    # reconcile step removes all of it.
    WAY_BACK_PIECES = [
        "/run/overlay-runtime-boot",
        "/run/systemd/system/overlay-runtime-boot.service",
        "/run/systemd/system/multi-user.target.wants/overlay-runtime-boot.service",
        "/run/systemd/system/wtmpdb-update-boot.service.d/zz-overlay-runtime.conf",
    ]


    def write_config():
        vm.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    minimum_space_mb = 100
    EOF"""
            % shlex.quote(config)
        )


    def prepare_boot():
        # Everything a soft-reboot drops: the once-mounted 9p binary share and
        # the /run config. The record files live on the decoy root and persist.
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


    def boot_id() -> str:
        return vm.succeed("cat /proc/sys/kernel/random/boot_id").strip()


    def guest_clock() -> float:
        return float(vm.succeed("date +%s.%N").strip())


    def run_noexec() -> bool:
        options = vm.succeed("findmnt -no OPTIONS /run").strip()
        return "noexec" in options.split(",")


    def guest_bytes(path: str) -> bytes | None:
        # Read one record file out of the guest as hex (od): coreutils only, and
        # line-safe for binary content. The command always exits 0 (an `if`), so
        # it does not rely on the driver's return code, which `execute` reports
        # as -1 whenever check_return is off.
        q = shlex.quote(path)
        out = vm.succeed(
            f"if test -s {q}; then od -An -v -tx1 {q} | tr -d ' \\n'; echo; "
            f"else echo; fi"
        )
        hexstr = out.splitlines()[0].strip() if out.splitlines() else ""
        if not hexstr:
            return None
        try:
            return bytes.fromhex(hexstr)
        except ValueError:
            return None


    def wtmpdb_path() -> str:
        # wtmpdb's database is not always where upstream puts it; find it.
        _, found = vm.execute(
            "find /var -name 'wtmp*.db' 2>/dev/null | head -n1", check_return=False
        )
        return found.strip() or "/var/log/wtmp.db"


    def listing() -> str:
        _, out = vm.execute(
            "last -F 2>/dev/null | head -n 20; echo ---; "
            "wtmpdb last 2>/dev/null | head -n 20 || true",
            check_return=False,
        )
        return out.rstrip()


    def capture(label: str) -> records.RecordCapture:
        # records.DEFAULT_PATHS is tree-relative (no leading slash); the guest
        # reads need absolute paths. wtmpdb's database is found at run time.
        guest_paths = {key: "/" + rel for key, rel in records.DEFAULT_PATHS.items()}
        guest_paths["wtmpdb"] = wtmpdb_path()
        tree = tempfile.mkdtemp(prefix=f"nails-records-{label}-")
        for key, guest_path in guest_paths.items():
            data = guest_bytes(guest_path)
            if data is None:
                continue
            dest = os.path.join(tree, records.DEFAULT_PATHS[key])
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(data)
        cap = records.capture_from_tree(label, tree)
        print(f"=== RECORD STAGE {label} ===\n{listing()}")
        return cap


    def follow(trigger: str, label: str) -> None:
        # A soft-reboot keeps the kernel: the boot ID must not change, or a full
        # reboot came instead and the records would read as a power cycle for
        # the wrong reason.
        before = boot_id()
        session.follow_soft_reboot(vm, trigger, label)
        assert boot_id() == before, f"{label}: the kernel restarted instead"
        prepare_boot()


    def power_cycle(label: str) -> None:
        # QEMU runs with -no-reboot, so a reboot would end it and the disk with
        # it; let this one reboot reset the machine instead, then put that back
        # so a full reboot in place of a soft-reboot still ends the test.
        before = boot_id()
        qmp("set-action", {"reboot": "reset"})
        try:
            session.follow_soft_reboot(vm, "systemctl reboot", label)
        finally:
            qmp("set-action", {"reboot": "shutdown"})
        assert boot_id() != before, f"{label}: the kernel did not restart"
        prepare_boot()


    def wait_for_reconcile() -> None:
        # The reconcile one-shot runs before multi-user.target and removes its
        # own directory; waiting for it gone makes the capture deterministic.
        vm.execute(
            "timeout 60 bash -c "
            "'while test -e /run/overlay-runtime-boot; do sleep 1; done'",
            check_return=False,
        )


    # --- the regression -----------------------------------------------------

    vm.wait_for_unit("multi-user.target")
    prepare_boot()

    if install_script:
        with subtest("install the distribution's record package"):
            print(vm.succeed(install_script))

    with subtest("a power cycle with the record writers installed (the reference)"):
        power_cycle("power-cycle")
        reference = capture("power-cycle-reference")
        decoy_noexec = run_noexec()
        # How the decoy's own tool lists the boots now; the session may add
        # no line it reads as a soft-reboot or a crash.
        reference_listing = vm.succeed("wtmpdb last -x 2>/dev/null || true")
        if assert_kind == "wtmpdb":
            assert any(
                records.WTMPDB_BOOT_TIME == row.get("Type")
                and row.get("User") == "reboot"
                for row in reference.wtmpdb
            ), f"the power cycle wrote no wtmpdb reboot row: {reference.wtmpdb}"
        else:
            assert records.boot_record_times(reference.wtmp), (
                f"the power cycle wrote no classic-wtmp boot record: {reference.wtmp}"
            )

    with subtest("a NAILS session past five minutes of uptime, then the way back"):
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        follow(f"{nails_cmd} activate -y > /mnt/data/activate.log 2>&1", "activate")
        session.assert_hidden_root(vm)
        # Work in the session until the kernel has been up past wtmpdb's
        # threshold, as any real session does: below it, a writer kept from
        # the bus dates the boot to the cold boot instead.
        vm.succeed(
            "timeout 600 bash -c 'while [ $(cut -d. -f1 /proc/uptime) -le "
            f"{int(WTMPDB_UPTIME_LIMIT) + 30} ]; do sleep 5; done'"
        )
        uptime = session.guest_uptime(vm)
        assert uptime > WTMPDB_UPTIME_LIMIT, f"uptime {uptime} s at the way back"
        before_way_back = guest_clock()
        follow(f"{nails_cmd} deactivate -y", "deactivate")
        session.assert_decoy_root(vm)
        wait_for_reconcile()
        after_way_back = guest_clock()
        window = (before_way_back, after_way_back)
        print(f"=== the way back happened within {window} at uptime {uptime} s ===")
        after = capture("after-session")

    with subtest("the way back leaves no piece of its own in /run, and /run noexec"):
        for piece in WAY_BACK_PIECES:
            vm.succeed(f"test ! -e {shlex.quote(piece)} && test ! -L {shlex.quote(piece)}")
        now = "noexec" if run_noexec() else "executable"
        had = "noexec" if decoy_noexec else "executable"
        assert now == had, f"/run is {now} after the way back, where the decoy had it {had}"

    with subtest("after a session the records read as one clean power cycle"):
        if assert_kind == "wtmpdb":
            problems = records.wtmpdb_way_back_problems(
                reference.wtmpdb, after.wtmpdb, window
            )
            print(f"=== wtmpdb rows after the way back ===\n{after.wtmpdb}")
            assert not problems, "\n".join(problems)
            # How the decoy's own tool shows it: no new self-labelling
            # s-reboot and no new boot left open (a crash). Rows the package
            # imported from an older wtmp may already read so; the session must
            # not add one.
            shown = vm.succeed("wtmpdb last -x")
            print(f"=== wtmpdb last -x ===\n{shown}")
            for word in ("s-reboot", "soft-reboot", "crash"):
                assert shown.count(word) == reference_listing.count(word), (
                    f"the session added a line wtmpdb last shows as {word}:\n{shown}"
                )
            # On systemd 256 and newer the service manager dates the way back's
            # start itself; the row must sit just before it, as a cold boot's
            # does before the userspace that wrote it.
            userspace = vm.succeed(
                "systemctl show -p UserspaceTimestamp --timestamp=unix --value"
            ).strip()
            login = records.wtmpdb_boot_logins(after.wtmpdb)[-1]
            if userspace.startswith("@") and float(userspace[1:]) >= before_way_back:
                gap = float(userspace[1:]) - login / 1e6
                assert -1.0 <= gap <= 10.0, (
                    f"the boot row is {gap:.3f} s before the way back's own start"
                )
            # The writer took its fallback quietly and finished: a failed unit
            # is itself an oddity an examiner can read.
            _, state = vm.execute(
                "systemctl is-failed wtmpdb-update-boot.service 2>&1 || true",
                check_return=False,
            )
            print(f"=== wtmpdb-update-boot.service after the way back: {state.strip()} ===")
            assert state.strip() != "failed", (
                f"the wtmpdb boot writer's service failed after the way back: {state.strip()}"
            )
        else:
            problems = records.classic_way_back_problems(
                reference.wtmp, after.wtmp, window
            )
            print(f"=== classic wtmp after the way back ===\n{after.wtmp}")
            assert not problems, "\n".join(problems)
            # The corrected record must read as a genuine boot: the same
            # identity (reboot, the kernel release) as the power cycle's.
            after_boot = records.last_boot_record(after.wtmp)
            reference_boot = records.last_boot_record(reference.wtmp)
            assert after_boot is not None and reference_boot is not None
            assert (after_boot["user"], after_boot["host"]) == (
                reference_boot["user"],
                reference_boot["host"],
            ), (
                "the way-back boot record does not match the power cycle's boot "
                f"record (after: {after_boot}, reference: {reference_boot})"
            )

    with subtest("a plain soft-reboot still carries the trace (positive control)"):
        follow("systemctl soft-reboot", "control-soft-reboot")
        control = capture("after-control-soft-reboot")
        if assert_kind == "wtmpdb":
            diff = records.diff_captures(after, control)
            assert diff["session_adds_soft_reboot_row"], (
                "a plain soft-reboot was expected to leave a wtmpdb soft-reboot "
                f"boot row, so the test can detect one; rows added: {diff['wtmpdb_added']}"
            )
        else:
            assert records.last_boot_is_backdated(control.wtmp), (
                "on this platform a soft-reboot was expected to carry the cold-boot "
                "time into the boot record (the cause of the backdated boot a session "
                f"leaves); boot times: {records.boot_record_times(control.wtmp)}"
            )
  '';
}
