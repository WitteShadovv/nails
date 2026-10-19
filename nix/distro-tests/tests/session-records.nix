# A cross-distro regression test for the decoy's login and boot records.
#
# A whole-root session returns to the decoy through a soft-reboot, and the
# decoy's own boot writers record that start. On Debian with wtmpdb the boot row
# would be named "soft-reboot"; on a service manager that keeps the userspace
# start time across a soft-reboot (systemd 255 and earlier, classic wtmp), the
# boot record would carry the decoy's first boot time, so the file would hold a
# boot stamped before the shutdown that precedes it. Neither is written by an
# ordinary power cycle. The way back neutralises both; this test proves it.
#
# The flow on one booted VM (so the records accumulate on one decoy disk):
#
#   1. fresh boot            -- the power-cycle reference (QEMU's own cold start);
#   2. a plain soft-reboot   -- no NAILS: the positive control, which must still
#                               carry the trace, so a vacuous pass is impossible;
#   3. a NAILS session       -- activate then deactivate: the way back runs the
#                               reconcile step;
#   4. assertions            -- the control carries the trace and the session
#                               does not, so after a session the records read as
#                               one clean power cycle.
#
# Records are read live in the guest and carried to the host-side readers in
# nix/e2e-tests/lib/records.py (reading live keeps install, control and session
# in one QEMU process; a disk image would end QEMU and the next boot would be
# the pristine cloud image again -- see lib/distro-vm.nix). Like the smoke suite
# it needs the guest's network to install a record package on Debian, so it runs
# on nix-vm-test's `driver` target, on the host under the heavy-job lock, never
# in CI.
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
        _, listing = vm.execute(
            "last -F 2>/dev/null | head -n 20; echo ---; "
            "wtmpdb last 2>/dev/null | head -n 20 || true",
            check_return=False,
        )
        print(f"=== RECORD STAGE {label} ===\n{listing.rstrip()}")
        return cap


    def follow(trigger: str, label: str) -> None:
        session.follow_soft_reboot(vm, trigger, label)
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

    fresh = capture("fresh-boot")  # the power-cycle reference

    with subtest("a plain soft-reboot still carries the trace (positive control)"):
        follow("systemctl soft-reboot", "control-soft-reboot")
        control = capture("after-control-soft-reboot")
        if assert_kind == "wtmpdb":
            assert records.has_soft_reboot_boot_row(control.wtmpdb), (
                "a plain soft-reboot was expected to leave a wtmpdb soft-reboot "
                f"boot row, so the test can detect one; rows: {control.wtmpdb}"
            )
        else:
            control_boots = records.boot_record_times(control.wtmp)
            assert len(control_boots) >= 2 and control_boots[-1] == control_boots[0], (
                "on this platform a soft-reboot was expected to carry the cold-boot "
                "time into the boot record (the cause of the backdated boot a session "
                f"leaves); boot times: {control_boots}"
            )

    with subtest("a NAILS session: activate then deactivate (the way back)"):
        vm.succeed("""${hiddenRoot.setupHiddenRoot}""")
        vm.succeed("""${hiddenRoot.makeDecoyAmnesic}""")
        follow(f"{nails_cmd} activate -y > /mnt/data/activate.log 2>&1", "activate")
        session.assert_hidden_root(vm)
        follow(f"{nails_cmd} deactivate -y", "deactivate")
        session.assert_decoy_root(vm)
        wait_for_reconcile()
        after = capture("after-session")

    with subtest("after a session the records read as one clean power cycle"):
        # The reconcile step removes every piece of itself from /run.
        vm.succeed("test ! -e /run/overlay-runtime-boot")
        _, leftovers = vm.execute(
            "ls /run/systemd/system/overlay-runtime-boot.service "
            "/run/systemd/system/wtmpdb-update-boot.service.d 2>&1 || true",
            check_return=False,
        )
        print(f"=== /run after the reconcile step ===\n{leftovers.rstrip()}")

        if assert_kind == "wtmpdb":
            added = records.sql_rows_added(control.wtmpdb, after.wtmpdb)
            print(f"=== wtmpdb rows the session added ===\n{added}")
            assert not records.has_soft_reboot_boot_row(added), (
                "the way back left a wtmpdb soft-reboot boot row; the reconcile "
                f"step did not neutralise it. Added rows: {added}"
            )
            assert any(str(row.get("User", "")).strip() == "reboot" for row in added), (
                "the way back wrote no ordinary reboot boot row to wtmpdb; the "
                f"writer may not have run. Added rows: {added}"
            )
            # The bus drop-in must let the boot writer fall back cleanly, not
            # fail: a failed unit is itself an oddity an examiner can read.
            _, state = vm.execute(
                "systemctl is-failed wtmpdb-update-boot.service 2>&1 || true",
                check_return=False,
            )
            print(f"=== wtmpdb-update-boot.service after the way back: {state.strip()} ===")
            assert state.strip() != "failed", (
                "the wtmpdb boot writer's service failed after the way back; the "
                f"bus drop-in must let it fall back cleanly. State: {state.strip()}"
            )
        else:
            after_boots = records.boot_record_times(after.wtmp)
            assert after_boots, f"no classic-wtmp boot record after the session: {after.wtmp}"
            assert not records.last_boot_is_backdated(after.wtmp), (
                "the way back left a backdated classic-wtmp boot record; the "
                f"reconcile step did not correct it. Boot times: {after_boots}"
            )
            # Without the fix the way-back boot would carry the cold-boot time
            # (control_boots[0]); the reconcile step moves it to when the decoy
            # came back, strictly later.
            assert after_boots[-1] > control_boots[0], (
                "the way-back boot record still carries the decoy's cold-boot time; "
                f"the reconcile step did not correct it (boots: {after_boots}, "
                f"cold: {control_boots[0]})"
            )
            # The corrected record must read as a genuine boot: a live
            # microsecond reading (a cleared 000000 is what no real boot carries
            # and would single this record out in utmpdump), and the same
            # identity (reboot, the kernel release) as the power-cycle reference's
            # own boot record.
            after_boot = records.last_boot_record(after.wtmp)
            assert after_boot is not None
            assert after_boot["tv_usec"] != 0, (
                "the way-back boot record carries a cleared microsecond field; a "
                f"genuine boot never does. Record: {after_boot}"
            )
            fresh_boot = records.last_boot_record(fresh.wtmp)
            if fresh_boot is not None:
                assert (after_boot["user"], after_boot["host"]) == (
                    fresh_boot["user"],
                    fresh_boot["host"],
                ), (
                    "the way-back boot record does not match the power-cycle "
                    f"reference's boot record (after: {after_boot}, "
                    f"reference: {fresh_boot})"
                )
  '';
}
