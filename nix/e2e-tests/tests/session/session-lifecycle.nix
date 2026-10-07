# The whole-root session end to end, through the real `nails` commands.
#
# Replaces the live-overlay basic workflow, re-activation, status/verify,
# emergency and backend-close tests:
#
#   1. `nails init` and `nails check` on the decoy;
#   2. `nails activate`: a soft-reboot into the root overlay. In the hidden
#      root `/` is the overlay with its upper on the hidden volume, a write
#      lands in the upper and never on the decoy filesystem, and status reports
#      the session;
#   3. `nails deactivate`: a soft-reboot back to the plain decoy. Nothing of the
#      hidden /run survives, the hidden volume's mapping closed itself, the
#      decoy never saw the hidden file;
#   4. a second activation finds the hidden file again (the upper persists);
#   5. `nails emergency` in the hidden session kills a hidden service and the
#      login session at once and soft-reboots back, with its phases timed in
#      the log on the hidden volume;
#   6. `nails recover` and `nails emergency` on the plain decoy are no-ops.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-lifecycle";
  meta.tags = [
    "smoke"
    "lifecycle"
    "session"
  ];
  # Three soft-reboot round trips at about 15 s each, plus setup.
  globalTimeout = 1500;

  testScript = _: ''
    import json
    import secrets

    from nails_e2e import session

    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"
    PEEK = "/run/decoy-peek"


    def peek_decoy(decoy_dev, command):
        """Run `command` against a read-only mount of the decoy root at PEEK.

        The decoy superblock is still mounted read-write (it is the overlay's
        lower), so a plain read-only mount would fail with EBUSY: mount it,
        then make this mount read-only."""
        machine.succeed(
            f"mkdir -p {PEEK} && mount {decoy_dev} {PEEK} && mount -o remount,bind,ro {PEEK}"
        )
        try:
            return machine.execute(command)
        finally:
            machine.succeed(f"umount {PEEK} && rmdir {PEEK}")


    machine.start()
    machine.wait_for_unit("multi-user.target")
    decoy_dev = machine.succeed("findmnt -no SOURCE /").strip()
    machine.log(f"decoy root: {decoy_dev}")

    with subtest("init and check on the decoy"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("nails init /mnt/data")
        machine.succeed(f"test -s {CONFIG}")
        # The binary runs from the Nix store, so the root cannot be derived
        # from its location: name it, and lower the space floor for the 2 GiB
        # test disk.
        machine.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "EOF"
        )
        rc, out = machine.execute(f"nails --config {CONFIG} check --overlay-only")
        machine.log(out)
        assert rc == 0, f"check refused a ready host (rc={rc})"
        status = read_status_json(config_path=CONFIG)
        assert status["state"]["kind"] == "inactive", status

    run_before = session.run_entries(machine)

    with subtest("activate soft-reboots into the hidden root"):
        timings = canonical_activate(CONFIG, "--overlay-only", "activate-1")
        session.assert_hidden_root(machine, UPPER)
        status = read_status_json(config_path=CONFIG)
        machine.log(json.dumps(status, indent=1))
        assert status["posture"] == "active", status
        count = machine.succeed("systemctl show -p SoftRebootsCount --value").strip()
        assert count == "1", f"SoftRebootsCount={count}"

    canary = "hidden-" + secrets.token_hex(8)
    with subtest("a hidden write lands in the upper, never on the decoy"):
        machine.succeed(f"echo {canary} > /root/hidden-canary && sync")
        assert machine.succeed(f"cat {UPPER}/root/hidden-canary").strip() == canary
        rc, _ = peek_decoy(decoy_dev, f"test ! -e {PEEK}/root/hidden-canary")
        assert rc == 0, "the hidden file is on the decoy filesystem"
        machine.succeed("mountpoint -q /mnt/data")

    with subtest("deactivate soft-reboots back and leaves no hidden /run"):
        machine.succeed("echo probe > /run/hidden-run-probe")
        machine.succeed("systemd-run --unit hidden-probe --property=Type=exec sleep infinity")
        wall = session.wall_clock(machine)
        canonical_deactivate(CONFIG, "deactivate-1")
        machine.fail("test -e /root/hidden-canary")
        machine.fail("test -e /run/hidden-run-probe")
        machine.fail("test -e /run/overlay-runtime")
        machine.fail("test -e /run/systemd/system/systemd-soft-reboot.service.d")
        machine.fail("systemctl is-active hidden-probe.service")
        residue = session.carried_run_residue(machine, run_before, wall)
        assert not residue, f"hidden /run residue on the decoy: {residue}"

    with subtest("the upper persists into the next session"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        status = read_status_json(config_path=CONFIG)
        assert status["state"]["kind"] == "inactive", status
        canonical_activate(CONFIG, "--overlay-only", "activate-2")
        assert machine.succeed("cat /root/hidden-canary").strip() == canary

    with subtest("emergency in the hidden session kills it and returns at once"):
        machine.succeed("systemd-run --unit hidden-writer --property=Type=exec sh -c 'while sleep 1; do date >> /root/w; done'")
        machine.succeed("systemctl is-active hidden-writer.service")
        timings = session.follow_soft_reboot(
            machine, f"nails --config {CONFIG} emergency --json > /dev/null", "emergency"
        )
        machine.log(f"emergency soft-reboot timings: {timings}")
        session.assert_decoy_root(machine)
        machine.fail("systemctl is-active hidden-writer.service")
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)

    with subtest("the emergency logged its timed phases on the hidden volume"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        log = machine.succeed("cat /mnt/data/logs/*.log 2>/dev/null || true")
        assert "emergency hot path finished" in log, log[-3000:]
        assert "phases=" in log, log[-3000:]

    with subtest("recover and emergency on the plain decoy change nothing"):
        out = machine.succeed(f"nails --config {CONFIG} recover")
        assert "Nothing to recover" in out, out
        out = machine.succeed(f"nails --config {CONFIG} emergency")
        assert "nothing to tear down" in out, out
        session.assert_decoy_root(machine)
  '';
}
