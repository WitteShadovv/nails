# A switch the transition refuses, and the reason `status` gives for it.
#
# Right before PID 1 switches, the transition checks the next root the way PID
# 1 will, and detaches it when the check fails, so PID 1 restarts the root it
# is on instead of freezing. It runs after `umount.target`: the decoy's
# shutdown has unmounted the hidden volume at /mnt/data by then, and the reason
# can reach the volume only through its bind in the next root. Here a unit's
# stop, which runs in the decoy's shutdown after the activation enqueued the
# soft-reboot, covers the next root's /etc with an empty tmpfs, so the next
# root is no OS tree any more:
#
#   1. the soft-reboot comes back to the plain decoy, the next root detached
#      and the hidden mapping closed, and the reason is nowhere on the decoy's
#      root filesystem;
#   2. the hidden volume, opened again, holds the reason: `status` names the
#      refused switch with its time and reason, and its JSON reports
#      `switch_refused` with the refusal's own reason;
#   3. `recover` resets the record the activation left at active, and the
#      reason stays;
#   4. the next activation clears it and enters the hidden root.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-refused-switch";
  meta.tags = [
    "session"
    "state"
  ];

  testScript = _: ''
    import json

    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    REASON = "the next root has neither /etc/os-release nor /usr/lib/os-release"
    MOUNT = "/run/current-system/sw/bin/mount"
    # The next root's /etc behind an empty tmpfs, and /usr/lib too where the
    # next root has one: then it has no os-release.
    HIDE = (
        f"{MOUNT} -t tmpfs none /run/nextroot/etc; "
        "if [ -d /run/nextroot/usr/lib ]; then "
        f"{MOUNT} -t tmpfs none /run/nextroot/usr/lib; fi"
    )

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_headless_config(CONFIG)

    with subtest("a switch the transition refuses comes back to the plain decoy"):
        # It stops with the rest of the decoy, after the activation enqueued the
        # soft-reboot and before the transition checks the next root.
        machine.succeed(
            "systemd-run --unit break-next-root -p Type=oneshot -p RemainAfterExit=yes "
            f"-p ExecStop='/bin/sh -c \"{HIDE}\"' "
            "/run/current-system/sw/bin/true"
        )
        machine.succeed("systemctl is-active break-next-root.service")
        timings = session.follow_soft_reboot(
            machine,
            f"set -o pipefail; nails --config {CONFIG} activate -y --overlay-only 2>&1 "
            f"| tee /mnt/data/refused.log > {session.SERIAL_CONSOLE}",
            "refused",
        )
        machine.log(f"refused switch timings: {timings}")
        session.assert_decoy_root(machine)
        machine.fail("test -e /run/overlay-runtime")
        machine.fail("test -e /run/systemd/system/systemd-soft-reboot.service.d")
        # The refused entry closes the hidden backend, as a reboot would.
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
        # The reason went to the hidden volume, never to the decoy's disk (the
        # volume itself holds it: see below).
        found = machine.succeed("find / -xdev -name last-switch.json -print 2>/dev/null || true")
        assert found == "", found

    with subtest("status names the refused switch, its time and its reason"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        print(machine.succeed("cat /mnt/data/refused.log || true"))
        machine.succeed("test -s /mnt/data/last-switch.json")
        data = read_status_json(CONFIG)
        machine.log(json.dumps(data, indent=1))
        assert data["place"] == "decoy", data
        assert data["attention"] == "switch_refused", data
        assert data["reason"] == REASON, data
        assert data["switch_refusal"]["reason"] == REASON, data
        assert "recover" in data["remediation"], data
        out = machine.succeed(f"nails --config {CONFIG} status")
        machine.log(out)
        assert "Last switch:        refused at " in out, out
        assert REASON in out, out
        assert "the switch into it was refused" in out, out

    with subtest("recover resets the record, and the reason stays"):
        machine.succeed(f"nails --config {CONFIG} recover")
        data = read_status_json(CONFIG)
        assert data["attention"] == "switch_refused", data
        assert data["reason"] == REASON, data
        assert "remediation" not in data, data
        out = machine.succeed(f"nails --config {CONFIG} status")
        assert REASON in out, out
        assert "none is running" not in out, out

    with subtest("the next activation clears the reason and enters"):
        machine.fail("systemctl is-active break-next-root.service")
        canonical_activate(CONFIG, "--overlay-only", "activate")
        machine.fail("test -e /mnt/data/last-switch.json")
        data = read_status_json(CONFIG)
        assert data["place"] == "hidden", data
        assert data["attention"] is None, data
        assert "switch_refusal" not in data, data
  '';
}
