# Test 76: Emergency on the plain decoy is a no-op
#
# With no hidden session (the plain decoy, the hidden volume opened and mounted
# as an operator prepares it before entering), `nails emergency` must not
# soft-reboot, power off or touch anything: it exits 0 and says there is
# nothing to tear down, in human and in --json form. Afterwards the machine is
# on the same boot with the same plain decoy root, no next root, the backend
# still open and mounted, and status still reports the "decoy" posture.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "emergency-while-inactive";
  meta.tags = [ "security" ];

  testScript = _: ''
    import json

    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}

    CONFIG = "/mnt/data/config/nails.toml"

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_headless_config(CONFIG)
    boot_id = machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()


    def assert_untouched():
        session.assert_decoy_root(machine)
        assert machine.succeed("cat /proc/sys/kernel/random/boot_id").strip() == boot_id
        count = machine.succeed("systemctl show -p SoftRebootsCount --value").strip()
        assert count in ("", "0"), f"a soft-reboot happened: SoftRebootsCount={count}"
        assert session.backend_open(machine), "emergency closed the prepared backend"
        machine.succeed("mountpoint -q /mnt/data")
        status = read_status_json(config_path=CONFIG)
        assert status["posture"] == "decoy", status


    with subtest("precondition: the plain decoy with the backend prepared"):
        assert_untouched()

    with subtest("emergency with no hidden session exits 0 and changes nothing"):
        rc, out = machine.execute(f"nails --config {CONFIG} emergency 2>&1")
        assert rc == 0, f"expected a no-op success, got rc={rc}: {out}"
        assert "No hidden session: nothing to tear down" in out, out
        assert_untouched()

    with subtest("the --json report says there was nothing to do"):
        out = machine.succeed(f"nails --config {CONFIG} --json emergency")
        data = json.loads(out)["data"]
        assert data["side"] == "none", data
        assert data["dispatched"] is None, data
        assert data["cgroups_killed"] == 0 and data["processes_killed"] == 0, data
        assert_untouched()
  '';
}
