# Test 09: State file integrity across whole-root sessions
#
# The state file lives on the hidden volume (/mnt/data/state.json). In each of
# three activate/deactivate cycles (each one a soft-reboot into the hidden root
# and one back):
#   - in the hidden session the file exists, is owner-only (0600), records the
#     Active state, and `status` reports the "active" posture;
#   - after the way back (and reopening the backend, which the switch closed)
#     the file records Inactive and `status` reports the plain "decoy" posture.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "state-integrity";
  meta.tags = [
    "security"
    "state"
  ];
  # Three round trips, six soft-reboots at about 15-30 s each, plus setup.
  globalTimeout = 1500;

  testScript = _: ''
    import json

    from nails_e2e import session

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    STATE_FILE = "/mnt/data/state.json"


    def read_state_kind():
        # The on-disk state is the externally tagged SystemState enum: Active is
        # an object keyed by "Active", Inactive the bare string "Inactive".
        # Checking membership on the string would match "Active" inside
        # "Inactive", so the type is checked first.
        raw = json.loads(machine.succeed(f"cat {STATE_FILE}"))["state"]
        if isinstance(raw, dict):
            keys = list(raw.keys())
            assert len(keys) == 1, f"unexpected state object: {raw}"
            return keys[0]
        return raw


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_headless_config(CONFIG)

    for cycle in range(1, 4):
        with subtest(f"cycle {cycle}: the hidden session records Active in an owner-only file"):
            if cycle > 1:
                machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
            canonical_activate(CONFIG, "--overlay-only", f"activate-{cycle}")
            machine.succeed(f"test -f {STATE_FILE}")
            perms = machine.succeed(f"stat -c %a {STATE_FILE}").strip()
            assert perms == "600", f"{STATE_FILE} has permissions {perms}, expected 600"
            kind = read_state_kind()
            assert kind == "Active", f"cycle {cycle}: state file records {kind!r}"
            status = read_status_json(config_path=CONFIG)
            assert status["place"] == "hidden", status

        with subtest(f"cycle {cycle}: the way back records Inactive"):
            canonical_deactivate(CONFIG, f"deactivate-{cycle}")
            # The switch closed the backend: reopen it to read the state.
            machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
            session.assert_decoy_root(machine)
            kind = read_state_kind()
            assert kind == "Inactive", f"cycle {cycle}: state file records {kind!r}"
            perms = machine.succeed(f"stat -c %a {STATE_FILE}").strip()
            assert perms == "600", f"{STATE_FILE} has permissions {perms}, expected 600"
            status = read_status_json(config_path=CONFIG)
            assert status["place"] == "decoy", status
            # Reopened for the next cycle at its start; close it here so every
            # cycle starts from the same closed backend.
            machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
