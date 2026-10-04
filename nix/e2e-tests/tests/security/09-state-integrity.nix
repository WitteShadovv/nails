# Test 09: State File Integrity
# Tests state file existence, permissions, and the tracked state across cycles.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "state-integrity";
  meta.tags = [
    "security"
    "state"
  ];

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}

    # The state file lives on the hidden volume, so it is the only path to read.
    state_file = "/mnt/data/state.json"

    def read_state_kind():
        # The on-disk state uses the externally tagged SystemState enum: the
        # active variant is an object keyed by "Active", the inactive variant is
        # the bare string "Inactive". Checking membership on the string would
        # match "Active" inside "Inactive", so the type is checked first.
        raw = json.loads(machine.succeed(f"cat {state_file}"))["state"]
        if isinstance(raw, dict):
            keys = list(raw.keys())
            assert len(keys) == 1, f"unexpected state object: {raw}"
            return keys[0]
        return raw

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activate writes an owner-only state file recording Active"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")

        machine.succeed(f"test -f {state_file}")
        perms = machine.succeed(f"stat -c %a {state_file}").strip()
        assert perms == "600", f"state file {state_file} has permissions {perms}, expected 600"

        kind = read_state_kind()
        assert kind == "Active", f"state file records {kind!r}, expected Active"
        assert_status_state("active", config_path=headless_config)

    with subtest("deactivate returns the tracked state to Inactive"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-state-integrity")
        assert_status_state("inactive")

    with subtest("state is tracked correctly across repeated cycles"):
        for cycle in range(1, 4):
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
            assert read_state_kind() == "Active", f"cycle {cycle}: state file not Active"
            assert_status_state("active", config_path=headless_config)

            canonical_deactivate(
                headless_config,
                unit_name=f"nails-deactivate-state-integrity-cycle-{cycle}",
            )
            assert_status_state("inactive")
            print(f"✓ cycle {cycle}: activate/deactivate state tracked correctly")
  '';
}
