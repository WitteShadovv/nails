# Test 56: State Missing File
#
# A hidden volume without a state file reads as the plain decoy, and
# activation bootstraps the file: the hidden session starts and the state
# file it records carries its integrity digest. The way back works from that
# bootstrapped state. Finally, with the state file gone from under a live
# hidden session (the hidden volume lazily unmounted), status probes the live
# root and never reports the plain decoy.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "state-missing-file";
  meta.tags = [ "state" ];

  testScript = _: ''
    import json
    import re

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # The config lives on the decoy's /run so it stays readable after the
    # hidden volume is detached below.
    headless_config = "/run/nails-headless.toml"
    state_path = "/mnt/data/state.json"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("missing state file reads as the plain decoy"):
        machine.succeed(f"rm -f {state_path}")
        payload = read_status_json(config_path=headless_config)
        assert payload["posture"] == "decoy", payload

    with subtest("activation recreates the state file and enters the session"):
        canonical_activate(headless_config, "--overlay-only", "state-missing-activate")
        payload = read_status_json(config_path=headless_config)
        assert payload["posture"] == "active", payload
        state_doc = json.loads(machine.succeed(f"cat {state_path}"))
        digest = state_doc.get("integrity_sha256") or ""
        assert re.fullmatch(r"[0-9a-f]{64}", digest), (
            f"Expected a recreated integrity-digest-bearing state file, got: {state_doc}"
        )

    with subtest("deactivation still succeeds after the missing-file bootstrap"):
        canonical_deactivate(headless_config, "state-missing-deactivate")
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        payload = read_status_json(config_path=headless_config)
        assert payload["posture"] == "decoy", payload

    with subtest("a hidden session whose state file vanished never reports decoy"):
        canonical_activate(headless_config, "--overlay-only", "state-missing-activate-2")
        # Detach the hidden volume from under the live hidden root: state.json
        # disappears with /mnt/data, but / is still the hidden overlay. Status
        # must probe the live root and refuse to call this the decoy.
        machine.succeed("umount -l /mnt/data")
        machine.fail(f"test -e {state_path}")
        _, payload = read_status_json_with_rc(config_path=headless_config)
        assert payload.get("posture") != "decoy", (
            f"status must never report decoy in the hidden root: {payload}"
        )
  '';
}
