# Test 56: State Missing File

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "state-missing-file";
  meta.tags = [ "state" ];

  testScript = _: ''
    import json
    import re

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    state_path = "/mnt/data/state.json"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("missing state file reports inactive"):
        machine.succeed(f"rm -f {state_path}")
        payload = read_status_json(config_path=headless_config)
        assert_status_state("Inactive", payload=payload)

    with subtest("activation recreates state file and succeeds"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        assert_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")
        state_doc = json.loads(machine.succeed(f"cat {state_path}"))
        # The durable state file v2 carries its integrity digest as
        # `integrity_sha256` (a 64-hex SHA-256), not the old `checksum` key.
        digest = state_doc.get("integrity_sha256") or ""
        assert re.fullmatch(r"[0-9a-f]{64}", digest), (
            f"Expected recreated integrity-digest-bearing state file, got: {state_doc}"
        )

    with subtest("deactivation still succeeds after missing-file bootstrap"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-state-missing-file")
        assert_status_state("Inactive")

    with subtest("lazily unmounting the backend during an active session never reports decoy"):
        # canonical_deactivate rebooted, which closed the hidden volume; reopen it
        # before re-activating so a genuine NAILS overlay is live again.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        assert_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")

        # Detach the hidden backend out from under the live overlay: state.json
        # disappears with /mnt/data, but the /home overlay keeps serving hidden
        # data. Status must probe the kernel and refuse to call this a decoy.
        machine.succeed("umount -l /mnt/data")

        rc, payload = read_status_json_with_rc(config_path=headless_config)
        posture = payload.get("posture")
        assert posture in ("inconsistent", "degraded"), (
            f"expected a dangerous posture, got {payload}"
        )
        assert posture != "decoy", (
            f"status must never report decoy while NAILS overlays are live: {payload}"
        )
        assert rc != 0, f"a dangerous posture must exit non-zero, got rc={rc}: {payload}"
  '';
}
