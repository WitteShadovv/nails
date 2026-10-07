# Test 20: Preflight State Check Integrity
#
# A completed activation and deactivation must leave a signed state file
# behind. Refusing a tampered state file is covered once, in
# state/52-state-corruption.nix, for both corruption vectors (a stale digest
# over a changed `last_modified` while active, and over a changed `version`
# once inactive).

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "preflight-state-check";
  meta.tags = [ "preflight" ];

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-state-check.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("baseline activation and deactivation produce a signed state file"):
        machine.succeed(f"nails --config {config_path} activate --overlay-only --session keep -y")
        assert_status_state("active", config_path=config_path)
        assert_overlay_mounted("/home")
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-state-initial")
        assert_status_state("inactive", config_path=config_path)
        # The deactivation reboot closed the hidden volume; reopen it to read
        # the state file the session left behind.
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        persisted = json.loads(machine.succeed("cat /mnt/data/state.json"))
        assert persisted.get("integrity_sha256"), (
            f"Expected an integrity digest in the persisted state: {persisted}"
        )
        assert_status_state("inactive", config_path=config_path)
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
