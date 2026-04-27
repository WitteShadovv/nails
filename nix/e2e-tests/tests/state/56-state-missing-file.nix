# Test 56: State Missing File
# Self-check list:
# 1. Uses with subtest(...).
# 2. Uses deterministic waits only.
# 3. Uses hard assertions only.
# 4. Sets meta.tags.
# 5. Uses shared lib helpers.
# 6. Preserves forensic invariants.
# 7. Exercises explicit failure injection and recovery.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "state-missing-file";
  meta.tags = [ "state" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    state_path = "/mnt/hidden-volume/state.json"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("missing state file reports inactive"):
        machine.succeed(f"rm -f {state_path}")
        payload = read_status_json(config_path=headless_config)
        assert_status_state("Inactive", payload=payload)

    with subtest("activation recreates state file and succeeds"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --no-kill-session -y"
        )
        assert_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")
        state_doc = json.loads(machine.succeed(f"cat {state_path}"))
        assert state_doc.get("checksum"), f"Expected recreated checksum-bearing state file, got: {state_doc}"

    with subtest("deactivation still succeeds after missing-file bootstrap"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-state-missing-file")
        assert_status_state("Inactive")
  '';
}
