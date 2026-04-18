# Test 53: State Guard Rollback
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
  stateHelpers = import ./../../lib/state-helpers.nix;
in {
  name = "state-guard-rollback";
  meta.tags = [ "state" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    import json

    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${stateHelpers.captureCommandFns}

    def write_partial_failure_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: doomed
        lower: /etc
        upper: /mnt/hidden-volume/doomed
        work: /mnt/hidden-volume/.work/doomed
        target: /state-rollback-missing-target
    EOF"""
            % path
        )

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/state-guard-rollback.yaml"
    state_path = "/mnt/hidden-volume/.nails/state.json"

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_partial_failure_config(config_path)
    machine.succeed("mkdir -p /mnt/hidden-volume/doomed /mnt/hidden-volume/.work/doomed")

    with subtest("prepare deterministic mount failure after state transition"):
        machine.fail("test -e /state-rollback-missing-target")
        assert_status_state("Inactive", config_path=config_path)

    with subtest("failed activation rolls state back to inactive"):
        rc, stdout, stderr = capture_command(
            "state-guard-rollback-activate",
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y",
        )
        assert rc == 1, f"Expected activation failure, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"

        payload = read_status_json(config_path=config_path)
        assert_status_state("Inactive", payload=payload)

        combined = stdout + stderr
        assert combined.strip(), "Expected non-empty activation diagnostics on rollback failure"

    with subtest("rollback removes all partial mounts and stale overlay tracking"):
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        state_doc = json.loads(machine.succeed(f"cat {state_path}"))
        assert state_doc["state"] == "Inactive", f"Expected persisted rollback state, got: {state_doc}"
        assert state_doc["overlay_status"] == {}, f"Expected empty overlay tracking after rollback, got: {state_doc}"
  '';
}
