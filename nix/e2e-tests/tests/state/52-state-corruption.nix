# Test 52: State Corruption
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
in
{
  name = "state-corruption";
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
    ${stateHelpers.captureCommandFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    state_path = "/mnt/hidden-volume/state.json"
    backup_path = "/tmp/state-backup.json"

    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activate and capture pristine state file"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --no-kill-session -y"
        )
        assert_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")
        machine.succeed(f"test -f {state_path}")

        original_state = json.loads(machine.succeed(f"cat {state_path}"))
        assert original_state.get("integrity_sha256"), (
            f"Expected integrity digest in persisted state: {original_state}"
        )
        machine.succeed(f"cp {state_path} {backup_path}")

    with subtest("corrupt state file without updating the integrity digest"):
        corrupt_state = json.loads(machine.succeed(f"cat {state_path}"))
        stale_digest = corrupt_state["integrity_sha256"]
        corrupt_state["last_modified"] = "1970-01-01T00:00:00Z"
        corrupt_state["integrity_sha256"] = stale_digest
        machine.succeed(
            """cat > %s <<'EOF'
    %s
    EOF"""
            % (state_path, json.dumps(corrupt_state, indent=2, sort_keys=True))
        )

        corrupt_payload = read_status_json(config_path=headless_config)
        assert_status_state("Unknown", payload=corrupt_payload)
        error_text = corrupt_payload.get("error", "")
        assert "corrupt" in error_text.lower(), (
            f"Expected corruption error, got: {corrupt_payload}"
        )

    with subtest("next activation refuses the corrupt state and leaves mounts unchanged"):
        rc, stdout, stderr = capture_command(
            "state-corruption-activate",
            f"nails --config {headless_config} activate --overlay-only --no-kill-session -y",
        )
        assert rc != 0, (
            f"Expected activation failure on corrupt state, got rc={rc}, "
            f"stdout={stdout!r}, stderr={stderr!r}"
        )
        combined = (stdout + stderr).lower()
        assert "corrupt" in combined, (
            f"Expected corruption refusal, got stdout={stdout!r}, stderr={stderr!r}"
        )
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")

    with subtest("restore pristine state and deactivate cleanly"):
        machine.succeed(f"cp {backup_path} {state_path}")
        canonical_deactivate(headless_config, unit_name="nails-deactivate-state-corruption")
        assert_status_state("Inactive")
  '';
}
