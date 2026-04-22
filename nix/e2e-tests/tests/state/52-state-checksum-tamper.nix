# Test 52: State Checksum Tamper
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
  name = "state-checksum-tamper";
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
        assert original_state.get("checksum"), f"Expected checksum in persisted state: {original_state}"
        machine.succeed(f"cp {state_path} {backup_path}")

    with subtest("tamper state file without updating checksum"):
        tampered_state = json.loads(machine.succeed(f"cat {state_path}"))
        original_checksum = tampered_state["checksum"]
        tampered_state["last_modified"] = "1970-01-01T00:00:00Z"
        tampered_state["checksum"] = original_checksum
        machine.succeed(
            """cat > %s <<'EOF'
    %s
    EOF"""
            % (state_path, json.dumps(tampered_state, indent=2, sort_keys=True))
        )

        tampered_payload = read_status_json(config_path=headless_config)
        assert_status_state("Inactive", payload=tampered_payload)
        error_text = tampered_payload.get("error", "")
        assert (
            "checksum" in error_text.lower() or "corrupt" in error_text.lower()
        ), f"Expected checksum/corruption error, got: {tampered_payload}"

    with subtest("next activation refuses tampered state and leaves mounts unchanged"):
        rc, stdout, stderr = capture_command(
            "state-checksum-tamper-activate",
            f"nails --config {headless_config} activate --overlay-only --no-kill-session -y",
        )
        assert rc == 1, f"Expected activation failure after tamper, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"
        combined = (stdout + stderr).lower()
        assert (
            "checksum" in combined or "corrupt" in combined
        ), f"Expected checksum refusal, got stdout={stdout!r}, stderr={stderr!r}"
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")

    with subtest("restore pristine state and deactivate cleanly"):
        machine.succeed(f"cp {backup_path} {state_path}")
        canonical_deactivate(headless_config, unit_name="nails-deactivate-state-checksum-tamper")
        assert_status_state("Inactive")
  '';
}
