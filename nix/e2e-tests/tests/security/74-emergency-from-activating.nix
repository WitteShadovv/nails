# Test 74: Emergency From Activating
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
in
{
  name = "emergency-from-activating";
  meta.tags = [ "security" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}

    import json
    import shlex

    expected_overlays = ["/etc", "/home", "/root", "/srv", "/tmp"]

    def assert_expected_overlays(paths):
        for path in paths:
            assert_overlay_mounted(path)

    def backup_state_file(state_path, backup_path):
        machine.succeed(
            "cp " + shlex.quote(state_path) + " " + shlex.quote(backup_path)
        )

    def restore_state_file(state_path, backup_path):
        machine.succeed(
            "cp " + shlex.quote(backup_path) + " " + shlex.quote(state_path)
        )

    def force_state_file_state(state_path, target_state):
        script = f"""python3 - <<'PY'
    import json

    state_path = {json.dumps(state_path)}
    target_state = {json.dumps(target_state)}

    with open(state_path, 'r', encoding='utf-8') as handle:
        payload = json.load(handle)

    state = payload['state']

    if isinstance(state, dict):
        previous = next(iter(state.values())) or {{}}
        timestamp = (
            previous.get('started_at')
            or previous.get('activated_at')
            or previous.get('triggered_at')
            or '1970-01-01T00:00:00Z'
        )
        if target_state in ('Activating', 'Deactivating'):
            payload['state'] = {{target_state: {{'started_at': timestamp}}}}
        elif target_state == 'Inactive':
            payload['state'] = 'Inactive'
        else:
            raise SystemExit(f'Unsupported target state: {{target_state}}')
    elif isinstance(state, str):
        payload['state'] = target_state
    else:
        raise SystemExit(f'Unsupported state encoding: {{state!r}}')

    payload.pop('checksum', None)

    with open(state_path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle)
    PY"""
        machine.succeed("/bin/sh -lc " + shlex.quote(script))

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    state_path = "/mnt/hidden-volume/state.json"
    backup_path = "/tmp/active-state.json"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("prepare active session and force activating state"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        machine.succeed(f"test -f {state_path}")
        backup_state_file(state_path, backup_path)
        force_state_file_state(state_path, "Activating")

        status = read_status_json(config_path=headless_config)
        assert_status_state("activating", payload=status)
        assert_expected_overlays(expected_overlays)

    with subtest("emergency fails closed while activation is in progress"):
        prefix = "/run/nails-tests/emergency-from-activating"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency", "--no-countdown"],
            unit_name="nails-emergency-from-activating",
            timeout=30,
        )

        assert result["rc"] == 1, f"Expected emergency to fail from Activating, got: {result}"
        assert "Activating" in result["stderr"], result
        assert "Must be ACTIVE" in result["stderr"], result

        status = read_status_json(config_path=headless_config)
        assert_status_state("activating", payload=status)
        assert_expected_overlays(expected_overlays)

    with subtest("restored active state can still be emergency-cleaned"):
        restore_state_file(state_path, backup_path)
        status = read_status_json(config_path=headless_config)
        assert status["state"].startswith("Active"), status

        prefix = "/run/nails-tests/emergency-from-activating-cleanup"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency", "--no-countdown"],
            unit_name="nails-emergency-from-activating-cleanup",
            timeout=30,
        )

        assert result["rc"] == 0, result
        assert "Emergency deactivation complete" in result["stdout"], result

        assert_no_overlays(expected_overlays)
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
  '';
}
