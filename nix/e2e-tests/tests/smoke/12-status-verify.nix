# Test 12: Status and Verify Command Coverage
# Tests status/verify at each phase, JSON output, verbose mode, artifact detection

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
in
{
  name = "status-verify";
  meta.tags = [
    "smoke"
    "contract"
  ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    import json
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.runVerifyFn}
    ${assertions.assertStatusStateFn}
    ${contractHelpers.runCommandCaptureFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    print("\n=== Test 1: Status shows Inactive initially ===")
    status_text = machine.succeed("nails status")
    assert "Inactive" in status_text or "INACTIVE" in status_text, \
        f"Expected Inactive in status, got: {status_text}"
    print("✓ Status shows Inactive")

    print("\n=== Test 2: Status --json output ===")
    status_json_raw = machine.succeed("nails status --json")
    status_json = json.loads(status_json_raw)
    assert "state" in status_json, f"Expected 'state' field in JSON, got: {status_json}"
    assert status_json["state"] == "Inactive", f"Expected Inactive, got: {status_json}"
    print(f"✓ Status --json returns valid JSON with state={status_json['state']}")

    print("\n=== Test 3: Status --verbose exposes real diagnostics ===")
    verbose_result = run_command_capture(
        "status-verify-inactive-verbose",
        f"nails --config {shlex.quote(headless_config)} status --verbose",
    )
    assert verbose_result["rc"] == 0, verbose_result
    assert "Verbose Details:" in verbose_result["stdout"], verbose_result
    assert "State loaded:" in verbose_result["stdout"], verbose_result
    assert "Log path:" in verbose_result["stdout"], verbose_result
    print("✓ Status --verbose returns concrete inactive diagnostics")

    print("\n=== Test 4: Verify detects planted artifacts ===")
    machine.succeed("touch /tmp/nails.log")
    verify_rc, verify_json = run_verify()
    assert verify_rc != 0 or verify_json.get("status") in ("Warning", "Critical"), \
        f"Expected verify to detect artifact, got: {verify_json}"
    print("✓ Verify detects planted artifacts")
    machine.succeed("rm -f /tmp/nails.log")

    print("\n=== Test 5: Verify --json output (clean) ===")
    verify2_rc, verify2_json = run_verify()
    assert "status" in verify2_json or "findings" in verify2_json, \
        f"Expected status/findings in verify JSON, got: {verify2_json}"
    print(f"✓ Verify --json returns valid JSON (exit={verify2_rc})")

    print("\n=== Test 6: Status shows Active after activation ===")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

    status_json = json.loads(machine.succeed("nails status --json"))
    assert status_json["state"].startswith("Active"), \
        f"Expected Active state, got: {status_json}"
    print(f"✓ Status shows {status_json['state']} after activation")

    print("\n=== Test 7: Default hidden logs are created and surfaced ===")
    machine.succeed("test -d /mnt/hidden-volume/logs")
    machine.succeed("test -f /mnt/hidden-volume/logs/nails.log")
    active_verbose = run_command_capture(
        "status-verify-active-verbose",
        f"nails --config {shlex.quote(headless_config)} status --verbose",
    )
    assert active_verbose["rc"] == 0, active_verbose
    assert "Overlay Mount Details:" in active_verbose["stdout"], active_verbose
    assert "Recent Logs:" in active_verbose["stdout"], active_verbose
    print("✓ Default hidden log directory/file are created and visible via status --verbose")

    print("\n=== Test 8: Non-root status stays truthful on unreadable state ===")
    machine.succeed("chown root:root /mnt/hidden-volume/state.json")
    machine.succeed("chmod 600 /mnt/hidden-volume/state.json")
    non_root = run_command_capture(
        "status-verify-non-root",
        "su - testuser -c "
        + shlex.quote(f"nails --config {headless_config} status --json"),
    )
    assert non_root["rc"] == 0, non_root
    non_root_payload = json.loads(non_root["stdout"])
    assert non_root_payload["state"] == "UNKNOWN", non_root_payload
    assert non_root_payload["security_posture"] == "warning", non_root_payload
    assert "error" in non_root_payload, non_root_payload
    assert "Permission denied" in non_root_payload["error"], non_root_payload
    assert "/mnt/hidden-volume/state.json" in non_root_payload["error"], non_root_payload
    assert_status_state("Active", config_path=headless_config)
    print("✓ Non-root status exits zero but reports permission failure explicitly")

    print("\n=== Test 9: Status after deactivation ===")
    machine.crash()
    machine.start()
    machine.wait_for_unit("multi-user.target")

    status_json = json.loads(machine.succeed("nails status --json"))
    assert status_json["state"] == "Inactive", \
        f"Expected Inactive after deactivation, got: {status_json}"
    print("✓ Status shows Inactive after deactivation")

    print("\n=== All Status/Verify Tests Passed ===")
  '';
}
