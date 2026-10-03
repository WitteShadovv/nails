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

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    print("\n=== Test 1: Status shows Inactive initially ===")
    status_text = machine.succeed("nails status")
    assert "Inactive" in status_text or "INACTIVE" in status_text, \
        f"Expected Inactive in status, got: {status_text}"
    print("✓ Status shows Inactive")

    print("\n=== Test 2: Status --json output ===")
    status_json_raw = machine.succeed("nails status --json")
    status_envelope = json.loads(status_json_raw)
    assert status_envelope["schema_version"] == 1, status_envelope
    status_json = status_envelope["data"]
    assert "state" in status_json, f"Expected 'state' field in data, got: {status_envelope}"
    assert status_json["state"]["kind"] == "inactive", f"Expected inactive, got: {status_json}"
    print(f"✓ Status --json returns valid JSON with state={status_json['state']['kind']}")

    print("\n=== Test 3: Status --details exposes real diagnostics ===")
    verbose_result = run_command_capture(
        "status-verify-inactive-verbose",
        f"nails --config {shlex.quote(headless_config)} status --details",
    )
    assert verbose_result["rc"] == 0, verbose_result
    assert "Details:" in verbose_result["stdout"], verbose_result
    assert "State loaded:" in verbose_result["stdout"], verbose_result
    assert "Log path:" in verbose_result["stdout"], verbose_result
    print("✓ Status --details returns concrete inactive diagnostics")

    print("\n=== Test 4: Verify detects planted artifacts ===")
    machine.succeed("touch /tmp/nails.log")
    verify_rc, verify_json = run_verify()
    assert verify_rc != 0 or verify_json.get("status") in ("warning", "critical"), \
        f"Expected verify to detect artifact, got: {verify_json}"
    print("✓ Verify detects planted artifacts")
    machine.succeed("rm -f /tmp/nails.log")

    print("\n=== Test 5: Verify --json output (clean) ===")
    verify2_rc, verify2_json = run_verify()
    assert "status" in verify2_json or "findings" in verify2_json, \
        f"Expected status/findings in verify JSON, got: {verify2_json}"
    # The honest headline is data-backed: a count of checks run and an explicit
    # list of areas the run did not inspect.
    assert verify2_json["checks_run"] > 0, verify2_json
    assert verify2_json["areas_not_checked"], verify2_json
    print(f"✓ Verify --json returns valid JSON (exit={verify2_rc})")

    print("\n=== Test 5b: Verify human headline never overclaims ===")
    # Run against the headless config: without one, verify falls back to the
    # binary-derived hidden-volume root (the store bin dir) and warns that it is
    # accessible, so the run never reaches the clean headline this checks.
    verify_human = machine.succeed(f"nails --no-log-file --config {headless_config} verify")
    assert "No traces found" not in verify_human, verify_human
    assert "System appears clean" not in verify_human, verify_human
    assert "not proof of absence" in verify_human.lower(), verify_human
    print("✓ Verify headline is honest")

    print("\n=== Test 6: Status shows Active after activation ===")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")

    # The binary lives in the Nix store, so status needs the headless config to
    # resolve the hidden-volume state file rather than the binary-derived default.
    status_json = json.loads(
        machine.succeed(f"nails --config {headless_config} status --json")
    )["data"]
    assert status_json["state"]["kind"] == "active", \
        f"Expected active state, got: {status_json}"
    print(f"✓ Status shows {status_json['state']['kind']} after activation")

    print("\n=== Test 7: Default hidden logs are created and surfaced ===")
    machine.succeed("test -d /mnt/data/logs")
    machine.succeed("test -f /mnt/data/logs/nails.log")
    active_verbose = run_command_capture(
        "status-verify-active-verbose",
        f"nails --config {shlex.quote(headless_config)} status --details",
    )
    assert active_verbose["rc"] == 0, active_verbose
    assert "Overlay Mount Details:" in active_verbose["stdout"], active_verbose
    assert "Recent Logs:" in active_verbose["stdout"], active_verbose
    print("✓ Default hidden log directory/file are created and visible via status --details")

    print("\n=== Test 8: Non-root status stays truthful on unreadable state ===")
    machine.succeed("chown root:root /mnt/data/state.json")
    machine.succeed("chmod 600 /mnt/data/state.json")
    non_root = run_command_capture(
        "status-verify-non-root",
        "su - testuser -c "
        + shlex.quote(f"nails --config {headless_config} status --json"),
    )
    # An unreadable state file means the real state is unknown: status fails
    # closed with the invalid-state exit code rather than claiming inactive.
    assert non_root["rc"] == 6, non_root
    non_root_payload = json.loads(non_root["stdout"])["data"]
    state = non_root_payload["state"]
    assert state["kind"] == "unknown", non_root_payload
    assert non_root_payload["posture"] == "unknown", non_root_payload
    # The untrusted-load reason carries the specific failure.
    assert "Permission denied" in state["reason"], non_root_payload
    assert "/mnt/data/state.json" in state["reason"], non_root_payload
    assert_status_state("Active", config_path=headless_config)
    print("✓ Non-root status fails closed and reports the permission failure explicitly")

    print("\n=== Test 9: Status after deactivation ===")
    machine.crash()
    machine.start()
    machine.wait_for_unit("multi-user.target")

    status_json = json.loads(machine.succeed("nails status --json"))["data"]
    assert status_json["state"]["kind"] == "inactive", \
        f"Expected inactive after deactivation, got: {status_json}"
    print("✓ Status shows Inactive after deactivation")

    print("\n=== All Status/Verify Tests Passed ===")
  '';
}
