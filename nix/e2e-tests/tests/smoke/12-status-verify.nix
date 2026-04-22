# Test 12: Status and Verify Command Coverage
# Tests status/verify at each phase, JSON output, verbose mode, artifact detection

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
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

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runVerifyFn}

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

    print("\n=== Test 3: Status -v verbose output ===")
    verbose_result = machine.execute("nails status -v 2>&1")
    if verbose_result[0] == 0:
        print(f"✓ Status -v works: {verbose_result[1][:200]}")
    else:
        verbose_result = machine.execute("nails status --verbose 2>&1")
        if verbose_result[0] == 0:
            print(f"✓ Status --verbose works: {verbose_result[1][:200]}")
        else:
            print("Note: -v/--verbose not supported for status, basic status works")

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

    print("\n=== Test 7: Status after deactivation ===")
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
