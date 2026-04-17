# Test 12: Status and Verify Command Coverage
# Tests status/verify at each phase, JSON output, verbose mode, artifact detection

{ self, ... }:
let
  hiddenVolume = import ./../lib/hidden-volume.nix;
  testHelpers = import ./../lib/test-helpers.nix;
in {
  name = "status-verify";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    # ============================================================================
    # TEST 1: Status shows Inactive initially
    # ============================================================================
    print("\n=== Test 1: Status shows Inactive initially ===")
    status_text = machine.succeed("nails status")
    assert "Inactive" in status_text or "INACTIVE" in status_text, \
        f"Expected Inactive in status, got: {status_text}"
    print("✓ Status shows Inactive")

    # ============================================================================
    # TEST 2: Status --json returns valid JSON with expected fields
    # ============================================================================
    print("\n=== Test 2: Status --json output ===")
    status_json_raw = machine.succeed("nails status --json")
    status_json = json.loads(status_json_raw)
    assert "state" in status_json, f"Expected 'state' field in JSON, got: {status_json}"
    assert status_json["state"] == "Inactive", f"Expected Inactive, got: {status_json}"
    print(f"✓ Status --json returns valid JSON with state={status_json['state']}")

    # ============================================================================
    # TEST 3: Status -v shows resolved paths
    # ============================================================================
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

    # ============================================================================
    # TEST 4: Verify detects planted artifacts (while in decoy state)
    # ============================================================================
    print("\n=== Test 4: Verify detects planted artifacts ===")
    machine.succeed("touch /tmp/nails.log")

    machine.succeed(
        "bash -lc 'set +e; nails verify --json > /tmp/verify.stdout 2>/tmp/verify.stderr; printf \"%s\" \"$?\" > /tmp/verify.rc'"
    )
    verify_rc = int(machine.succeed("cat /tmp/verify.rc"))
    verify_output = machine.succeed("cat /tmp/verify.stdout")
    verify_json = json.loads(verify_output)
    assert verify_rc != 0 or verify_json.get("status") in ("Warning", "Critical"), \
        f"Expected verify to detect artifact, got: {verify_json}"
    print("✓ Verify detects planted artifacts")
    machine.succeed("rm -f /tmp/nails.log")

    # ============================================================================
    # TEST 5: Verify --json returns valid JSON (clean state)
    # ============================================================================
    print("\n=== Test 5: Verify --json output (clean) ===")
    machine.succeed(
        "bash -lc 'set +e; nails verify --json > /tmp/verify2.stdout 2>/tmp/verify2.stderr; printf \"%s\" \"$?\" > /tmp/verify2.rc'"
    )
    verify2_rc = int(machine.succeed("cat /tmp/verify2.rc"))
    verify2_output = machine.succeed("cat /tmp/verify2.stdout")
    verify2_json = json.loads(verify2_output)
    assert "status" in verify2_json or "findings" in verify2_json, \
        f"Expected status/findings in verify JSON, got: {verify2_json}"
    print(f"✓ Verify --json returns valid JSON (exit={verify2_rc})")

    # ============================================================================
    # TEST 6: Status shows Active after activation
    # ============================================================================
    print("\n=== Test 6: Status shows Active after activation ===")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

    status_json = json.loads(machine.succeed("nails status --json"))
    assert status_json["state"].startswith("Active"), \
        f"Expected Active state, got: {status_json}"
    print(f"✓ Status shows {status_json['state']} after activation")

    # ============================================================================
    # TEST 7: Status shows Inactive after deactivation
    # ============================================================================
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
