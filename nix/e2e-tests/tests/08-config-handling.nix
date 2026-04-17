# Test 08: Config Handling Edge Cases
# Tests --config flag, invalid configs, missing configs, and defaults

{ self, ... }:
let
  hiddenVolume = import ./../lib/hidden-volume.nix;
  testHelpers = import ./../lib/test-helpers.nix;
in {
  name = "config-handling";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # ============================================================================
    # TEST 1: --config with nonexistent path exits non-zero
    # ============================================================================
    print("\n=== Test 1: Nonexistent config path ===")
    machine.fail("nails --config /nonexistent/path/config.yaml status")
    print("✓ nails --config /nonexistent exits non-zero")

    # ============================================================================
    # TEST 2: --config with valid path works
    # ============================================================================
    print("\n=== Test 2: Valid config path ===")
    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    # Status with valid config should work
    machine.succeed(f"nails --config {headless_config} status")
    print("✓ nails --config /valid/path status works")

    # ============================================================================
    # TEST 3: nails status (no --config) works with defaults
    # ============================================================================
    print("\n=== Test 3: Default config (no --config) ===")
    status_output = machine.succeed("nails status")
    assert "Inactive" in status_output or "Active" in status_output or "INACTIVE" in status_output, \
        f"Expected status output with state info, got: {status_output}"
    print("✓ nails status (no --config) works with defaults")

    # ============================================================================
    # TEST 4: Invalid YAML config produces clear error
    # ============================================================================
    print("\n=== Test 4: Invalid YAML config ===")
    machine.succeed("echo '{{invalid yaml: [[[' > /tmp/bad-config.yaml")
    result = machine.execute("nails --config /tmp/bad-config.yaml status 2>&1")
    # Should exit non-zero
    machine.fail("nails --config /tmp/bad-config.yaml status")
    print("✓ Invalid YAML config produces error and exits non-zero")

    # ============================================================================
    # TEST 5: Config with wrong permissions still loads (nails runs as root)
    # ============================================================================
    print("\n=== Test 5: Config with restrictive permissions ===")
    machine.succeed(f"chmod 0400 {headless_config}")
    machine.succeed(f"nails --config {headless_config} status")
    print("✓ Config with 0400 permissions loads fine as root")

    machine.succeed(f"chmod 0000 {headless_config}")
    machine.succeed(f"nails --config {headless_config} status")
    print("✓ Config with 0000 permissions loads fine as root")

    # Restore for cleanup
    machine.succeed(f"chmod 0644 {headless_config}")

    # Cleanup
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    print("\n=== All Config Handling Tests Passed ===")
  '';
}
