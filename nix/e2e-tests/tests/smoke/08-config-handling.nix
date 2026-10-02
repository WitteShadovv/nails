# Test 08: Config Handling Edge Cases
# Tests --config flag, invalid configs, missing configs, and defaults

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  invalidTypeFixture = ./../../fixtures/configs/invalid-type.toml;
in
{
  name = "config-handling";
  meta.tags = [ "smoke" ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    print("\n=== Test 1: Nonexistent config path ===")
    code, output = machine.execute("nails --no-log-file --config /nonexistent/path/config.toml status 2>&1")
    assert code == 3, f"expected exit 3 for a missing --config, got {code}: {output!r}"
    assert output.strip() == (
        "error: config file not found: /nonexistent/path/config.toml "
        "(run `nails init <root>` or pass --config)"
    ), f"expected exactly one error line, got: {output!r}"
    print("✓ nails --config /nonexistent exits 3 with one error line")

    print("\n=== Test 2: Valid config path ===")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(f"nails --config {headless_config} status")
    print("✓ nails --config /valid/path status works")

    print("\n=== Test 3: Default config (no --config) ===")
    status_output = machine.succeed("nails status")
    assert "Inactive" in status_output or "Active" in status_output or "INACTIVE" in status_output, \
        f"Expected status output with state info, got: {status_output}"
    print("✓ nails status (no --config) works with defaults")

    print("\n=== Test 4: Invalid TOML config ===")
    machine.succeed("cp ${invalidTypeFixture} /tmp/bad-config.toml")
    code, output = machine.execute("nails --config /tmp/bad-config.toml status 2>&1")
    assert code == 3, f"expected exit 3 for an invalid config, got {code}: {output!r}"
    assert "invalid config /tmp/bad-config.toml: line 3" in output, output
    print("✓ Invalid TOML config exits 3 and names the line")

    print("\n=== Test 5: Config with restrictive permissions ===")
    machine.succeed(f"chmod 0400 {headless_config}")
    machine.succeed(f"nails --config {headless_config} status")
    print("✓ Config with 0400 permissions loads fine as root")

    machine.succeed(f"chmod 0000 {headless_config}")
    machine.succeed(f"nails --config {headless_config} status")
    print("✓ Config with 0000 permissions loads fine as root")

    machine.succeed(f"chmod 0644 {headless_config}")
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    print("\n=== All Config Handling Tests Passed ===")
  '';
}
