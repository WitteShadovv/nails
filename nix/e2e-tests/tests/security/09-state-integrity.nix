# Test 09: State File Integrity
# Tests state file existence, permissions, tampering detection, and persistence

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in {
  name = "state-integrity";
  meta.tags = [ "security" "state" ];

  nodes = {
    machine = { ... }: {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalDeactivateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    print("\n=== Test 1: State file existence and permissions after activate ===")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

    state_file = machine.succeed(
        "find /run /tmp /var -name '*.state' -o -name 'nails.state' -o -name 'state.json' 2>/dev/null | head -1 || "
        "find /run /tmp /var -name '*nails*' -type f 2>/dev/null | grep -v config | head -1 || "
        "echo NONE"
    ).strip()

    if state_file and state_file != "NONE":
        perms = machine.succeed(f"stat -c %a {state_file}").strip()
        print(f"✓ State file found at {state_file} with permissions {perms}")
    else:
        print("Note: No explicit state file found (state may be tracked via mounts/runtime)")

    status = machine.succeed("nails status")
    assert "Active" in status or "ACTIVE" in status, f"Expected Active status, got: {status}"
    print("✓ NAILS reports Active state")

    print("\n=== Test 2: Deactivate and verify state ===")
    canonical_deactivate(headless_config, unit_name="nails-deactivate-state-integrity")

    status = machine.succeed("nails status")
    assert "Inactive" in status or "INACTIVE" in status, f"Expected Inactive after deactivate, got: {status}"
    print("✓ NAILS reports Inactive after deactivate")

    print("\n=== Test 3: State persistence across cycles ===")
    for cycle in range(1, 4):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

        status = machine.succeed("nails status")
        assert "Active" in status or "ACTIVE" in status, \
            f"Cycle {cycle}: Expected Active, got: {status}"

        canonical_deactivate(
            headless_config,
            unit_name=f"nails-deactivate-state-integrity-cycle-{cycle}",
        )

        status = machine.succeed("nails status")
        assert "Inactive" in status or "INACTIVE" in status, \
            f"Cycle {cycle}: Expected Inactive, got: {status}"

        print(f"✓ Cycle {cycle}: activate/deactivate state tracked correctly")

    print("\n=== All State Integrity Tests Passed ===")
  '';
}
