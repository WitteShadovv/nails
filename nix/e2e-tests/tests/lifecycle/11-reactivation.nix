# Test 11: Re-activation Workflow
# Tests activate -> deactivate -> activate again with data persistence

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in {
  name = "reactivation";
  meta.tags = [ "lifecycle" ];

  nodes = {
    machine = { ... }: {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    print("\n=== Phase 1: First Activation ===")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
    machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")

    machine.succeed("su - testuser -c 'echo REACTIVATION_DATA_1 > ~/reactivation-test.txt'")
    machine.succeed("su - testuser -c 'mkdir -p ~/reactivation-project/src'")
    machine.succeed("su - testuser -c 'echo REACTIVATION_CODE_1 > ~/reactivation-project/src/main.py'")
    machine.succeed("su - testuser -c 'test -f ~/reactivation-test.txt'")
    print("✓ Created data during first activation")

    machine.succeed("test -f /mnt/hidden-volume/home/testuser/reactivation-test.txt")
    print("✓ Data stored in hidden volume overlay")

    print("\n=== Phase 2: Deactivate ===")
    canonical_deactivate(headless_config, unit_name="nails-deactivate-reactivation-phase-2")

    machine.fail("su - testuser -c 'test -f ~/reactivation-test.txt'")
    machine.fail("su - testuser -c 'test -d ~/reactivation-project'")
    print("✓ Data not visible in decoy state")

    print("\n=== Phase 3: Re-activation ===")
    machine.succeed("""${hiddenVolume.mountHiddenVolume}""")

    machine.succeed("test -f /mnt/hidden-volume/home/testuser/reactivation-test.txt")
    content = machine.succeed("cat /mnt/hidden-volume/home/testuser/reactivation-test.txt").strip()
    assert "REACTIVATION_DATA_1" in content, f"Expected data in hidden volume, got: {content}"
    print("✓ Data persists in hidden volume after deactivation")

    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
    machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")

    machine.succeed("su - testuser -c 'test -f ~/reactivation-test.txt'")
    content = machine.succeed("su - testuser -c 'cat ~/reactivation-test.txt'").strip()
    assert "REACTIVATION_DATA_1" in content, f"Expected original data, got: {content}"

    machine.succeed("su - testuser -c 'test -f ~/reactivation-project/src/main.py'")
    code = machine.succeed("su - testuser -c 'cat ~/reactivation-project/src/main.py'").strip()
    assert "REACTIVATION_CODE_1" in code, f"Expected original code, got: {code}"
    print("✓ Previous data is accessible after re-activation")

    machine.succeed("su - testuser -c 'echo REACTIVATION_DATA_2 > ~/reactivation-test2.txt'")
    print("✓ Created additional data during re-activation")

    print("\n=== Phase 4: Final Deactivate ===")
    canonical_deactivate(headless_config, unit_name="nails-deactivate-reactivation-phase-4")

    machine.fail("su - testuser -c 'test -f ~/reactivation-test.txt'")
    machine.fail("su - testuser -c 'test -f ~/reactivation-test2.txt'")
    machine.fail("su - testuser -c 'test -d ~/reactivation-project'")
    machine.fail("mount | grep 'overlay on /home'")
    print("✓ All data cleaned after final deactivation")

    status = machine.succeed("nails status")
    assert "Inactive" in status or "INACTIVE" in status, f"Expected Inactive, got: {status}"
    print("✓ NAILS reports Inactive")

    print("\n=== All Re-activation Tests Passed ===")
  '';
}
