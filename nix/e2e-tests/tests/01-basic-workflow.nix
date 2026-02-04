# Story 13.4: Basic Workflow Test (activate/deactivate)
# Tests the happy path: activate → user activities → deactivate

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../lib/hidden-volume.nix;
in {
  name = "basic-workflow";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];

      # Inject NAILS binary into VM
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = { nodes, ... }: ''
    import time

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # ============================================================================
    # PRE-CONDITION TESTS
    # ============================================================================

    print("\n=== Testing Pre-Conditions ===")

    # Setup hidden volume
    machine.succeed("${hiddenVolume.setupHiddenVolume}")

    # Verify hidden volume is mounted
    machine.succeed("test -d /mnt/hidden-volume")
    machine.succeed("test -f /mnt/hidden-volume/nails/config.toml")
    print("✓ Hidden volume is mounted at /mnt/hidden-volume")

    # Verify no overlays are mounted on /home or /etc
    machine.fail("mount | grep 'overlay on /home'")
    machine.fail("mount | grep 'overlay on /etc'")
    print("✓ No overlays mounted on /home or /etc")

    # Verify NAILS status reports INACTIVE state
    status = machine.succeed("nails status")
    assert "INACTIVE" in status, f"Expected INACTIVE, got: {status}"
    print("✓ NAILS status reports INACTIVE state")

    # ============================================================================
    # ACTIVATION TEST
    # ============================================================================

    print("\n=== Testing Activation ===")

    # Run nails activate and measure time
    start_time = time.time()
    machine.succeed("nails activate")
    activation_time = time.time() - start_time
    print(f"Activation completed in {activation_time:.2f}s")

    # Verify activation completes in <60s
    assert activation_time < 60, f"Activation too slow: {activation_time:.2f}s (limit: 60s)"
    print(f"✓ Activation completed in <60s ({activation_time:.2f}s)")

    # Verify overlays are mounted on /home and /etc
    home_mount = machine.succeed("mount | grep 'overlay on /home' || true")
    etc_mount = machine.succeed("mount | grep 'overlay on /etc' || true")
    assert "overlay" in home_mount, "Overlay not mounted on /home"
    assert "overlay" in etc_mount, "Overlay not mounted on /etc"
    print("✓ Overlays mounted on /home and /etc")

    # Verify NAILS status reports ACTIVE state
    status = machine.succeed("nails status")
    assert "ACTIVE" in status, f"Expected ACTIVE, got: {status}"
    print("✓ NAILS status reports ACTIVE state")

    # ============================================================================
    # USER ACTIVITIES TEST
    # ============================================================================

    print("\n=== Testing User Activities ===")

    # Switch to testuser for realistic user activities
    machine.succeed("su - testuser -c 'echo \"This is a secret document\" > ~/secret-document.txt'")
    print("✓ Created secret-document.txt in home directory")

    machine.succeed("su - testuser -c 'mkdir -p ~/hidden-project/src'")
    machine.succeed("su - testuser -c 'echo \"print(\\\"Hello World\\\")\" > ~/hidden-project/src/main.py'")
    print("✓ Created hidden-project/ directory with files")

    # Verify files persist during active session
    machine.succeed("su - testuser -c 'test -f ~/secret-document.txt'")
    machine.succeed("su - testuser -c 'test -d ~/hidden-project/src'")
    machine.succeed("su - testuser -c 'test -f ~/hidden-project/src/main.py'")
    content = machine.succeed("su - testuser -c 'cat ~/secret-document.txt'")
    assert "secret document" in content, "File content doesn't match"
    print("✓ Files persist during active session")

    # Verify files exist in overlay upper directory
    machine.succeed("test -f /mnt/hidden-volume/nails/overlay/home/upper/testuser/secret-document.txt")
    machine.succeed("test -d /mnt/hidden-volume/nails/overlay/home/upper/testuser/hidden-project")
    print("✓ Files stored in hidden volume overlay")

    # ============================================================================
    # DEACTIVATION TEST
    # ============================================================================

    print("\n=== Testing Deactivation ===")

    # Run nails deactivate and measure time
    start_time = time.time()
    machine.succeed("nails deactivate")
    deactivation_time = time.time() - start_time
    print(f"Deactivation completed in {deactivation_time:.2f}s")

    # Verify deactivation completes in <5s
    assert deactivation_time < 5, f"Deactivation too slow: {deactivation_time:.2f}s (limit: 5s)"
    print(f"✓ Deactivation completed in <5s ({deactivation_time:.2f}s)")

    # Verify overlays are unmounted from /home and /etc
    machine.fail("mount | grep 'overlay on /home'")
    machine.fail("mount | grep 'overlay on /etc'")
    print("✓ Overlays unmounted from /home and /etc")

    # Verify NAILS status reports INACTIVE state
    status = machine.succeed("nails status")
    assert "INACTIVE" in status, f"Expected INACTIVE, got: {status}"
    print("✓ NAILS status reports INACTIVE state")

    # ============================================================================
    # FORENSIC CLEANLINESS TEST (files invisible)
    # ============================================================================

    print("\n=== Testing Forensic Cleanliness ===")

    # Verify user files are no longer visible in home directory
    machine.fail("su - testuser -c 'test -f ~/secret-document.txt'")
    machine.fail("su - testuser -c 'test -d ~/hidden-project'")
    print("✓ User files are no longer visible in home directory")

    # Verify files still exist in hidden volume (data preserved)
    machine.succeed("test -f /mnt/hidden-volume/nails/overlay/home/upper/testuser/secret-document.txt")
    machine.succeed("test -d /mnt/hidden-volume/nails/overlay/home/upper/testuser/hidden-project")
    print("✓ Data preserved in hidden volume")

    # Cleanup
    machine.succeed("${hiddenVolume.unmountHiddenVolume}")

    print("\n=== All Tests Passed ===")
  '';
}
