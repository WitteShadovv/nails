# Story 13.4: Basic Workflow Test (activate/deactivate)
# Tests the happy path: activate → user activities → deactivate

{ self, ... }:
let hiddenVolume = import ./../lib/hidden-volume.nix;
in {
  name = "basic-workflow";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];

      # Inject NAILS binary into VM
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
    import time

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # ============================================================================
    # PRE-CONDITION TESTS
    # ============================================================================

    print("\n=== Testing Pre-Conditions ===")

    # Setup hidden volume (machine.succeed fails automatically on error)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    # Verify hidden volume is mounted with expected structure
    machine.succeed("test -d /mnt/hidden-volume")
    machine.succeed("test -d /mnt/hidden-volume/home")
    machine.succeed("test -d /mnt/hidden-volume/.work/home")
    print("✓ Hidden volume is mounted at /mnt/hidden-volume")

    # Verify no overlays are mounted on /home, /etc, /var, or /nix
    machine.fail("mount | grep 'overlay on /home'")
    machine.fail("mount | grep 'overlay on /etc'")
    machine.fail("mount | grep 'overlay on /var'")
    machine.fail("mount | grep 'overlay on /nix'")
    print("✓ No overlays mounted on /home, /etc, /var, or /nix")

    # Verify NAILS status command runs
    # TODO: Once status command is implemented, check for "INACTIVE" in output
    machine.succeed("nails status")
    print("✓ NAILS status command runs (status output not yet implemented)")

    # ============================================================================
    # ACTIVATION TEST
    # ============================================================================

    print("\n=== Testing Activation ===")

    # Run nails activate and measure time
    start_time = time.time()
    machine.succeed("sudo nails activate -y")
    activation_time = time.time() - start_time
    print(f"Activation completed in {activation_time:.2f}s")

    # Verify activation completes in <60s
    assert activation_time < 60, f"Activation too slow: {activation_time:.2f}s (limit: 60s)"
    print(f"✓ Activation completed in <60s ({activation_time:.2f}s)")

    # Verify overlays are mounted on /home, /etc, /var, and /nix with correct options
    home_mount = machine.succeed("mount | grep 'overlay on /home' || true")
    etc_mount = machine.succeed("mount | grep 'overlay on /etc' || true")
    var_mount = machine.succeed("mount | grep 'overlay on /var' || true")
    nix_mount = machine.succeed("mount | grep 'overlay on /nix' || true")
    assert "overlay" in home_mount, "Overlay not mounted on /home"
    assert "overlay" in etc_mount, "Overlay not mounted on /etc"
    assert "overlay" in var_mount, "Overlay not mounted on /var"
    assert "overlay" in nix_mount, "Overlay not mounted on /nix"
    # Verify overlay points to hidden volume upper/work directories
    assert "/mnt/hidden-volume/home" in home_mount, "Overlay upperdir not pointing to hidden volume"
    assert "/mnt/hidden-volume/etc" in etc_mount, "Overlay upperdir not pointing to hidden volume"
    assert "/mnt/hidden-volume/var" in var_mount, "Overlay upperdir not pointing to hidden volume"
    assert "/mnt/hidden-volume/nix" in nix_mount, "Overlay upperdir not pointing to hidden volume"
    print("✓ Overlays mounted on /home, /etc, /var, and /nix with correct upperdir")

    # Verify store path is read-only for regular processes (defense-in-depth)
    machine.fail("touch ${builtins.storeDir}/test-write-should-fail")
    print("✓ store path is read-only (EROFS)")

    # Verify nix operations work during active session
    machine.succeed("nix-instantiate --eval -E '1+1'")
    print("✓ Nix operations work during active session")

    # Verify NAILS status command runs after activation
    # TODO: Once status command is implemented, check for "ACTIVE" in output
    machine.succeed("nails status")
    print("✓ NAILS status command runs (status output not yet implemented)")

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
    machine.succeed("test -f /mnt/hidden-volume/home/testuser/secret-document.txt")
    machine.succeed("test -d /mnt/hidden-volume/home/testuser/hidden-project")
    print("✓ Files stored in hidden volume overlay")

    # ============================================================================
    # DEACTIVATION TEST
    # ============================================================================

    print("\n=== Testing Deactivation ===")

    # Run nails deactivate and measure time
    start_time = time.time()
    machine.succeed("sudo nails deactivate")
    deactivation_time = time.time() - start_time
    print(f"Deactivation completed in {deactivation_time:.2f}s")

    # Verify deactivation completes in <5s
    assert deactivation_time < 5, f"Deactivation too slow: {deactivation_time:.2f}s (limit: 5s)"
    print(f"✓ Deactivation completed in <5s ({deactivation_time:.2f}s)")

    # Verify overlays are unmounted from /home, /etc, /var, and /nix
    machine.fail("mount | grep 'overlay on /home'")
    machine.fail("mount | grep 'overlay on /etc'")
    machine.fail("mount | grep 'overlay on /var'")
    machine.fail("mount | grep 'overlay on /nix'")
    print("✓ Overlays unmounted from /home, /etc, /var, and /nix")

    # Verify original /nix is restored (nix operations still work)
    machine.succeed("nix-instantiate --eval -E '1+1'")
    print("✓ Original /nix restored after deactivation")

    # Verify NAILS status command runs after deactivation
    # TODO: Once status command is implemented, check for "INACTIVE" in output
    machine.succeed("nails status")
    print("✓ NAILS status command runs (status output not yet implemented)")

    # ============================================================================
    # FORENSIC CLEANLINESS TEST (files invisible)
    # ============================================================================

    print("\n=== Testing Forensic Cleanliness ===")

    # Verify user files are no longer visible in home directory
    machine.fail("su - testuser -c 'test -f ~/secret-document.txt'")
    machine.fail("su - testuser -c 'test -d ~/hidden-project'")
    print("✓ User files are no longer visible in home directory")

    # Verify files still exist in hidden volume (data preserved)
    machine.succeed("test -f /mnt/hidden-volume/home/testuser/secret-document.txt")
    machine.succeed("test -d /mnt/hidden-volume/home/testuser/hidden-project")
    print("✓ Data preserved in hidden volume")

    # Cleanup - unmount hidden volume (LUKS device closure is test infrastructure only)
    # Note: In production, the hidden volume would remain open for the next session
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")

    print("\n=== All Tests Passed ===")
  '';
}
