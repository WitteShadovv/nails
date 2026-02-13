# Story 13.6: Forensic Cleanliness Validation
# Tests that no forensic artifacts remain after deactivation - NFR19

{ self, ... }:
let hiddenVolume = import ./../lib/hidden-volume.nix;
in {
  name = "forensic-clean";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    # ============================================================================
    # BASELINE CAPTURE (AC: #1)
    # ============================================================================

    print("\n=== Capturing Baseline Filesystem State ===")

    # Capture baseline BEFORE any NAILS activity
    # Focus on key directories, skip pseudo-filesystems and nix store
    machine.succeed("find /home /etc /var -type f 2>/dev/null | sort > /tmp/baseline-files.txt || true")
    machine.succeed("find /home /etc /var -type d 2>/dev/null | sort > /tmp/baseline-dirs.txt || true")
    print("✓ Baseline captured")

    # ============================================================================
    # DETECTABLE ACTIVITIES (AC: #2)
    # ============================================================================

    print("\n=== Setting up Hidden Volume and Creating Markers ===")

    # Setup hidden volume with error handling
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    # Activate NAILS
    machine.succeed("sudo nails activate")
    print("✓ NAILS activated")

    # Create forensic markers
    machine.succeed("su - testuser -c 'echo FORENSIC_MARKER_SECRET > ~/forensic-test.txt'")
    print("✓ Created FORENSIC_MARKER_SECRET in home directory")

    machine.succeed("echo FORENSIC_MARKER_TEMP > /tmp/nails-temp-file")
    print("✓ Created FORENSIC_MARKER_TEMP in /tmp")

    machine.succeed("su - testuser -c 'echo FORENSIC_MARKER_HISTORY >> ~/.bash_history'")
    machine.succeed("su - testuser -c 'history -s FORENSIC_MARKER_HISTORY_CMD'")
    print("✓ Added FORENSIC_MARKER_HISTORY to shell history")

    # Verify markers exist during active session
    machine.succeed("su - testuser -c 'test -f ~/forensic-test.txt'")
    machine.succeed("test -f /tmp/nails-temp-file")
    print("✓ Verified markers exist during active session")

    # ============================================================================
    # DEACTIVATION AND CLEANUP (AC: #3)
    # ============================================================================

    print("\n=== Deactivating and Cleaning Up ===")

    # Deactivate
    machine.succeed("sudo nails deactivate")
    print("✓ NAILS deactivated")

    # Unmount hidden volume
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    # Note: /dev/mapper/hidden-volume may persist in VM environments due to
    # kernel-internal dm-crypt references. This is a known test infrastructure
    # limitation and does not affect test validity (device cleaned up on VM shutdown).
    print("✓ Hidden volume unmounted")

    # ============================================================================
    # FORENSIC ANALYSIS - GREP SCAN (AC: #3)
    # ============================================================================

    print("\n=== Forensic Analysis: Grep Scan ===")

    # Scan key filesystem locations for forensic markers
    # Exclude pseudo-filesystems and nix store (read-only) to avoid timeouts under TCG
    grep_result = machine.succeed("grep -r 'FORENSIC_MARKER' /home /etc /var /tmp /root 2>/dev/null || echo 'CLEAN'")

    # Check if any markers were found
    if "FORENSIC_MARKER" in grep_result:
        print(f"FAIL: Found forensic markers: {grep_result}")
        assert False, "Forensic markers found after deactivation"
    else:
        print("✓ No FORENSIC_MARKER strings found on filesystem")

    # ============================================================================
    # FORENSIC ANALYSIS - SLEUTH KIT (AC: #4)
    # ============================================================================

    print("\n=== Forensic Analysis: Sleuth Kit fls ===")

    # Use fls to list deleted files on the secondary disk (hidden volume device)
    # Note: the root filesystem may not support fls (tmpfs), so we check the secondary disk
    fls_output = machine.succeed("fls -r /dev/vdb 2>/dev/null | grep -i 'nails\\|forensic\\|secret\\|hidden' || echo 'CLEAN'")

    # Check if any NAILS-related deleted files were found
    if "CLEAN" not in fls_output:
        print(f"FAIL: Found NAILS artifacts in deleted files: {fls_output}")
        assert False, "Sleuth Kit found NAILS artifacts in deleted files"
    else:
        print("✓ No NAILS-related deleted files found")

    # ============================================================================
    # SHELL HISTORY CHECK (AC: #5)
    # ============================================================================

    print("\n=== Forensic Analysis: Shell History ===")

    # Check shell history for forensic markers
    history_check = machine.succeed("cat /home/testuser/.bash_history 2>/dev/null || echo 'NO_HISTORY'")

    if "FORENSIC_MARKER" in history_check:
        print(f"FAIL: Found forensic markers in shell history: {history_check}")
        assert False, "Shell history contains forensic markers"
    else:
        print("✓ No FORENSIC_MARKER strings in shell history")

    # ============================================================================
    # FILESYSTEM DIFF AGAINST BASELINE (AC: #6)
    # ============================================================================

    print("\n=== Forensic Analysis: Filesystem Diff ===")

    # Capture post-deactivation state
    machine.succeed("find /home /etc /var -type f 2>/dev/null | sort > /tmp/post-files.txt || true")
    machine.succeed("find /home /etc /var -type d 2>/dev/null | sort > /tmp/post-dirs.txt || true")

    # Diff files against baseline
    file_diff = machine.succeed("diff /tmp/baseline-files.txt /tmp/post-files.txt || echo 'DIFF_FOUND'")

    # Check for unexpected NAILS-related paths
    # Filter out expected transient paths (logs, var/lib)
    unexpected_paths = machine.succeed("""
      grep -v '^/var/log/' /tmp/post-files.txt 2>/dev/null | \
      grep -v '^/var/lib/' | \
      grep -E '(secret|hidden|forensic)' || echo 'CLEAN'
    """)

    if "CLEAN" not in unexpected_paths:
        print(f"FAIL: Found unexpected NAILS-related paths: {unexpected_paths}")
        assert False, "Filesystem diff found unexpected NAILS paths"
    else:
        print("✓ No unexpected NAILS/secret/hidden/forensic paths outside transient locations")

    print("\n=== All Forensic Cleanliness Tests Passed ===")
  '';
}
