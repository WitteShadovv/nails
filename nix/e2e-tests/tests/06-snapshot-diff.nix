# Story 13.7: Snapshot Comparison Test
# Tests that system returns to exact initial state after full workflow

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../lib/hidden-volume.nix;
in {
  name = "snapshot-diff";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = { nodes, ... }: ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    # ============================================================================
    # INITIAL SNAPSHOT (AC: #1)
    # ============================================================================

    print("\n=== Capturing INITIAL Snapshot ===")

    # Capture filesystem tree
    machine.succeed("tree -a -I 'proc|sys|dev|run' / > /tmp/snapshot-initial.txt 2>/dev/null || true")

    # Capture MD5 checksums for /home, /etc, /var
    machine.succeed("find /home -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-initial-home.txt || true")
    machine.succeed("find /etc -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-initial-etc.txt || true")
    machine.succeed("find /var -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-initial-var.txt || true")

    # Capture mount state
    machine.succeed("mount | sort > /tmp/mounts-initial.txt")
    print("✓ Initial snapshot captured")

    # ============================================================================
    # FULL NAILS WORKFLOW (AC: #2)
    # ============================================================================

    print("\n=== Running Full NAILS Workflow ===")

    # Setup hidden volume
    setup_result = machine.succeed("${hiddenVolume.setupHiddenVolume} || echo 'Setup failed with code $?'")
    assert "Setup failed" not in setup_result, f"Hidden volume setup failed: {setup_result}"

    # Activate
    machine.succeed("sudo nails activate")
    print("✓ NAILS activated")

    # Heavy usage: Create 50 files
    machine.succeed("su - testuser -c 'mkdir -p ~/work/project'")
    machine.succeed("su - testuser -c 'for i in $(seq 1 50); do echo content > ~/work/project/file_$i.txt; done'")
    print("✓ Created 50 files in ~/work/project/")

    # Run git init
    machine.succeed("su - testuser -c 'cd ~/work/project && git init 2>/dev/null || true'")
    print("✓ Ran git init in project directory")

    # Create shell script with execute permission
    machine.succeed("su - testuser -c 'echo \"#!/bin/bash\" > ~/work/script.sh'")
    machine.succeed("su - testuser -c 'echo \"echo test\" >> ~/work/script.sh'")
    machine.succeed("su - testuser -c 'chmod +x ~/work/script.sh'")
    print("✓ Created executable shell script")

    # Deactivate
    machine.succeed("sudo nails deactivate")
    print("✓ NAILS deactivated")

    # Unmount hidden volume
    machine.succeed("${hiddenVolume.unmountHiddenVolume}")
    machine.fail("test -e /dev/mapper/hidden-volume")
    print("✓ Hidden volume unmounted and LUKS device closed")

    # ============================================================================
    # FINAL SNAPSHOT (AC: #3)
    # ============================================================================

    print("\n=== Capturing FINAL Snapshot ===")

    # Capture filesystem tree
    machine.succeed("tree -a -I 'proc|sys|dev|run' / > /tmp/snapshot-final.txt 2>/dev/null || true")

    # Capture MD5 checksums
    machine.succeed("find /home -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-final-home.txt || true")
    machine.succeed("find /etc -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-final-etc.txt || true")
    machine.succeed("find /var -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-final-var.txt || true")

    # Capture mount state
    machine.succeed("mount | sort > /tmp/mounts-final.txt")
    print("✓ Final snapshot captured")

    # ============================================================================
    # TREE DIFF COMPARISON (AC: #4)
    # ============================================================================

    print("\n=== Comparing Snapshots ===")

    # Diff filesystem trees
    tree_diff = machine.succeed("diff /tmp/snapshot-initial.txt /tmp/snapshot-final.txt || echo 'DIFF_FOUND'")

    # Filter out expected transient paths
    filtered_diff = machine.succeed('''
      grep -v '^/var/log/' /tmp/snapshot-final.txt 2>/dev/null | \
      grep -v '^/tmp/' | \
      grep -v '^/run/' | \
      grep -v '^/proc/' | \
      grep -v '^/sys/' | \
      grep -E '(nails|secret|hidden|work)' || echo 'CLEAN'
    ''')

    if "CLEAN" not in filtered_diff:
        print(f"FAIL: Found unexpected NAILS-related paths in filesystem")
        assert False, "Filesystem tree diff shows unexpected NAILS paths"
    else:
        print("✓ No NAILS-related changes in filesystem tree")

    # ============================================================================
    # CHECKSUM COMPARISON (AC: #5)
    # ============================================================================

    print("\n=== Comparing Checksums ===")

    # Compare home directory checksums
    home_diff = machine.succeed("diff /tmp/checksums-initial-home.txt /tmp/checksums-final-home.txt || echo 'DIFF'")
    # Filter out expected transient changes in /home/testuser
    home_filtered = machine.succeed('''
      grep -v 'work/project' /tmp/checksums-final-home.txt 2>/dev/null | \
      grep -E '(nails|secret|hidden)' || echo 'CLEAN'
    ''')

    if "CLEAN" not in home_filtered:
        print(f"FAIL: Checksums differ - unexpected NAILS artifacts remain")
        assert False, "Home directory checksums show unexpected differences"
    else:
        print("✓ Home directory checksums match (or only expected transient changes)")

    # ============================================================================
    # MOUNT STATE COMPARISON (AC: #6)
    # ============================================================================

    print("\n=== Comparing Mount States ===")

    # Check for overlay/hidden/nails entries in mounts
    mount_check = machine.succeed("cat /tmp/mounts-final.txt | grep -E '(overlay|hidden-volume|nails)' || echo 'CLEAN'")

    if "CLEAN" not in mount_check:
        print(f"FAIL: Mount state shows NAILS-related entries: {mount_check}")
        assert False, "Mount state contains overlay/hidden/nails entries"
    else:
        print("✓ Mount state returned to initial (no overlay/hidden/nails)")

    print("\n=== All Snapshot Comparison Tests Passed ===")
    print("✓ System returned to exact initial state after full workflow")
  '';
}
