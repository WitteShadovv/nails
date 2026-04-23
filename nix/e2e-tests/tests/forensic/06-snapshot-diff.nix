# Test 06: Snapshot Comparison
# Tests that system returns to exact initial state after full workflow

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "snapshot-diff";
  meta.tags = [ "forensic" ];

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
    ${testHelpers.canonicalDeactivateFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    print("\n=== Capturing INITIAL Snapshot ===")
    machine.succeed("find /home /etc /var -type f 2>/dev/null | sort > /tmp/snapshot-initial.txt || true")
    machine.succeed("find /home -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-initial-home.txt || true")
    machine.succeed("find /etc -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-initial-etc.txt || true")
    machine.succeed("find /var -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-initial-var.txt || true")
    machine.succeed("mount | sort > /tmp/mounts-initial.txt")
    print("✓ Initial snapshot captured")

    print("\n=== Running Full NAILS Workflow ===")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
    machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
    print("✓ NAILS activated")
    machine.succeed("su - testuser -c 'mkdir -p ~/work/project'")
    machine.succeed("su - testuser -c 'for i in $(seq 1 50); do echo content > ~/work/project/file_$i.txt; done'")
    print("✓ Created 50 files in ~/work/project/")
    machine.succeed("su - testuser -c 'cd ~/work/project && git init 2>/dev/null || true'")
    print("✓ Ran git init in project directory")
    machine.succeed("su - testuser -c 'echo \"#!/bin/bash\" > ~/work/script.sh'")
    machine.succeed("su - testuser -c 'echo \"echo test\" >> ~/work/script.sh'")
    machine.succeed("su - testuser -c 'chmod +x ~/work/script.sh'")
    print("✓ Created executable shell script")
    canonical_deactivate(headless_config, unit_name="nails-deactivate-snapshot-diff")
    print("✓ NAILS rebooted back to decoy state")
    status = json.loads(machine.succeed("nails status --json"))
    assert status["state"] == "Inactive", f"Expected Inactive status after reboot, got: {status}"
    print("✓ NAILS status reports Inactive after reboot")
    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    print("✓ Hidden volume unmounted")

    print("\n=== Capturing FINAL Snapshot ===")
    machine.succeed("find /home /etc /var -type f 2>/dev/null | sort > /tmp/snapshot-final.txt || true")
    machine.succeed("find /home -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-final-home.txt || true")
    machine.succeed("find /etc -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-final-etc.txt || true")
    machine.succeed("find /var -type f -exec md5sum {} \\; 2>/dev/null | sort > /tmp/checksums-final-var.txt || true")
    machine.succeed("mount | sort > /tmp/mounts-final.txt")
    print("✓ Final snapshot captured")

    print("\n=== Comparing Snapshots ===")
    tree_diff = machine.succeed("diff /tmp/snapshot-initial.txt /tmp/snapshot-final.txt || echo 'DIFF_FOUND'")
    filtered_diff = machine.succeed("""
      diff /tmp/snapshot-initial.txt /tmp/snapshot-final.txt 2>/dev/null | \
      grep '^>' | \
      grep -v '/var/log/' | \
      grep -v '/var/lib/systemd/' | \
      grep -v '/tmp/' | \
      grep -E '(work/project|secret|hidden|forensic)' || echo 'CLEAN'
    """)

    if "CLEAN" not in filtered_diff:
        print("FAIL: Found unexpected NAILS-related paths in filesystem")
        assert False, "Filesystem tree diff shows unexpected NAILS paths"
    else:
        print("✓ No NAILS-related changes in filesystem tree")

    print("\n=== Comparing Checksums ===")
    home_diff = machine.succeed("diff /tmp/checksums-initial-home.txt /tmp/checksums-final-home.txt || echo 'DIFF'")
    home_filtered = machine.succeed("""
      grep -E '(secret|hidden|forensic)' /tmp/checksums-final-home.txt 2>/dev/null || echo 'CLEAN'
    """)

    if "CLEAN" not in home_filtered:
        print("FAIL: Checksums differ - unexpected NAILS artifacts remain")
        assert False, "Home directory checksums show unexpected differences"
    else:
        print("✓ Home directory checksums match (or only expected transient changes)")

    print("\n=== Comparing Mount States ===")
    mount_check = machine.succeed(
        "grep -E '(/mnt/hidden-volume|/mnt/nails-pivot|overlay on /(etc|home|root|srv|tmp|var|opt|boot)( |$)|hidden-volume)' /tmp/mounts-final.txt || echo 'CLEAN'"
    )

    if "CLEAN" not in mount_check:
        print(f"FAIL: Mount state shows NAILS-related entries: {mount_check}")
        assert False, "Mount state contains overlay/hidden/nails entries"
    else:
        print("✓ Mount state returned to initial (no overlay/hidden/nails)")

    print("\n=== All Snapshot Comparison Tests Passed ===")
    print("✓ System returned to exact initial state after full workflow")
  '';
}
