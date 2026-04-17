# Test 04: Forensic Cleanliness Validation
# Tests that no forensic artifacts remain after deactivation - NFR19

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in {
  name = "forensic-clean";
  meta.tags = [ "forensic" ];

  nodes = {
    machine = { ... }: {
      imports = [ ./../../lib/vm-config.nix ];
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

    print("\n=== Capturing Baseline Filesystem State ===")
    machine.succeed("find /home /etc /var -type f 2>/dev/null | sort > /tmp/baseline-files.txt || true")
    machine.succeed("find /home /etc /var -type d 2>/dev/null | sort > /tmp/baseline-dirs.txt || true")
    print("✓ Baseline captured")

    print("\n=== Setting up Hidden Volume and Creating Markers ===")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
    machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
    print("✓ NAILS activated")

    machine.succeed("su - testuser -c 'echo FORENSIC_MARKER_SECRET > ~/forensic-test.txt'")
    print("✓ Created FORENSIC_MARKER_SECRET in home directory")

    machine.succeed("echo FORENSIC_MARKER_TEMP > /tmp/nails-temp-file")
    print("✓ Created FORENSIC_MARKER_TEMP in /tmp")

    machine.succeed("su - testuser -c 'echo FORENSIC_MARKER_HISTORY >> ~/.bash_history'")
    machine.succeed("su - testuser -c 'history -s FORENSIC_MARKER_HISTORY_CMD'")
    print("✓ Added FORENSIC_MARKER_HISTORY to shell history")

    machine.succeed("su - testuser -c 'test -f ~/forensic-test.txt'")
    machine.succeed("test -f /tmp/nails-temp-file")
    print("✓ Verified markers exist during active session")

    print("\n=== Deactivating and Cleaning Up ===")
    machine.execute("sudo nails deactivate; reboot", check_return=False, check_output=False)
    machine.wait_for_shutdown()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    print("✓ NAILS rebooted back to decoy state")

    status = json.loads(machine.succeed("nails status --json"))
    assert status["state"] == "Inactive", f"Expected Inactive status after reboot, got: {status}"
    print("✓ NAILS status reports Inactive after reboot")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
    print("✓ Hidden volume unmounted from decoy state")

    print("\n=== Forensic Analysis: Grep Scan ===")
    grep_result = machine.succeed("grep -r 'FORENSIC_MARKER' /home /etc /var /tmp /root 2>/dev/null || echo 'CLEAN'")
    if "FORENSIC_MARKER" in grep_result:
        print(f"FAIL: Found forensic markers: {grep_result}")
        assert False, "Forensic markers found after deactivation"
    else:
        print("✓ No FORENSIC_MARKER strings found on filesystem")

    print("\n=== Forensic Analysis: Sleuth Kit fls ===")
    fls_output = machine.succeed("fls -r /dev/vdb 2>/dev/null | grep -i 'nails\\|forensic\\|secret\\|hidden' || echo 'CLEAN'")
    if "CLEAN" not in fls_output:
        print(f"FAIL: Found NAILS artifacts in deleted files: {fls_output}")
        assert False, "Sleuth Kit found NAILS artifacts in deleted files"
    else:
        print("✓ No NAILS-related deleted files found")

    print("\n=== Forensic Analysis: Shell History ===")
    history_check = machine.succeed("cat /home/testuser/.bash_history 2>/dev/null || echo 'NO_HISTORY'")
    if "FORENSIC_MARKER" in history_check:
        print(f"FAIL: Found forensic markers in shell history: {history_check}")
        assert False, "Shell history contains forensic markers"
    else:
        print("✓ No FORENSIC_MARKER strings in shell history")

    print("\n=== Forensic Analysis: Filesystem Diff ===")
    machine.succeed("find /home /etc /var -type f 2>/dev/null | sort > /tmp/post-files.txt || true")
    machine.succeed("find /home /etc /var -type d 2>/dev/null | sort > /tmp/post-dirs.txt || true")

    file_diff = machine.succeed("diff /tmp/baseline-files.txt /tmp/post-files.txt || echo 'DIFF_FOUND'")
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
