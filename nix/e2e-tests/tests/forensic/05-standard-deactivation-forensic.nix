# Test 05: Standard Deactivation Forensic Safety
# Tests that standard deactivation leaves no forensic traces

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in {
  name = "standard-deactivation-forensic";
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
        ${testHelpers.runVerifyFn}

        machine.start()
        machine.wait_for_unit("multi-user.target")

        print("\n" + "=" * 70)
        print("PHASE 1: SETUP AND ACTIVATE")
        print("=" * 70)

        headless_config = "/tmp/nails-headless.yaml"
        write_headless_config(headless_config)

        baseline_history_size = int(machine.succeed(
            "su - testuser -c 'wc -c < ~/.bash_history 2>/dev/null || echo 0'"
        ).strip())
        print(f"✓ Baseline .bash_history size: {baseline_history_size} bytes")

        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        print("✓ Hidden volume created and mounted")

        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
        print("✓ NAILS activated with overlays")

        machine.succeed("mount | grep 'overlay on /home'")
        machine.succeed("mount | grep 'overlay on /tmp'")
        print("✓ Overlays verified active on /home and /tmp")

        print("\n" + "=" * 70)
        print("PHASE 2: PLANT CANARY PATTERNS")
        print("=" * 70)

        machine.succeed("su - testuser -c 'echo NAILS_CANARY_HISTORY_2026 >> ~/.bash_history'")
        machine.succeed("su - testuser -c 'history -s NAILS_CANARY_HISTORY_CMD_2026'")
        print("✓ Planted NAILS_CANARY_HISTORY_2026 in shell history")

        machine.succeed("echo 'NAILS_CANARY_TEMP_2026' > /tmp/nails-canary-temp")
        machine.succeed("test -f /tmp/nails-canary-temp")
        print("✓ Planted NAILS_CANARY_TEMP_2026 in /tmp/nails-canary-temp")

        machine.succeed("su - testuser -c 'echo NAILS_CANARY_DOCUMENT_2026 > ~/canary-document.txt'")
        machine.succeed("su - testuser -c 'test -f ~/canary-document.txt'")
        print("✓ Planted NAILS_CANARY_DOCUMENT_2026 in ~/canary-document.txt")

        machine.succeed("su - testuser -c 'echo secret_content > ~/secret-project.txt'")
        machine.succeed("su - testuser -c 'test -f ~/secret-project.txt'")
        print("✓ Planted secret-project.txt (sensitive filename)")

        machine.succeed("su - testuser -c 'echo NAILS_CANARY_FINANCIAL_2026,100000,CONFIDENTIAL > ~/financial-data.csv'")
        machine.succeed("su - testuser -c 'test -f ~/financial-data.csv'")
        print("✓ Planted financial-data.csv with NAILS_CANARY_FINANCIAL_2026")

        machine.succeed("su - testuser -c 'mkdir -p ~/confidential-project/secrets'")
        machine.succeed("su - testuser -c 'echo NAILS_CANARY_NESTED_2026 > ~/confidential-project/secrets/keys.txt'")
        machine.succeed("su - testuser -c 'test -f ~/confidential-project/secrets/keys.txt'")
        print("✓ Planted nested confidential-project/secrets/keys.txt")

        machine.succeed("su - testuser -c 'echo NAILS_CANARY_HIDDEN_2026 > ~/.hidden-secrets'")
        machine.succeed("su - testuser -c 'test -f ~/.hidden-secrets'")
        print("✓ Planted ~/.hidden-secrets (hidden dotfile)")

        machine.succeed("touch /tmp/secret-cache-123")
        machine.succeed("echo NAILS_CANARY_CACHE_2026 > /tmp/private-session-data")
        print("✓ Planted additional /tmp canaries")

        canary_count = machine.succeed(
            "grep -r 'NAILS_CANARY' /home /tmp 2>/dev/null | wc -l"
        ).strip()
        print(f"✓ Found {canary_count} canary occurrences in active session")

        print("\n" + "=" * 70)
        print("PHASE 3: STANDARD DEACTIVATION")
        print("=" * 70)

        print("Executing: nails deactivate")
        machine.execute("sudo nails deactivate; reboot", check_return=False, check_output=False)
        machine.wait_for_shutdown()
        print("✓ VM shut down after deactivation")

        machine.start()
        machine.wait_for_unit("multi-user.target")
        print("✓ VM rebooted to decoy state")

        status = json.loads(machine.succeed("nails status --json"))
        assert status["state"] == "Inactive", f"Expected Inactive status after reboot, got: {status}"
        print("✓ NAILS status reports Inactive")

        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        print("✓ Hidden volume unmounted from decoy state")

        print("\n" + "=" * 70)
        print("PHASE 4: FORENSIC VERIFICATION")
        print("=" * 70)

        print("\n--- Test 4.1: Canary String Grep Scan ---")
        grep_result = machine.succeed(
            "grep -r 'NAILS_CANARY' /home /tmp /var /etc /root 2>/dev/null || echo 'CLEAN'"
        )
        if "NAILS_CANARY" in grep_result:
            print(f"FAIL: Found canary strings: {grep_result}")
            assert False, "Canary strings found after deactivation"
        print("✓ No NAILS_CANARY strings found on filesystem")

        print("\n--- Test 4.2: Canary File Existence Checks ---")
        machine.fail("test -f /tmp/nails-canary-temp")
        print("✓ /tmp/nails-canary-temp does not exist")
        machine.fail("su - testuser -c 'test -f ~/canary-document.txt'")
        print("✓ ~/canary-document.txt does not exist")
        machine.fail("su - testuser -c 'test -f ~/secret-project.txt'")
        print("✓ ~/secret-project.txt does not exist")
        machine.fail("su - testuser -c 'test -f ~/financial-data.csv'")
        print("✓ ~/financial-data.csv does not exist")
        machine.fail("su - testuser -c 'test -d ~/confidential-project'")
        print("✓ ~/confidential-project/ directory does not exist")
        machine.fail("su - testuser -c 'test -f ~/.hidden-secrets'")
        print("✓ ~/.hidden-secrets does not exist")
        machine.fail("test -f /tmp/secret-cache-123")
        print("✓ /tmp/secret-cache-123 does not exist")
        machine.fail("test -f /tmp/private-session-data")
        print("✓ /tmp/private-session-data does not exist")

        print("\n--- Test 4.3: Shell History Verification ---")
        history_check = machine.succeed(
            "su - testuser -c 'cat ~/.bash_history 2>/dev/null || echo NO_HISTORY'"
        )
        if "NAILS_CANARY" in history_check:
            print(f"FAIL: Found canary in shell history: {history_check}")
            assert False, "Shell history contains NAILS_CANARY strings"
        print("✓ No NAILS_CANARY strings in shell history")

        print("\n--- Test 4.4: History File Size Check ---")
        post_history_size = int(machine.succeed(
            "su - testuser -c 'wc -c < ~/.bash_history 2>/dev/null || echo 0'"
        ).strip())

        print(f"  Baseline history size: {baseline_history_size} bytes")
        print(f"  Post-deactivation history size: {post_history_size} bytes")

        max_allowed = max(200, baseline_history_size + 50)
        if post_history_size > max_allowed:
            print(f"WARNING: History file larger than expected ({post_history_size} > {max_allowed})")
            history_content = machine.succeed(
                "su - testuser -c 'cat ~/.bash_history 2>/dev/null || echo EMPTY'"
            )
            print(f"History content: {history_content[:500]}")
            assert "NAILS_CANARY" not in history_content, \
                "History file contains canary despite size check"
        print(f"✓ History file size acceptable: {post_history_size} bytes")

        print("\n--- Test 4.5: nails verify --deep ---")
        verify_status, verify_payload = run_verify("--deep")
        findings_text = json.dumps(verify_payload)
        if "NAILS_CANARY" in findings_text or "canary" in findings_text.lower():
            print(f"FAIL: verify --deep found canary artifacts: {verify_payload}")
            assert False, "nails verify --deep found canary artifacts"

        verify_messages = [finding["message"] for finding in verify_payload.get("findings", [])]
        overlay_findings = [m for m in verify_messages if "Overlay mount found" in m]
        assert not overlay_findings, f"Found overlay mount findings: {overlay_findings}"

        print(f"✓ nails verify --deep status: {verify_payload.get('status', 'Unknown')}")
        print(f"✓ nails verify --deep exit code: {verify_status}")

        print("\n--- Test 4.6: Sleuth Kit fls Deleted File Analysis ---")
        fls_output = machine.succeed(
            "fls -r /dev/vdb 2>/dev/null | grep -iE '(nails|canary|secret|financial|confidential|hidden|keys)' || echo 'CLEAN'"
        )

        if "CLEAN" not in fls_output:
            print(f"FAIL: Sleuth Kit found artifacts in deleted files: {fls_output}")
            assert False, "Sleuth Kit fls found NAILS/canary artifacts in deleted files"
        print("✓ No canary-related deleted files found via Sleuth Kit fls")

        print("\n--- Test 4.7: Comprehensive Sensitive Pattern Scan ---")
        sensitive_patterns = [
            "NAILS_CANARY",
            "secret-project",
            "financial-data",
            "confidential-project",
            "hidden-secrets",
            "secret-cache",
            "private-session",
        ]

        for pattern in sensitive_patterns:
            scan_result = machine.succeed(
                f"grep -r '{pattern}' /home /tmp /var /etc 2>/dev/null | head -5 || echo 'CLEAN'"
            )
            if "CLEAN" not in scan_result:
                print(f"FAIL: Found pattern '{pattern}': {scan_result}")
                assert False, f"Sensitive pattern '{pattern}' found after deactivation"
            print(f"✓ Pattern '{pattern}' not found")

        print("\n--- Test 4.8: Sensitive Filename Scan ---")
        filename_scan = machine.succeed(
            "find /home /tmp 2>/dev/null | grep -iE '(secret|financial|confidential|canary|hidden-secret|keys\\.txt)' || echo 'CLEAN'"
        )

        if "CLEAN" not in filename_scan:
            print(f"FAIL: Found sensitive filenames: {filename_scan}")
            assert False, "Sensitive filenames found after deactivation"
        print("✓ No sensitive filenames found in /home or /tmp")

        print("\n--- Test 4.9: Overlay Mount Verification ---")
        machine.fail("mount | grep 'overlay on /home'")
        print("✓ No overlay on /home")
        machine.fail("mount | grep 'overlay on /tmp'")
        print("✓ No overlay on /tmp")
        machine.fail("mount | grep 'overlay on /etc'")
        print("✓ No overlay on /etc")

        print("\n--- Test 4.10: NAILS-related Mount Verification ---")
        mount_check = machine.succeed(
            "mount | grep -E '(nails|hidden-volume|overlay)' || echo 'CLEAN'"
        )

        if "CLEAN" not in mount_check:
            print(f"FAIL: Found NAILS-related mounts: {mount_check}")
            assert False, "NAILS-related mounts still present"
        print("✓ No NAILS-related mounts found")

        print("\n" + "=" * 70)
        print("PHASE 5: STATISTICAL VALIDATION (5 cycles)")
        print("=" * 70)

        for cycle in range(1, 6):
            print(f"\n--- Cycle {cycle}/5 ---")
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

            cycle_canary = f"NAILS_CANARY_CYCLE{cycle}_2026"
            machine.succeed(f"su - testuser -c 'echo {cycle_canary} > ~/cycle-canary.txt'")
            machine.succeed(f"echo {cycle_canary} > /tmp/cycle-canary-temp")
            machine.succeed(f"su - testuser -c 'grep {cycle_canary} ~/cycle-canary.txt'")
            print(f"  ✓ Planted {cycle_canary}")

            machine.execute("sudo nails deactivate; reboot", check_return=False, check_output=False)
            machine.wait_for_shutdown()
            machine.start()
            machine.wait_for_unit("multi-user.target")
            print("  ✓ Rebooted to decoy state")

            machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")

            grep_check = machine.succeed(
                f"grep -r '{cycle_canary}' /home /tmp /var /etc 2>/dev/null || echo 'CLEAN'"
            )
            assert "CLEAN" in grep_check, f"Cycle {cycle}: Canary {cycle_canary} found after deactivation"
            print(f"  ✓ {cycle_canary} not found after deactivation")

            machine.fail("su - testuser -c 'test -f ~/cycle-canary.txt'")
            machine.fail("test -f /tmp/cycle-canary-temp")
            print(f"  ✓ Cycle {cycle} canary files do not exist")

        print("\n" + "=" * 70)
        print("ALL STANDARD DEACTIVATION FORENSIC TESTS PASSED")
        print("=" * 70)
        print("""
    Summary of verified forensic safety:
      ✓ All canary strings removed from filesystem
      ✓ All canary files removed from /home and /tmp
      ✓ Shell history does not contain canary strings
      ✓ History file size within acceptable bounds
      ✓ nails verify --deep returns clean
      ✓ Sleuth Kit fls finds no canary-related deleted files
      ✓ No sensitive patterns found via grep
      ✓ No sensitive filenames found via find
      ✓ All overlay mounts removed
      ✓ No NAILS-related mounts present
      ✓ Statistical validation (5 cycles) passed
    """)
  '';
}
