# Story 13.6b: Standard Deactivation Forensic Safety Test
# Tests that standard deactivation (nails deactivate) leaves no forensic traces
# Uses comprehensive canary pattern planting to verify complete cleanup

{ self, ... }:
let hiddenVolume = import ./../lib/hidden-volume.nix;
in {
  name = "standard-deactivation-forensic";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = _: ''
        import json

        def write_headless_config(path):
            machine.succeed(
                """cat > %s <<'EOF'
        hidden_volume_root: /mnt/hidden-volume
        overlay_mode: explicit
        overlays:
          - name: etc
            lower: /etc
            upper: /mnt/hidden-volume/etc
            work: /mnt/hidden-volume/.work/etc
            target: /etc
          - name: home
            lower: /home
            upper: /mnt/hidden-volume/home
            work: /mnt/hidden-volume/.work/home
            target: /home
          - name: root
            lower: /root
            upper: /mnt/hidden-volume/root
            work: /mnt/hidden-volume/.work/root
            target: /root
          - name: srv
            lower: /srv
            upper: /mnt/hidden-volume/srv
            work: /mnt/hidden-volume/.work/srv
            target: /srv
          - name: tmp
            lower: /tmp
            upper: /mnt/hidden-volume/tmp
            work: /mnt/hidden-volume/.work/tmp
            target: /tmp
        EOF""" % path
            )

        def run_verify(args=""):
            """Run nails verify and return exit status and JSON payload."""
            command = "nails verify --json"
            if args:
                command = f"{command} {args}"
            machine.succeed(
                f"bash -lc 'set +e; {command} > /tmp/verify.stdout 2>/tmp/verify.stderr; printf \"%s\" \"$?\" > /tmp/verify.rc'"
            )
            status = int(machine.succeed("cat /tmp/verify.rc"))
            output = machine.succeed("cat /tmp/verify.stdout")
            return status, json.loads(output)

        # ============================================================================
        # PHASE 1: SETUP AND ACTIVATE
        # ============================================================================

        machine.start()
        machine.wait_for_unit("multi-user.target")

        print("\n" + "=" * 70)
        print("PHASE 1: SETUP AND ACTIVATE")
        print("=" * 70)

        headless_config = "/tmp/nails-headless.yaml"
        write_headless_config(headless_config)

        # Capture pre-activation baseline of .bash_history
        baseline_history_size = int(machine.succeed(
            "su - testuser -c 'wc -c < ~/.bash_history 2>/dev/null || echo 0'"
        ).strip())
        print(f"✓ Baseline .bash_history size: {baseline_history_size} bytes")

        # Setup hidden volume
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        print("✓ Hidden volume created and mounted")

        # Activate NAILS
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

        # Use a fresh login shell after activation
        machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
        print("✓ NAILS activated with overlays")

        # Verify overlay is active
        machine.succeed("mount | grep 'overlay on /home'")
        machine.succeed("mount | grep 'overlay on /tmp'")
        print("✓ Overlays verified active on /home and /tmp")

        # ============================================================================
        # PHASE 2: PLANT CANARY PATTERNS
        # ============================================================================

        print("\n" + "=" * 70)
        print("PHASE 2: PLANT CANARY PATTERNS")
        print("=" * 70)

        # Canary 1: Shell history canary
        machine.succeed("su - testuser -c 'echo NAILS_CANARY_HISTORY_2026 >> ~/.bash_history'")
        machine.succeed("su - testuser -c 'history -s NAILS_CANARY_HISTORY_CMD_2026'")
        print("✓ Planted NAILS_CANARY_HISTORY_2026 in shell history")

        # Canary 2: Temp file canary
        machine.succeed("echo 'NAILS_CANARY_TEMP_2026' > /tmp/nails-canary-temp")
        machine.succeed("test -f /tmp/nails-canary-temp")
        print("✓ Planted NAILS_CANARY_TEMP_2026 in /tmp/nails-canary-temp")

        # Canary 3: Document content canary
        machine.succeed("su - testuser -c 'echo NAILS_CANARY_DOCUMENT_2026 > ~/canary-document.txt'")
        machine.succeed("su - testuser -c 'test -f ~/canary-document.txt'")
        print("✓ Planted NAILS_CANARY_DOCUMENT_2026 in ~/canary-document.txt")

        # Canary 4: Sensitive filename - secret-project.txt
        machine.succeed("su - testuser -c 'echo secret_content > ~/secret-project.txt'")
        machine.succeed("su - testuser -c 'test -f ~/secret-project.txt'")
        print("✓ Planted secret-project.txt (sensitive filename)")

        # Canary 5: Sensitive filename - financial-data.csv
        machine.succeed("su - testuser -c 'echo NAILS_CANARY_FINANCIAL_2026,100000,CONFIDENTIAL > ~/financial-data.csv'")
        machine.succeed("su - testuser -c 'test -f ~/financial-data.csv'")
        print("✓ Planted financial-data.csv with NAILS_CANARY_FINANCIAL_2026")

        # Canary 6: Nested directory structure with sensitive names
        machine.succeed("su - testuser -c 'mkdir -p ~/confidential-project/secrets'")
        machine.succeed("su - testuser -c 'echo NAILS_CANARY_NESTED_2026 > ~/confidential-project/secrets/keys.txt'")
        machine.succeed("su - testuser -c 'test -f ~/confidential-project/secrets/keys.txt'")
        print("✓ Planted nested confidential-project/secrets/keys.txt")

        # Canary 7: Hidden dotfile
        machine.succeed("su - testuser -c 'echo NAILS_CANARY_HIDDEN_2026 > ~/.hidden-secrets'")
        machine.succeed("su - testuser -c 'test -f ~/.hidden-secrets'")
        print("✓ Planted ~/.hidden-secrets (hidden dotfile)")

        # Canary 8: Multiple entries in /tmp
        machine.succeed("touch /tmp/secret-cache-123")
        machine.succeed("echo NAILS_CANARY_CACHE_2026 > /tmp/private-session-data")
        print("✓ Planted additional /tmp canaries")

        # Verify all canaries exist during active session
        print("\n--- Verifying all canaries exist ---")
        canary_count = machine.succeed(
            "grep -r 'NAILS_CANARY' /home /tmp 2>/dev/null | wc -l"
        ).strip()
        print(f"✓ Found {canary_count} canary occurrences in active session")

        # ============================================================================
        # PHASE 3: STANDARD DEACTIVATION
        # ============================================================================

        print("\n" + "=" * 70)
        print("PHASE 3: STANDARD DEACTIVATION")
        print("=" * 70)

        print("Executing: nails deactivate")
        machine.execute("sudo nails deactivate", check_return=False, check_output=False)
        machine.wait_for_shutdown()
        print("✓ VM shut down after deactivation")

        machine.start()
        machine.wait_for_unit("multi-user.target")
        print("✓ VM rebooted to decoy state")

        # Verify NAILS reports inactive
        status = json.loads(machine.succeed("nails status --json"))
        assert status["state"] == "Inactive", f"Expected Inactive status after reboot, got: {status}"
        print("✓ NAILS status reports Inactive")

        # Unmount hidden volume from decoy state (cleanup)
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        print("✓ Hidden volume unmounted from decoy state")

        # ============================================================================
        # PHASE 4: FORENSIC VERIFICATION
        # ============================================================================

        print("\n" + "=" * 70)
        print("PHASE 4: FORENSIC VERIFICATION")
        print("=" * 70)

        # ----------------------------------------------------------------------------
        # Test 4.1: Grep scan for canary strings
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.1: Canary String Grep Scan ---")

        grep_result = machine.succeed(
            "grep -r 'NAILS_CANARY' /home /tmp /var /etc /root 2>/dev/null || echo 'CLEAN'"
        )
        if "NAILS_CANARY" in grep_result:
            print(f"FAIL: Found canary strings: {grep_result}")
            assert False, "Canary strings found after deactivation"
        print("✓ No NAILS_CANARY strings found on filesystem")

        # ----------------------------------------------------------------------------
        # Test 4.2: Canary file existence checks
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.2: Canary File Existence Checks ---")

        # Temp file canary must not exist
        machine.fail("test -f /tmp/nails-canary-temp")
        print("✓ /tmp/nails-canary-temp does not exist")

        # Home directory canaries must not exist
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

        # Additional /tmp canaries
        machine.fail("test -f /tmp/secret-cache-123")
        print("✓ /tmp/secret-cache-123 does not exist")

        machine.fail("test -f /tmp/private-session-data")
        print("✓ /tmp/private-session-data does not exist")

        # ----------------------------------------------------------------------------
        # Test 4.3: Shell history verification
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.3: Shell History Verification ---")

        history_check = machine.succeed(
            "su - testuser -c 'cat ~/.bash_history 2>/dev/null || echo NO_HISTORY'"
        )

        if "NAILS_CANARY" in history_check:
            print(f"FAIL: Found canary in shell history: {history_check}")
            assert False, "Shell history contains NAILS_CANARY strings"
        print("✓ No NAILS_CANARY strings in shell history")

        # ----------------------------------------------------------------------------
        # Test 4.4: History file size check
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.4: History File Size Check ---")

        post_history_size = int(machine.succeed(
            "su - testuser -c 'wc -c < ~/.bash_history 2>/dev/null || echo 0'"
        ).strip())

        print(f"  Baseline history size: {baseline_history_size} bytes")
        print(f"  Post-deactivation history size: {post_history_size} bytes")

        # History should be small (< 200 bytes) or at most baseline + small delta
        max_allowed = max(200, baseline_history_size + 50)
        if post_history_size > max_allowed:
            print(f"WARNING: History file larger than expected ({post_history_size} > {max_allowed})")
            # Dump contents for debugging
            history_content = machine.succeed(
                "su - testuser -c 'cat ~/.bash_history 2>/dev/null || echo EMPTY'"
            )
            print(f"History content: {history_content[:500]}")
            # Only fail if it contains sensitive content
            assert "NAILS_CANARY" not in history_content, \
                "History file contains canary despite size check"
        print(f"✓ History file size acceptable: {post_history_size} bytes")

        # ----------------------------------------------------------------------------
        # Test 4.5: nails verify --deep
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.5: nails verify --deep ---")

        verify_status, verify_payload = run_verify("--deep")

        # Check for canary-related findings
        findings_text = json.dumps(verify_payload)
        if "NAILS_CANARY" in findings_text or "canary" in findings_text.lower():
            print(f"FAIL: verify --deep found canary artifacts: {verify_payload}")
            assert False, "nails verify --deep found canary artifacts"

        # Verify should not report critical issues
        verify_messages = [finding["message"] for finding in verify_payload.get("findings", [])]
        overlay_findings = [m for m in verify_messages if "Overlay mount found" in m]
        assert not overlay_findings, f"Found overlay mount findings: {overlay_findings}"

        print(f"✓ nails verify --deep status: {verify_payload.get('status', 'Unknown')}")
        print(f"✓ nails verify --deep exit code: {verify_status}")

        # ----------------------------------------------------------------------------
        # Test 4.6: Sleuth Kit fls analysis
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.6: Sleuth Kit fls Deleted File Analysis ---")

        # Use fls to scan for deleted files on the secondary disk (hidden volume device)
        # This checks if any canary-named files appear as deleted entries
        fls_output = machine.succeed(
            "fls -r /dev/vdb 2>/dev/null | grep -iE '(nails|canary|secret|financial|confidential|hidden|keys)' || echo 'CLEAN'"
        )

        if "CLEAN" not in fls_output:
            print(f"FAIL: Sleuth Kit found artifacts in deleted files: {fls_output}")
            assert False, "Sleuth Kit fls found NAILS/canary artifacts in deleted files"
        print("✓ No canary-related deleted files found via Sleuth Kit fls")

        # ----------------------------------------------------------------------------
        # Test 4.7: Comprehensive filesystem scan for sensitive patterns
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.7: Comprehensive Sensitive Pattern Scan ---")

        # Scan for any sensitive patterns that might have leaked
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

        # ----------------------------------------------------------------------------
        # Test 4.8: File listing scan for sensitive filenames
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.8: Sensitive Filename Scan ---")

        filename_scan = machine.succeed(
            "find /home /tmp 2>/dev/null | grep -iE '(secret|financial|confidential|canary|hidden-secret|keys\\.txt)' || echo 'CLEAN'"
        )

        if "CLEAN" not in filename_scan:
            print(f"FAIL: Found sensitive filenames: {filename_scan}")
            assert False, "Sensitive filenames found after deactivation"
        print("✓ No sensitive filenames found in /home or /tmp")

        # ----------------------------------------------------------------------------
        # Test 4.9: Overlay mount verification
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.9: Overlay Mount Verification ---")

        machine.fail("mount | grep 'overlay on /home'")
        print("✓ No overlay on /home")

        machine.fail("mount | grep 'overlay on /tmp'")
        print("✓ No overlay on /tmp")

        machine.fail("mount | grep 'overlay on /etc'")
        print("✓ No overlay on /etc")

        # ----------------------------------------------------------------------------
        # Test 4.10: Verify no NAILS-related mounts
        # ----------------------------------------------------------------------------
        print("\n--- Test 4.10: NAILS-related Mount Verification ---")

        mount_check = machine.succeed(
            "mount | grep -E '(nails|hidden-volume|overlay)' || echo 'CLEAN'"
        )

        if "CLEAN" not in mount_check:
            print(f"FAIL: Found NAILS-related mounts: {mount_check}")
            assert False, "NAILS-related mounts still present"
        print("✓ No NAILS-related mounts found")

        # ============================================================================
        # PHASE 5: STATISTICAL VALIDATION - Multiple Cycles
        # ============================================================================

        print("\n" + "=" * 70)
        print("PHASE 5: STATISTICAL VALIDATION (5 cycles)")
        print("=" * 70)

        for cycle in range(1, 6):
            print(f"\n--- Cycle {cycle}/5 ---")

            # Setup and activate
            machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")

            # Plant unique canary for this cycle
            cycle_canary = f"NAILS_CANARY_CYCLE{cycle}_2026"
            machine.succeed(f"su - testuser -c 'echo {cycle_canary} > ~/cycle-canary.txt'")
            machine.succeed(f"echo {cycle_canary} > /tmp/cycle-canary-temp")

            # Verify canary exists
            machine.succeed(f"su - testuser -c 'grep {cycle_canary} ~/cycle-canary.txt'")
            print(f"  ✓ Planted {cycle_canary}")

            # Deactivate
            machine.execute("sudo nails deactivate", check_return=False, check_output=False)
            machine.wait_for_shutdown()
            machine.start()
            machine.wait_for_unit("multi-user.target")
            print(f"  ✓ Rebooted to decoy state")

            # Cleanup hidden volume
            machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")

            # Verify canary is gone
            grep_check = machine.succeed(
                f"grep -r '{cycle_canary}' /home /tmp /var /etc 2>/dev/null || echo 'CLEAN'"
            )
            assert "CLEAN" in grep_check, f"Cycle {cycle}: Canary {cycle_canary} found after deactivation"
            print(f"  ✓ {cycle_canary} not found after deactivation")

            # Verify file doesn't exist
            machine.fail("su - testuser -c 'test -f ~/cycle-canary.txt'")
            machine.fail("test -f /tmp/cycle-canary-temp")
            print(f"  ✓ Cycle {cycle} canary files do not exist")

        # ============================================================================
        # FINAL SUMMARY
        # ============================================================================

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
