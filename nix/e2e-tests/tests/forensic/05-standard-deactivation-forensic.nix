# Test 05: Standard deactivation leaves no trace on the decoy disk image
#
# One disk lineage: baseline -> activate and plant canaries -> standard
# deactivate -> image the decoy root. The hidden canaries (a file, a shell
# history line and a logged journal line) and every artifact-indicator token
# from the shared registry must be absent from the post-deactivation image,
# measured against the baseline so decoy-native strings do not raise false
# findings. The old test grepped a live filesystem and ran `fls` on the LUKS
# ciphertext, so it could not observe a leak onto the decoy.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "standard-deactivation-forensic";
  meta.tags = [ "forensic" ];

  # Disk imaging across the lineage plus two activation cycles; generous margin.
  globalTimeout = 1800;

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    import json

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.runVerifyFn}
    ${assertions.assertNoOverlaysFn}
    ${diskForensics.pythonSetup}

    # Distinctive, run-unique canary tokens planted inside the hidden session.
    canary_file_token = "NAILS_CANARY_FILE_2026a"
    canary_hist_token = "NAILS_CANARY_HISTORY_2026a"
    canary_jrnl_token = "NAILS_CANARY_JOURNAL_2026a"
    hidden_tokens = [canary_file_token, canary_hist_token, canary_jrnl_token]

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Keep the config file name free of "nails": it is written to the decoy /tmp
    # before activation and survives the cycle, and `verify --deep` recursively
    # flags nails-named files under /tmp as suspicious leftovers — so a config
    # called nails-*.toml would make verify warn about the test's own artifact.
    headless_config = "/tmp/forensic-headless.toml"
    write_headless_config(headless_config, overlay_var=True)

    with subtest("capture the decoy baseline image"):
        baseline = disk_forensics.snapshot(machine, "baseline")
        baseline_fls = disk_forensics.fls_paths(disk_forensics.run_fls(baseline))
        registry_tokens = load_registry_tokens()
        # A registry token that already occurs on the stock decoy image (e.g. the
        # generic "configuration.nix" under /etc/nixos) is decoy-native; only a
        # token that appears *after* the cycle can be a leak, so subtract the
        # baseline up front. Scan the decoy's files (journal excluded): every
        # command here runs through a journaled service, so nails' diagnostic
        # stderr naming its own files would otherwise read as a decoy trace even
        # though nothing was written to the decoy. The journal's own hygiene is
        # covered by the canary journal scan below.
        baseline_offset = disk_forensics.partition_offset(baseline)
        baseline_registry_hits = disk_forensics.run_decoy_file_scan(
            baseline, registry_tokens, offset=baseline_offset
        )

    with subtest("activate and plant hidden canaries"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep --accept-persistent-decoy -y"
        )
        machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
        machine.succeed("mount | grep 'overlay on /home'")

        machine.succeed(
            f"su - testuser -c 'echo {canary_file_token} > ~/secret-notes.txt'"
        )
        machine.succeed(
            f"su - testuser -c 'echo {canary_hist_token} >> ~/.bash_history'"
        )
        machine.succeed(f"logger -t session {canary_jrnl_token}")
        machine.succeed("journalctl --sync 2>/dev/null || journalctl --flush || true")
        # The canaries are visible while the session is live.
        assert canary_file_token in machine.succeed(
            "su - testuser -c 'cat ~/secret-notes.txt'"
        )

    with subtest("standard deactivation and verify"):
        canonical_deactivate(
            headless_config, unit_name="nails-deactivate-standard-forensic"
        )
        status = json.loads(machine.succeed("nails status --json"))["data"]
        assert status["state"]["kind"] == "inactive", f"expected inactive, got {status}"
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")

        verify_status, verify_payload = run_verify("--deep")
        findings_text = json.dumps(verify_payload)
        assert "NAILS_CANARY" not in findings_text, (
            f"verify --deep surfaced a canary: {verify_payload}"
        )
        overlay_findings = [
            finding["message"]
            for finding in verify_payload.get("findings", [])
            if "Overlay mount found" in finding["message"]
        ]
        assert not overlay_findings, f"verify reported overlays: {overlay_findings}"
        assert verify_status == 0, (
            f"verify --deep exit code was {verify_status}: {verify_payload}"
        )
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp", "/var"])

    with subtest("the decoy disk image is clean of every canary and registry token"):
        post = disk_forensics.snapshot(machine, "post-standard", restart=False)
        offset = disk_forensics.partition_offset(post)

        post_fls = disk_forensics.fls_paths(disk_forensics.run_fls(post, offset))
        new_names = disk_forensics.diff(baseline_fls, post_fls)
        leaked_names = {
            name for name in new_names if any(tok in name for tok in hidden_tokens)
        }
        assert not leaked_names, f"fls found canary-named entries: {sorted(leaked_names)}"

        string_hits = disk_forensics.run_strings_scan(post, hidden_tokens)
        assert not string_hits, f"strings found canary content: {sorted(string_hits)}"

        journal_hits = disk_forensics.run_journal_scan(post, hidden_tokens, offset=offset)
        assert not journal_hits, f"journal retained a canary line: {sorted(journal_hits)}"

        # Registry tokens that were not already on the baseline image must not be
        # introduced onto the decoy's files by the cycle (journal excluded; see
        # the baseline capture above).
        post_registry_hits = disk_forensics.run_decoy_file_scan(
            post, registry_tokens, offset=offset
        )
        new_registry = post_registry_hits - baseline_registry_hits
        assert not new_registry, (
            f"activate/deactivate introduced registry tokens onto the decoy "
            f"image: {sorted(new_registry)}"
        )
        print("✓ post-standard image clean of canaries and registry tokens")
  '';
}
