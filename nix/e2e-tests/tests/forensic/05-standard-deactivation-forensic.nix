# Test 05: A whole-root session leaves no trace on the decoy disk image
#
# One disk lineage: baseline -> activate (a soft-reboot into the hidden root)
# and plant canaries -> deactivate (a soft-reboot back) -> image the decoy
# root. The decoy keeps a persistent journal and an on-disk Nix store, the
# strict case: the hidden journal and the hidden store writes must land in the
# upper on the hidden volume, never on this disk. The hidden canaries (a file, a shell
# history line and a logged journal line) and every artifact-indicator token
# from the shared registry must be absent from the post-deactivation image,
# measured against the baseline so decoy-native strings do not raise false
# findings. The old test grepped a live filesystem and ran `fls` on the LUKS
# ciphertext, so it could not observe a leak onto the decoy.
#
# Tokens miss a decoy file modified in place. So, as in forensic/06, each image
# also yields a bodyfile and per-file content hashes, and a control run (the
# same number of plain reboots, no session) records the boot noise: the hidden
# session may change no inode, mode, owner, size, mtime, ctime, crtime or file
# contents beyond it and the volatile allowlist.
#
# nails runs through sudo, as an operator runs it. sudo logs each command, so
# the decoy's persistent journal keeps its records of the activation and of the
# verify run, and `verify --deep` must report them as sudo's records; the
# record of the deactivation, made in the hidden session, must not reach it.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "standard-deactivation-forensic";
  meta.tags = [ "forensic" ];

  # Disk imaging three times (baseline, control, post), an extra reboot for the
  # control run, two soft-reboots and three carve-and-hash passes.
  globalTimeout = 2700;

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
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.runVerifyFn}
    ${diskForensics.pythonSetup}

    from nails_e2e import session

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
    write_headless_config(headless_config)

    with subtest("capture the decoy baseline image"):
        # The hidden-volume mount point is a permanent part of the decoy; create
        # it before the baseline so the new /mnt entry is not read as drift.
        machine.succeed("mkdir -p /mnt/data")
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
        baseline_state = disk_forensics.image_state(baseline, "baseline", machine)

    with subtest("control run: a plain reboot with no hidden session"):
        # The session below spans the boot after this snapshot and two
        # soft-reboots (the decoy's shutdown and its start again), so the
        # control is one plain reboot. Whatever changes here is boot noise, not
        # the hidden session.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        control = disk_forensics.snapshot(machine, "control")
        control_state = disk_forensics.image_state(control, "control", machine)

    with subtest("activate and plant hidden canaries"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        canonical_activate(
            headless_config,
            "--overlay-only --accept-persistent-decoy",
            "activate",
            sudo=True,
        )
        machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")

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

    with subtest("deactivation and verify"):
        canonical_deactivate(headless_config, sudo=True)
        status = json.loads(
            machine.succeed(f"nails --config {headless_config} status --json")
        )["data"]
        assert status["place"] == "decoy", f"expected the plain decoy, got {status}"

        # sudo's record of the deactivation was made in the hidden session, so
        # it went to the hidden journal on the hidden volume, never to this one.
        machine.succeed("journalctl --sync")
        deactivations = machine.succeed(
            "journalctl --no-pager -o cat | grep -c -F 'deactivate -y' || true"
        ).strip()
        assert deactivations == "0", (
            f"sudo's record of the hidden deactivation reached the decoy journal "
            f"({deactivations} lines)"
        )

        verify_status, verify_payload = run_verify("--deep", sudo=True)
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
        # The persistent journal keeps sudo's records of the activation and of
        # this run on the decoy disk: verify warns about them as sudo's records
        # and about nothing else.
        warnings = [
            finding
            for finding in verify_payload.get("findings", [])
            if finding["severity"] != "info"
        ]
        assert warnings, f"sudo's record of the activation was not reported: {verify_payload}"
        unexpected = [
            finding
            for finding in warnings
            if finding["category"] != "journal" or "sudo record" not in finding["message"]
        ]
        assert not unexpected, f"verify --deep reported more than sudo's records: {unexpected}"
        assert verify_status == 10, (
            f"verify --deep exit code was {verify_status}: {verify_payload}"
        )
        session.assert_decoy_root(machine)

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
        if new_registry:
            # Name the offending files and show a short latin-1 snippet around each
            # hit so the next run points straight at the leaking path.
            offenders = disk_forensics.scan_decoy_files_for_paths(
                post, sorted(new_registry), offset=offset
            )
            detail = "\n".join(
                f"  {token}:\n"
                + "\n".join(f"    {location}" for location in offenders.get(token, []))
                for token in sorted(new_registry)
            )
            raise AssertionError(
                "activate/deactivate introduced registry tokens onto the decoy "
                f"image: {sorted(new_registry)}\n{detail}"
            )
        print("✓ post-standard image clean of canaries and registry tokens")

    with subtest("existing decoy inodes keep their MAC times and contents"):
        post_state = disk_forensics.image_state(post, "post", machine)
        disk_forensics.assert_mac_unchanged(
            machine, baseline_state, control_state, post_state
        )
  '';
}
