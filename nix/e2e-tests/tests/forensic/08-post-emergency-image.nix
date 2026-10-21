# Test 08: Emergency in the hidden session leaves no trace on the decoy image
#
# The sibling of test 05 for the emergency path. One disk lineage: baseline ->
# activate (a soft-reboot into the hidden root) and plant canaries ->
# `nails emergency` (every hidden process killed at once and a soft-reboot
# back) -> image the decoy root. The decoy keeps a persistent journal and an
# on-disk Nix store, the strict case. The hidden canaries (a file, a shell
# history line and a logged journal line) must be absent from the
# post-emergency image, and so must every artifact-indicator token that was not
# already on the baseline image. (The emergency test lives at 08 rather than 80
# because forensic/80 is taken by the ESP/NVRAM invariant.)
#
# As in forensic/05, the images are also compared by MAC times and content
# hashes against a control run (one plain reboot: the session spans two
# soft-reboots), so an emergency that left a decoy file modified in place
# fails too.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "post-emergency-image";
  meta.tags = [ "forensic" ];

  # Disk imaging three times, an extra reboot for the control run, two
  # soft-reboots and three carve-and-hash passes; generous margin.
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
    ${diskForensics.pythonSetup}

    from nails_e2e import session

    canary_file_token = "NAILS_CANARY_EMERG_FILE_2026a"
    canary_hist_token = "NAILS_CANARY_EMERG_HISTORY_2026a"
    canary_jrnl_token = "NAILS_CANARY_EMERG_JOURNAL_2026a"
    hidden_tokens = [canary_file_token, canary_hist_token, canary_jrnl_token]

    machine.start()
    machine.wait_for_unit("multi-user.target")
    # No "nails" in the name: the file stays on the decoy /tmp (see forensic/05).
    headless_config = "/tmp/forensic-headless.toml"
    write_headless_config(headless_config)

    with subtest("capture the decoy baseline image"):
        # The hidden-volume mount point is a permanent part of the decoy; create
        # it before the baseline so the new /mnt entry is not read as drift.
        machine.succeed("mkdir -p /mnt/data")
        baseline = disk_forensics.snapshot(machine, "baseline")
        baseline_fls = disk_forensics.fls_paths(disk_forensics.run_fls(baseline))
        registry_tokens = load_registry_tokens()
        # Decoy files only (journal excluded), measured against the baseline:
        # see forensic/05 for why the journal is covered by the canary scan.
        baseline_registry_hits = disk_forensics.run_decoy_file_scan(
            baseline, registry_tokens, offset=disk_forensics.partition_offset(baseline)
        )
        baseline_state = disk_forensics.image_state(baseline, "baseline", machine)

    with subtest("control run: a plain reboot with no hidden session"):
        # The session below spans the boot after this snapshot and two
        # soft-reboots, so the control is one plain reboot. Whatever changes
        # here is boot noise, not the hidden session.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        control = disk_forensics.snapshot(machine, "control")
        control_state = disk_forensics.image_state(control, "control", machine)

    with subtest("activate and plant hidden canaries"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        canonical_activate(
            headless_config, "--overlay-only --accept-persistent-decoy", "activate"
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
        machine.succeed(
            "test -s /mnt/data/root/upper/home/testuser/secret-notes.txt"
        )

    with subtest("emergency kills the hidden session and soft-reboots back"):
        timings = session.follow_soft_reboot(
            machine, f"nails --config {headless_config} emergency", "emergency"
        )
        machine.log(f"emergency soft-reboot timings: {timings}")
        session.assert_decoy_root(machine)
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
        machine.fail("test -e /home/testuser/secret-notes.txt")
        status = json.loads(
            machine.succeed(f"nails --config {headless_config} status --json")
        )["data"]
        assert status["place"] == "decoy", f"expected the plain decoy, got {status}"

    with subtest("the decoy disk image is clean of every canary and registry token"):
        post = disk_forensics.snapshot(machine, "post-emergency", restart=False)
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

        post_registry_hits = disk_forensics.run_decoy_file_scan(
            post, registry_tokens, offset=offset
        )
        new_registry = post_registry_hits - baseline_registry_hits
        if new_registry:
            offenders = disk_forensics.scan_decoy_files_for_paths(
                post, sorted(new_registry), offset=offset
            )
            detail = "\n".join(
                f"  {token}:\n"
                + "\n".join(f"    {location}" for location in offenders.get(token, []))
                for token in sorted(new_registry)
            )
            raise AssertionError(
                "the emergency introduced registry tokens onto the decoy image: "
                f"{sorted(new_registry)}\n{detail}"
            )
        print("post-emergency image clean of canaries and registry tokens")

    with subtest("existing decoy inodes keep their MAC times and contents"):
        post_state = disk_forensics.image_state(post, "post", machine)
        disk_forensics.assert_mac_unchanged(
            machine, baseline_state, control_state, post_state
        )
  '';
}
