# Test 08: Emergency deactivation leaves no trace on the decoy disk image
#
# The sibling of test 05 for the emergency path. One disk lineage: baseline ->
# activate and plant canaries -> emergency teardown -> image the decoy root. The
# hidden canaries and every artifact-indicator token must be absent from the
# post-emergency image, measured against the baseline. (The emergency test lives
# at 08 rather than 80 because forensic/80 is taken by the ESP/NVRAM invariant.)
#
# As in forensic/06, the images are also compared by MAC times and content
# hashes against a plain-reboot control run, so an emergency teardown that left
# a decoy file modified in place fails too.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  assertions = import ./../../lib/assertions.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "post-emergency-image";
  meta.tags = [ "forensic" ];

  # Disk imaging three times, an extra reboot for the control run and three
  # carve-and-hash passes around the emergency teardown; generous margin.
  globalTimeout = 2700;

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/forensic-vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
        services.getty.autologinUser = "root";
        systemd.services.nails-emergency-test = emergency.makeEmergencyUnit self.packages.x86_64-linux.nails "/tmp/nails-headless.toml";
      };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${emergency.prepareTty1ShellFn}
    ${emergency.waitForConsoleLogFn}
    ${emergency.rebootAfterEmergencyFn}
    ${emergency.waitForEmergencyUnitFn}
    ${emergency.runEmergencyCommandFn}
    ${assertions.assertNoOverlaysFn}
    ${diskForensics.pythonSetup}

    canary_file_token = "NAILS_CANARY_EMERG_FILE_2026a"
    canary_hist_token = "NAILS_CANARY_EMERG_HISTORY_2026a"
    canary_jrnl_token = "NAILS_CANARY_EMERG_JOURNAL_2026a"
    hidden_tokens = [canary_file_token, canary_hist_token, canary_jrnl_token]

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config, overlay_var=True)

    with subtest("capture the decoy baseline image"):
        # The hidden-volume mount point is a permanent part of the decoy; create
        # it before the baseline so the new /mnt entry is not read as drift.
        machine.succeed("mkdir -p /mnt/data")
        baseline = disk_forensics.snapshot(machine, "baseline")
        baseline_fls = disk_forensics.fls_paths(disk_forensics.run_fls(baseline))
        registry_tokens = load_registry_tokens()
        baseline_registry_hits = disk_forensics.run_strings_scan(baseline, registry_tokens)
        baseline_state = disk_forensics.image_state(baseline, "baseline", machine)

    with subtest("control run: plain reboots with no hidden session"):
        # The session below spans two boots (the one after this snapshot and the
        # one after the teardown reboots), so the control spans two plain boots.
        # Whatever changes here is boot noise, not the hidden session.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        control = disk_forensics.snapshot(machine, "control")
        control_state = disk_forensics.image_state(control, "control", machine)

    with subtest("activate and plant hidden canaries"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep --accept-persistent-decoy -y"
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

    with subtest("emergency teardown and reboot to decoy"):
        emergency_time = run_emergency_command(reboot=True)
        print(f"✓ emergency command completed in {emergency_time:.3f}s")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp", "/var"])

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

        post_registry_hits = disk_forensics.run_strings_scan(post, registry_tokens)
        new_registry = post_registry_hits - baseline_registry_hits
        assert not new_registry, (
            f"emergency teardown introduced registry tokens onto the decoy "
            f"image: {sorted(new_registry)}"
        )
        print("✓ post-emergency image clean of canaries and registry tokens")

    with subtest("existing decoy inodes keep their MAC times and contents"):
        post_state = disk_forensics.image_state(post, "post", machine)
        disk_forensics.assert_mac_unchanged(
            machine, baseline_state, control_state, post_state
        )
  '';
}
