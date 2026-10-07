# Test 83: The hidden session leaves no journal trace on a persistent decoy
#
# T-094. The journald relinquish/flush hooks are meant to keep a hidden
# session's own journal off the decoy's persistent journal: --relinquish-var
# before /var is overlaid, --flush once journald has reopened under the overlay,
# and --relinquish-var again before /var is unmounted at teardown. This spec
# proves the hooks hold against a forensic read of the decoy disk.
#
# The decoy here keeps a persistent journal (forensic-vm-config sets
# Storage=persistent), so a leak would be durable. Controls make the scan
# honest: a line logged *before* activation must still be carved from the decoy
# journal after the cycle (positive control — the scan can see the journal),
# while the canary logged *inside* the hidden session must be absent (the leak
# check).

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
in
{
  name = "decoy-journal-leak";
  meta.tags = [ "security" ];

  # Disk imaging plus an activation cycle with a reboot; generous margin.
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
    ${assertions.assertNoOverlaysFn}
    ${diskForensics.pythonSetup}

    # A line logged to the decoy journal before activation (positive control) and
    # the canary logged inside the hidden session (must never reach the decoy).
    precontrol_token = "NAILS_JCTL_PRECONTROL_2026a"
    hidden_jrnl_token = "NAILS_JCTL_HIDDEN_2026a"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    # Config file name kept free of "nails" so verify's /tmp scan never flags it.
    headless_config = "/tmp/journal-leak-headless.toml"
    write_headless_config(headless_config, overlay_var=True)

    with subtest("confirm the decoy keeps a persistent journal"):
        machine.succeed("grep -qi '^Storage=persistent' /etc/systemd/journald.conf")

    with subtest("plant a pre-activation journal control on the decoy"):
        machine.succeed(f"logger -t decoy {precontrol_token}")
        machine.succeed("journalctl --sync 2>/dev/null || journalctl --flush || true")

    with subtest("activate a persistent-journal decoy and log inside the session"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep --accept-persistent-decoy -y"
        )
        machine.succeed("mount | grep 'overlay on /var'")
        # T-139: the re-home check ran against the real journald and confirmed
        # its writable journal fds on the /var overlay. An indeterminate result
        # is tolerated by activation with a warning, so the activation's own log
        # on the hidden volume (every level) must carry the positive verdict.
        nails_log = machine.succeed("cat /mnt/data/logs/nails.log")
        assert "journald journal fds resolve into the /var overlay upper" in nails_log, (
            "activation did not confirm journald's fds on the /var overlay"
        )
        assert "could not confirm journald journal fds" not in nails_log
        # Logged while /var is overlaid: journald --flush must land this in the
        # overlay upper (on the hidden volume), never on the decoy's /var.
        machine.succeed(f"logger -t session {hidden_jrnl_token}")
        machine.succeed("journalctl --sync 2>/dev/null || journalctl --flush || true")
        assert hidden_jrnl_token in machine.succeed(
            f"journalctl --grep {hidden_jrnl_token} --no-pager -o cat"
        ), "the canary must be visible in the live (overlaid) journal"

    with subtest("capture the kernel and systemd fixtures of a live session"):
        # T-139: the parser tests read these (nails-core/tests/fixtures/kernel/
        # README.md). Read-only, written under /run, never on the decoy disk.
        machine.copy_from_host(
            "${../../../../scripts/capture-kernel-fixtures.sh}", "/run/capture-kernel-fixtures.sh"
        )
        machine.succeed("bash /run/capture-kernel-fixtures.sh vm /run/kernel-fixtures")
        machine.copy_from_vm("/run/kernel-fixtures", "kernel-fixtures")
        machine.succeed("rm -rf /run/kernel-fixtures /run/capture-kernel-fixtures.sh")

    with subtest("standard deactivation and reboot to the decoy"):
        canonical_deactivate(
            headless_config, unit_name="nails-deactivate-journal-leak"
        )
        status = json.loads(machine.succeed("nails status --json"))["data"]
        assert status["state"]["kind"] == "inactive", f"expected inactive, got {status}"
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp", "/var"])

    with subtest("the decoy journal retains the control but none of the hidden canary"):
        post = disk_forensics.snapshot(machine, "post-journal-leak", restart=False)
        offset = disk_forensics.partition_offset(post)

        # Positive control: the pre-activation line is still carvable, so an empty
        # hidden-canary result below means "searched and clean", not "no journal".
        control_hits = disk_forensics.run_journal_scan(
            post, [precontrol_token], offset=offset
        )
        assert precontrol_token in control_hits, (
            f"positive control missing — the decoy journal was not read: {control_hits}"
        )

        # The leak check: the hidden-session canary must be absent from the decoy
        # journal, proving the relinquish/flush hooks kept it on the overlay.
        leak_hits = disk_forensics.run_journal_scan(
            post, [hidden_jrnl_token], offset=offset
        )
        assert not leak_hits, (
            f"the hidden-session journal leaked onto the decoy: {sorted(leak_hits)}"
        )

        # And the raw ciphertext/plaintext of the decoy image carries no canary.
        string_hits = disk_forensics.run_strings_scan(post, [hidden_jrnl_token])
        assert not string_hits, (
            f"strings found the hidden canary on the decoy image: {sorted(string_hits)}"
        )
        print("✓ decoy journal clean of the hidden session, control intact")
  '';
}
