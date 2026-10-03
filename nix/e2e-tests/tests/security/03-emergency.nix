# Test 03: Emergency Deactivation
# Tests the functional emergency workflow and cleanup behavior

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "emergency";
  meta.tags = [
    "security"
    "smoke"
    "forensic"
  ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
        services.getty.autologinUser = "root";
        systemd.services.nails-emergency-test = emergency.makeEmergencyUnit self.packages.x86_64-linux.nails "/tmp/nails-headless.toml";
      };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${emergency.prepareTty1ShellFn}
    ${emergency.waitForConsoleLogFn}
    ${emergency.rebootAfterEmergencyFn}
    ${emergency.runEmergencyCommandFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    # A unique token logged into the volatile journal during the hidden session.
    # The decoy models the recommended amnesic posture (journald Storage=volatile),
    # so this lands in /run/log/journal, which is never overlaid; teardown must
    # scrub it rather than leave it readable with `journalctl`.
    journal_marker = "nails_journal_canary_8f3a2c1d"

    def assert_journal_marker_gone():
        # The marker must survive nowhere: not in the live journal, and not in any
        # runtime journal file under /run/log/journal (grepped as binary).
        journal = machine.succeed("journalctl --no-pager 2>/dev/null || true")
        assert journal_marker not in journal, \
            f"journal still holds the hidden-session marker: {journal_marker!r}"
        runtime_hits = machine.succeed(
            f"grep -ral '{journal_marker}' /run/log/journal 2>/dev/null || true"
        )
        assert runtime_hits.strip() == "", \
            f"runtime journal files still hold the marker: {runtime_hits!r}"

    def assert_session_data_gone():
        assert_no_overlays(["/home", "/etc"])
        for marker in ("secret_1", "secret_50", "secret_100"):
            machine.fail(f"su - testuser -c 'test -f ~/{marker}.txt'")
        history = machine.succeed(
            "su - testuser -c 'cat ~/.bash_history 2>/dev/null || echo gone'"
        )
        assert "sensitive_command_1" not in history, \
            f"shell history still holds sensitive commands: {history!r}"
        assert "secret_key_export" not in history, \
            f"shell history still holds the secret key export: {history!r}"

    with subtest("set up an active session with sensitive data"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
        machine.succeed("su - testuser -c 'for i in $(seq 1 100); do echo \"secret data $i\" > ~/secret_$i.txt; done'")
        machine.succeed("su - testuser -c 'echo \"sensitive_command_1\" >> ~/.bash_history'")
        machine.succeed("su - testuser -c 'echo \"secret_key_export\" >> ~/.bash_history'")
        machine.succeed("su - testuser -c 'test -s ~/.bash_history'")
        for marker in ("secret_1", "secret_50", "secret_100"):
            machine.succeed(f"su - testuser -c 'test -f ~/{marker}.txt'")
        # Record a marker in the volatile journal and confirm it is present while
        # the hidden session is active.
        machine.succeed(f"logger -t nails-canary '{journal_marker}'")
        machine.succeed("journalctl --sync 2>/dev/null || journalctl --flush || true")
        machine.succeed(f"journalctl --no-pager | grep -q '{journal_marker}'")

    with subtest("emergency teardown cleans the live system before any reboot"):
        # Stop short of the reboot so the assertions below prove the emergency
        # command itself tore the session down, not a lucky reboot.
        emergency_time = run_emergency_command(reboot=False)
        print(f"✓ emergency command completed in {emergency_time:.3f}s")
        assert_session_data_gone()
        # The runtime journal must be scrubbed even though emergency does not
        # reboot: the volatile store would otherwise keep the hidden session's
        # records in RAM for anyone with `journalctl`.
        assert_journal_marker_gone()

    with subtest("the decoy state survives the reboot"):
        reboot_after_emergency()
        assert_session_data_gone()
        assert_journal_marker_gone()
        assert_status_state("inactive", config_path=headless_config)
  '';
}
