# Test 81: Emergency backend close/lock
#
# The emergency panic button always tears down the overlays; closing the
# encrypted backend is opt-in. This test exercises both paths against a real LUKS
# backend (the "data" dm device mounted at /mnt/data):
#
#   - Without the opt-in: after a plain emergency the hidden root stays mounted
#     and the dm device stays open, and `nails verify`/`status` report the
#     still-mounted hidden root as Critical.
#   - With `--lock-backend`: after the process exits the hidden root is unmounted
#     and `/dev/mapper/data` is gone (deferred removal fired as the last
#     reference dropped). A close failure fails the test.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  emergency = import ./../../lib/emergency.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "emergency-backend-lock";
  meta.tags = [
    "security"
    "forensic"
  ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
        services.getty.autologinUser = "root";
        # Plain emergency (backend left open) and the opt-in lock variant, each a
        # detached transient unit so the teardown's shell kill cannot abort the
        # driver's own shell.
        systemd.services.nails-emergency-test = emergency.makeEmergencyUnit self.packages.x86_64-linux.nails "/tmp/nails-headless.toml";
        systemd.services.nails-emergency-lock-test = {
          description = "NAILS emergency lock test runner";
          serviceConfig = {
            Type = "exec";
            ExecStart = "${self.packages.x86_64-linux.nails}/bin/nails --config /tmp/nails-headless.toml emergency --lock-backend";
            StandardOutput = "journal+console";
            StandardError = "journal+console";
          };
        };
      };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${emergency.prepareTty1ShellFn}
    ${emergency.waitForConsoleLogFn}
    ${emergency.runEmergencyCommandFn}
    ${assertions.assertNoOverlaysFn}

    def run_lock_emergency():
        # Mirror run_emergency_command, but start the --lock-backend unit instead.
        import time
        prepare_tty1_shell()
        console_start = len(machine.get_console_log())
        machine.send_key("alt-f1")
        machine.send_chars("systemctl reset-failed nails-emergency-lock-test.service\n", delay=0)
        machine.wait_until_tty_matches("1", r"TTY1_READY#", timeout=30)
        machine.send_chars("systemctl start --no-block nails-emergency-lock-test.service\n", delay=0)
        wait_for_console_log(r"Emergency teardown complete", timeout=30, start_index=console_start)
        # Wait for the transient unit to exit so the deferred dm removal has fired
        # (the kernel removes the device once the last reference — the nails
        # process — drops at exit).
        machine.wait_until_fails("systemctl is-active --quiet nails-emergency-lock-test.service")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("set up and activate a hidden session over the LUKS backend"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
        machine.succeed("findmnt /mnt/data")

    with subtest("a plain emergency leaves the backend open and reports it Critical"):
        run_emergency_command(reboot=False)
        assert_no_overlays(["/home", "/etc"])
        # The hidden root is still mounted and the dm device still open.
        machine.succeed("findmnt /mnt/data")
        machine.succeed("test -e /dev/mapper/data")
        # verify and status must name the still-mounted hidden root as Critical.
        verify_out = machine.succeed(
            f"nails --config {headless_config} verify --json || true"
        )
        assert "hidden root still mounted" in verify_out, \
            f"verify did not report the still-mounted hidden root: {verify_out!r}"
        status_out = machine.succeed(
            f"nails --config {headless_config} status --json || true"
        )
        assert '"hidden_root_mounted":true' in status_out.replace(" ", ""), \
            f"status did not report the hidden root as mounted: {status_out!r}"

    with subtest("emergency --lock-backend closes the backend as the process exits"):
        run_lock_emergency()
        # After the process exits the lazy unmount has detached the mount and the
        # deferred removal has dropped the dm device.
        machine.fail("findmnt /mnt/data")
        machine.fail("test -e /dev/mapper/data")
  '';
}
