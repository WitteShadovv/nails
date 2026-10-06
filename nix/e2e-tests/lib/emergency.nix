{
  prepareTty1ShellFn = ''
    def prepare_tty1_shell():
        machine.wait_for_unit("getty@tty1.service")
        machine.send_key("alt-f1")
        machine.wait_until_tty_matches("1", r"#", timeout=60)
        machine.send_chars("export PS1='TTY1_READY# '\n", delay=0)
        machine.wait_until_tty_matches("1", r"TTY1_READY#", timeout=30)
  '';

  waitForConsoleLogFn = ''
    def wait_for_console_log(regex, timeout, start_index=0):
        import re
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            console_log = machine.get_console_log()[start_index:]
            if re.search(regex, console_log):
                return
            time.sleep(0.2)
        raise AssertionError(f"Timed out after {timeout}s waiting for console log regex: {regex}")
  '';

  rebootAfterEmergencyFn = ''
    def reboot_after_emergency():
        machine.send_key("ctrl-alt-delete")
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
  '';

  # Wait for the emergency unit to finish through a result file the unit's
  # ExecStopPost writes under /run, not by scanning the console or querying the
  # unit's runtime record. The teardown restarts journald while it scrubs the
  # runtime journal, which severs the unit's journal+console stream, and it
  # reloads systemd after restoring /etc, which drops the unit's Result and
  # InvocationID; the tmpfs result file survives both. On a failure the helper
  # dumps the unit status, its journal and any overlay mounts still present, so
  # a future run explains itself instead of only timing out.
  waitForEmergencyUnitFn = ''
    EMERGENCY_UNIT = "nails-emergency-test.service"
    EMERGENCY_RESULT = "/run/nails-emergency-test.result"

    def _dump_emergency_diagnostics(reason):
        status = machine.execute(f"systemctl status {EMERGENCY_UNIT} --no-pager -l")[1]
        journal = machine.execute(f"journalctl -u {EMERGENCY_UNIT} --no-pager -b")[1]
        overlays = machine.execute("findmnt -rn -t overlay -o TARGET,SOURCE || true")[1]
        raise AssertionError(
            f"emergency unit {reason}\n"
            f"--- systemctl status {EMERGENCY_UNIT} ---\n{status}\n"
            f"--- journalctl -u {EMERGENCY_UNIT} ---\n{journal}\n"
            f"--- remaining overlay mounts ---\n{overlays}\n"
        )

    def clear_emergency_result():
        machine.succeed(f"rm -f {EMERGENCY_RESULT}")

    # Block until the emergency unit's ExecStopPost has recorded the run's
    # outcome ("<SERVICE_RESULT> <EXIT_STATUS>"), and require a clean exit.
    def wait_for_emergency_unit(timeout=60):
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            rc, out = machine.execute(f"cat {EMERGENCY_RESULT}")
            if rc == 0 and out.strip():
                break
            time.sleep(0.5)
        else:
            _dump_emergency_diagnostics(f"did not finish within {timeout}s")

        fields = out.split()
        if fields[:2] != ["success", "0"]:
            _dump_emergency_diagnostics(f"finished unsuccessfully ({out.strip()})")
  '';

  # With reboot=False the caller can assert the live, post-emergency state
  # before the machine reboots, so a test proves emergency teardown itself
  # cleaned up rather than relying on the reboot to hide leftovers.
  runEmergencyCommandFn = ''
    def run_emergency_command(reboot=True):
        import time

        prepare_tty1_shell()

        start_time = time.time()
        # Start the teardown from the tty1 operator shell, exactly as a user at
        # the console would. Completion is then observed through systemd rather
        # than the console, which the teardown's journald restart would sever.
        clear_emergency_result()
        machine.send_key("alt-f1")
        machine.send_chars("systemctl reset-failed nails-emergency-test.service\n", delay=0)
        machine.wait_until_tty_matches("1", r"TTY1_READY#", timeout=30)
        machine.send_chars("systemctl start --no-block nails-emergency-test.service\n", delay=0)
        wait_for_emergency_unit(timeout=60)
        elapsed = time.time() - start_time
        if reboot:
            reboot_after_emergency()
        return elapsed
  '';

  makeEmergencyUnit = nailsPackage: configPath: {
    description = "NAILS emergency test runner";
    serviceConfig = {
      Type = "exec";
      ExecStart = "${nailsPackage}/bin/nails --config ${configPath} emergency";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      # Record the outcome where the test can read it after the teardown has
      # restarted journald and reloaded systemd.
      ExecStopPost = "/bin/sh -c 'echo \"$$SERVICE_RESULT $$EXIT_STATUS\" > /run/nails-emergency-test.result'";
    };
  };
}
