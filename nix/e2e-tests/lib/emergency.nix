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

  # Wait for the emergency unit to finish by polling systemd over the test
  # backdoor, not by scanning the console. The teardown restarts journald while
  # it scrubs the runtime journal, which severs the unit's journal+console
  # stream, so any line nails prints afterwards (including "Emergency teardown
  # complete") can never reach the console. systemd's own record of the unit
  # result survives that restart, so it is the reliable completion signal. On a
  # failure the helper dumps the unit status, its journal and any overlay mounts
  # still present, so a future run explains itself instead of only timing out.
  waitForEmergencyUnitFn = ''
    EMERGENCY_UNIT = "nails-emergency-test.service"

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

    def emergency_invocation_id():
        return machine.succeed(
            f"systemctl show {EMERGENCY_UNIT} -p InvocationID --value"
        ).strip()

    # Block until a run of the emergency unit started after `previous_invocation`
    # has finished, keying on systemd's per-start InvocationID so a unit that has
    # not started yet (same inactive state as a finished one) is never mistaken
    # for a completed run. The unit result is read from systemd, which survives
    # the journald restart the teardown performs, and anything but a clean exit
    # dumps diagnostics.
    def wait_for_emergency_unit(previous_invocation, timeout=60):
        import time

        deadline = time.time() + timeout
        active = ""
        invocation = ""
        while time.time() < deadline:
            invocation = emergency_invocation_id()
            active = machine.succeed(
                f"systemctl show {EMERGENCY_UNIT} -p ActiveState --value"
            ).strip()
            if invocation and invocation != previous_invocation and active in ("inactive", "failed"):
                break
            time.sleep(0.5)
        else:
            _dump_emergency_diagnostics(f"did not finish within {timeout}s")

        result = machine.succeed(
            f"systemctl show {EMERGENCY_UNIT} -p Result --value"
        ).strip()
        if not (active == "inactive" and result == "success"):
            _dump_emergency_diagnostics(
                f"finished unsuccessfully (ActiveState={active}, Result={result})"
            )
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
        previous_invocation = emergency_invocation_id()
        machine.send_key("alt-f1")
        machine.send_chars("systemctl reset-failed nails-emergency-test.service\n", delay=0)
        machine.wait_until_tty_matches("1", r"TTY1_READY#", timeout=30)
        machine.send_chars("systemctl start --no-block nails-emergency-test.service\n", delay=0)
        wait_for_emergency_unit(previous_invocation, timeout=60)
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
    };
  };
}
