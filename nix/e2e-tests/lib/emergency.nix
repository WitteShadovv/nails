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

  runEmergencyCommandFn = ''
    def run_emergency_command():
        import time

        prepare_tty1_shell()
        console_start = len(machine.get_console_log())

        start_time = time.time()
        machine.send_key("alt-f1")
        machine.send_chars("systemctl reset-failed nails-emergency-test.service\n", delay=0)
        machine.wait_until_tty_matches("1", r"TTY1_READY#", timeout=30)
        machine.send_chars("systemctl start --no-block nails-emergency-test.service\n", delay=0)
        wait_for_console_log(r"Emergency deactivation complete", timeout=30, start_index=console_start)
        wait_for_console_log(r"System returned to decoy configuration", timeout=5, start_index=console_start)
        elapsed = time.time() - start_time
        reboot_after_emergency()
        return elapsed
  '';

  makeEmergencyUnit = nailsPackage: configPath: {
    description = "NAILS emergency test runner";
    serviceConfig = {
      Type = "exec";
      ExecStart = "${nailsPackage}/bin/nails --config ${configPath} emergency --no-countdown";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };
}
