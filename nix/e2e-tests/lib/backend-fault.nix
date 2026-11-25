# Shared steps of the backend-fault tests (tests/faults/): the hidden backend
# fails while the whole-root session runs, and the way out must still end with
# the machine off within a bounded wait. A hidden session never goes back to
# the decoy, so every ending is a power-off.
{
  # `emergency_outcome(trigger, label)`: run `trigger` (a shell command that
  # tears the hidden session down) in the background and follow the machine
  # until it powers off for real (session.follow_power_off: the kernel's
  # "reboot: Power down" on the console and no new userspace before it).
  # Returns "off", with the driver reset so `machine.start()` boots it again.
  # Fails at once if a new userspace comes up instead, lands in emergency mode
  # or PID 1 freezes, and after `deadline_s` if the machine is still on.
  # `trigger=None` waits for a teardown something else starts (the backend
  # watcher's auto-emergency); `console_index` then names where in the console
  # log to start looking, so an ending that began before the call is not
  # missed. A wait that runs out reports what PID 1 waits on and the SysRq
  # dumps (nails_e2e.stall).
  emergencyOutcomeFn = ''
    def emergency_outcome(trigger, label, deadline_s=600, console_index=None):
        from nails_e2e import session

        session.follow_power_off(
            machine, trigger, label, deadline_s=deadline_s, console_index=console_index
        )
        return "off"
  '';

  # The checks every fault test makes once the machine is off: a cold boot is
  # the plain decoy, with the hidden mapping closed and no NAILS runtime
  # directory (session.boot_decoy).
  assertFaultExitFn = ''
    def assert_fault_exit(outcome):
        from nails_e2e import session

        assert outcome == "off", outcome
        session.boot_decoy(machine)
  '';
}
