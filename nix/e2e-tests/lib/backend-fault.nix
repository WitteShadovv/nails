# Shared steps of the backend-fault tests (tests/faults/): the hidden backend
# fails while the whole-root session runs, and the way out must still end on
# the plain decoy or with the machine off, within a bounded wait.
{
  # `emergency_outcome(trigger, label)`: run `trigger` (a shell command that
  # tears the hidden session down) in the background and follow the machine
  # until it either comes back on the plain decoy (returns "decoy", with the
  # backdoor reconnected and the decoy root asserted) or powers off (returns
  # "off", with the driver reset so `machine.start()` boots it again). Fails at
  # once if the next userspace lands in emergency mode or PID 1 freezes, and
  # after `deadline_s` if neither outcome came. A failed backend can stall the
  # hidden shutdown, so this does not require the soft-reboot back: a power-off
  # is the documented fallback. `trigger=None` waits for a teardown something
  # else starts (the backend watcher's auto-emergency); `console_index` then
  # names where in the console log to start looking, so a switch that began
  # before the call is not missed.
  emergencyOutcomeFn = ''
    def emergency_outcome(trigger, label, deadline_s=600, console_index=None):
        import signal
        import time

        from nails_e2e import session

        if console_index is None:
            console_index = len(machine.full_console_log)
        if trigger is not None:
            machine.execute(
                f"({trigger}) </dev/null >/dev/null 2>&1 &",
                check_return=False,
                check_output=False,
            )
        deadline = time.monotonic() + deadline_s
        while True:
            lines = machine.full_console_log[console_index:]
            stuck = session.stuck_lines(lines)
            if stuck:
                machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
                raise AssertionError(f"{label}: the next userspace is stuck: {stuck[0]}")
            if any(session.BACKDOOR_MARKER in line for line in lines):
                break
            if machine.process is not None and machine.process.poll() is not None:
                machine.log(f"{label}: the machine powered off")
                machine.process.wait(timeout=30)
                machine.connected = False
                machine.wait_for_shutdown()
                return "off"
            if time.monotonic() > deadline:
                machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
                raise AssertionError(
                    f"{label}: neither back on the decoy nor off after {deadline_s} s"
                )
            time.sleep(
                0.5
            )  # sync-lint: allow sleep -- polls the console log and QEMU under the deadline above

        def _alarm(_signum, _frame):
            raise TimeoutError()

        machine.connected = False
        previous = signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(120)
        try:
            machine.connect()
        except TimeoutError:
            raise AssertionError(
                f"{label}: the backdoor announced itself but never connected"
            ) from None
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        return "decoy"
  '';

  # The checks every fault test makes once the machine is back: on the decoy
  # the hidden mapping is gone (the deferred close released it with the hidden
  # root), the RAM copy and the watcher's runtime unit did not survive, and the
  # hidden /run left nothing behind; after a power-off, a cold boot is the plain
  # decoy.
  assertFaultExitFn = ''
    def assert_fault_exit(outcome, run_before, wall):
        from nails_e2e import session

        if outcome == "off":
            machine.start()
            machine.wait_for_unit("multi-user.target")
            session.assert_decoy_root(machine)
            return
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
        machine.fail("test -e /run/overlay-runtime")
        machine.fail("test -e /run/systemd/system/overlay-runtime-monitor.service")
        residue = session.carried_run_residue(machine, run_before, wall)
        assert not residue, f"hidden /run residue on the decoy: {residue}"
  '';
}
