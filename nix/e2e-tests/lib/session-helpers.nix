{
  readSystemdActiveEnterMonotonicFn = ''
    def read_systemd_active_enter_monotonic(unit):
        import shlex

        value = machine.succeed(
            "systemctl show "
            + shlex.quote(unit)
            + " -p ActiveEnterTimestampMonotonic --value"
        ).strip()
        assert value and value != "0", f"Unit {unit} does not have an active timestamp: {value!r}"
        return int(value)
  '';

  # Wait until a unit has been started again after a baseline taken with
  # read_systemd_active_enter_monotonic(). `systemctl is-active` cannot tell the
  # instance that existed before a restart from the new one, so it passes before
  # the restart has even begun; the activation timestamp only moves forward once
  # the new instance is up. Needs readSystemdActiveEnterMonotonicFn.
  waitForUnitRestartedFn = ''
    def wait_for_unit_restarted(unit, before, timeout=180):
        import shlex

        quoted = shlex.quote(unit)
        machine.wait_until_succeeds(
            "systemctl is-active --quiet "
            + quoted
            + " && [ \"$(systemctl show "
            + quoted
            + " -p ActiveEnterTimestampMonotonic --value)\" -gt "
            + str(int(before))
            + " ]",
            timeout=timeout,
        )
        return read_systemd_active_enter_monotonic(unit)
  '';

  waitForActivationTransientUnitFn = ''
    def wait_for_activation_transient_unit():
        import shlex

        # T-066: the detached activation worker no longer names its transient
        # unit after the product. systemd auto-names it `run-<id>.service` and it
        # carries a fixed neutral description, so the product string never
        # reaches the decoy journal. Identify the worker by that description
        # instead of a product-specific unit name.
        description = "System maintenance task"
        finder = (
            "systemctl list-units --all --plain --no-legend 'run-*.service' "
            + "| while read -r unit _; do "
            + "if [ \"$(systemctl show \"$unit\" -p Description --value)\" = "
            + shlex.quote(description)
            + " ]; then printf '%s' \"$unit\"; break; fi; "
            + "done"
        )
        machine.wait_until_succeeds(
            "bash -lc " + shlex.quote("test -n \"$(" + finder + ")\"")
        )
        unit = machine.succeed("bash -lc " + shlex.quote(finder)).strip()
        assert unit.startswith("run-"), f"Unexpected activation transient unit: {unit!r}"
        return unit
  '';

  assertUnitInSystemSliceFn = ''
    def assert_unit_in_system_slice(unit):
        import shlex

        slice_name = machine.succeed(
            "systemctl show " + shlex.quote(unit) + " -p Slice --value"
        ).strip()
        assert slice_name == "system.slice", (
            f"Expected transient activation unit {unit} in system.slice, got {slice_name!r}"
        )
  '';
}
