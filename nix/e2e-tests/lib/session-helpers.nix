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

        machine.wait_until_succeeds(
            "/bin/sh -lc "
            + shlex.quote(
                "case \"$(systemctl list-units --all --plain --no-legend 'nails-activate-*')\" in "
                + "*nails-activate-*) exit 0 ;; "
                + "*) exit 1 ;; "
                + "esac"
            )
        )
        unit = machine.succeed(
            "bash -lc "
            + shlex.quote(
                "systemctl list-units --all --plain --no-legend 'nails-activate-*' "
                + "| while read -r unit _; do printf '%s' \"$unit\"; break; done"
            )
        ).strip()
        assert unit.startswith("nails-activate-"), f"Unexpected activation transient unit: {unit!r}"
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
