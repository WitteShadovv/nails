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
