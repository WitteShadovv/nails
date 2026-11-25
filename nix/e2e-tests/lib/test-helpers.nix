# Shared test helper functions for E2E tests
# Provides common Python functions as string snippets that can be interpolated into testScripts
{
  # Python function to write the standard headless config file.
  # Usage in testScript: ${testHelpers.writeHeadlessConfigFn}
  # Then call: write_headless_config("/run/nails-tests/nails-headless.toml")
  #
  # The whole-root session needs nothing but the hidden root: the root overlay
  # and the fstab policy are derived from the host. The hidden data disk is only
  # ~2 GB, below the 4 GB default rebuild floor, so the floor is lowered for the
  # tiny hidden configurations these tests build. `overlay_var` is accepted for
  # old call sites and ignored: /var is part of the root overlay.
  writeHeadlessConfigFn = ''
    def write_headless_config(path, overlay_var=False):
        import os
        import shlex

        parent_dir = os.path.dirname(path) or "."
        machine.succeed("mkdir -p " + shlex.quote(parent_dir))
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    rebuild_space_mb = 64
    EOF""" % path
        )
  '';

  # The same minimal config under the name the auto-mode tests used.
  writeAutoConfigFn = ''
    def write_auto_config(path):
        import os
        import shlex

        parent_dir = os.path.dirname(path) or "."
        machine.succeed("mkdir -p " + shlex.quote(parent_dir))
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    rebuild_space_mb = 64
    EOF""" % path
        )
  '';

  # Launch a command from a transient systemd unit so the test harness shell
  # returns immediately before the unit tears down shell processes or reboots.
  runDetachedCommandFn = ''
    def run_detached_command(unit_name, command):
        import shlex

        machine.succeed(
            "systemd-run --unit "
            + shlex.quote(unit_name)
            + " --no-block --service-type=exec /bin/sh -lc "
            + shlex.quote(command)
        )
  '';

  # `status` exits by posture: 0 for the safe postures, 7 for degraded or
  # inconsistent, 6 for an unknown (unreadable or corrupt) state. The JSON
  # payload is written in every case, so `read_status_json_with_rc` returns the
  # exit code alongside it for tests that drive status into a fail-closed
  # posture; `read_status_json` keeps requiring a zero exit.
  readStatusJsonFn = ''
    def read_status_json_with_rc(config_path=None):
        import json
        import shlex

        command = "nails"
        if config_path is not None:
            command += " --config " + shlex.quote(config_path)
        command += " status --json"

        rc, _ = machine.execute(
            "bash -lc "
            + shlex.quote(
                command
                + " > /run/nails-status.stdout 2>/run/nails-status.stderr"
            )
        )
        stdout = machine.succeed("cat /run/nails-status.stdout")
        try:
            payload = json.loads(stdout)
        except ValueError as err:
            stderr = machine.succeed("cat /run/nails-status.stderr")
            raise AssertionError(
                f"status --json exited {rc} without a JSON payload: "
                f"stdout={stdout!r}, stderr={stderr!r}"
            ) from err
        # status --json is an envelope: callers work against its typed `data`.
        return rc, payload.get("data", payload)

    def read_status_json(config_path=None):
        rc, data = read_status_json_with_rc(config_path=config_path)
        assert rc == 0, (
            f"status --json exited {rc}: {data}; stderr: "
            + machine.succeed("cat /run/nails-status.stderr")
        )
        return data
  '';

  waitForStatusStateFn = ''
    def wait_for_status_state(expected, config_path=None, timeout=180):
        import time

        expected_prefix = expected.lower()
        deadline = time.monotonic() + timeout
        last_payload = None
        last_error = None

        while time.monotonic() < deadline:
            try:
                payload = read_status_json(config_path=config_path)
                last_payload = payload
                actual = str(payload.get("place", "")).lower()
                if actual.startswith(expected_prefix):
                    return payload
            except Exception as exc:
                last_error = exc
            time.sleep(1)

        details = f"last_payload={last_payload!r}"
        if last_error is not None:
            details += f", last_error={last_error!r}"
        raise AssertionError(
            f"Timed out waiting for state {expected!r} within {timeout}s; {details}"
        )
  '';

  # `sudo=True` runs nails through sudo, as an operator does, so sudo logs the
  # command to the journal.
  runVerifyFn = ''
    def run_verify(args="", config_path=None, sudo=False):
        import json
        import shlex

        command = "sudo nails" if sudo else "nails"
        if config_path is not None:
            command += " --config " + shlex.quote(config_path)
        command += " verify --json"
        if args:
            command += f" {args}"

        # Capture under /run (tmpfs), not /tmp: /tmp is on the decoy disk, and
        # the forensic image scans would find verify's own output there.
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + " > /run/verify.stdout 2>/run/verify.stderr; "
                + "printf \"%s\" \"$?\" > /run/verify.rc"
            )
        )
        status = int(machine.succeed("cat /run/verify.rc"))
        output = machine.succeed("cat /run/verify.stdout")
        payload = json.loads(output)
        # verify --json is an envelope: callers work against its typed `data`.
        return status, payload.get("data", payload)
  '';

  # The standard way out of a hidden session in a test: `nails deactivate -y`
  # ends the session and powers the machine off (a hidden session never goes
  # back to the decoy). Follow it until the kernel said it powered off, with
  # no new userspace in between (session.follow_power_off), then start the
  # machine again and wait for the decoy's cold boot: the plain decoy root,
  # the hidden mapping closed and no NAILS runtime directory
  # (session.boot_decoy). `boot=False` leaves the machine off, for a test that
  # ends there or inspects its disks first. The hidden volume is closed after
  # the boot: a test that goes on opens it again as its setup does, and
  # anything it kept in /run is gone. `sudo=True` runs nails through sudo, as
  # an operator does. Returns the host-side time from the trigger to the
  # power-off.
  canonicalDeactivateFn = ''
    def canonical_deactivate(config_path, label="deactivate", sudo=False, boot=True):
        import shlex

        # Aliased, so the test's own `session` import is never shadowed.
        from nails_e2e import session as _session

        timings = _session.follow_power_off(
            machine,
            ("sudo " if sudo else "")
            + "nails --config "
            + shlex.quote(config_path)
            + " deactivate -y",
            label,
        )
        if boot:
            _session.boot_decoy(machine)
        return timings
  '';

  # `nails emergency` in the hidden session: it kills the session's shells,
  # enqueues poweroff.target and kills the rest, so the machine powers off.
  # Followed and booted again as canonical_deactivate does. `extra_args` are
  # emergency's flags (`--json` among them; its output is discarded, because
  # the shell that ran it is gone); `--reboot` is no power-off and is not for
  # this helper.
  canonicalEmergencyFn = ''
    def canonical_emergency(config_path, label="emergency", extra_args="", sudo=False, boot=True):
        import shlex

        from nails_e2e import session as _session

        timings = _session.follow_power_off(
            machine,
            ("sudo " if sudo else "")
            + "nails --config "
            + shlex.quote(config_path)
            + " emergency "
            + extra_args,
            label,
        )
        if boot:
            _session.boot_decoy(machine)
        return timings
  '';

  # Enter the hidden session from a test: `nails activate -y` soft-reboots into
  # the hidden root. Its output goes to the hidden volume (the decoy shell that
  # ran it is gone after the switch) and, line by line, to the serial console
  # the driver records, so a long step (a hidden build, the first copy of the
  # hidden system) shows its progress in the test log, and a failed activation
  # shows its own error there before the test fails. `env` is a prefix of
  # variable assignments (for example the sudo variables that name the
  # operator), and `sudo=True` runs nails through sudo, as an operator does.
  # `deadline_s` bounds the wait for the hidden root's backdoor. Returns the
  # in-guest timings.
  canonicalActivateFn = ''
    def canonical_activate(
        config_path,
        extra_args="",
        label="activate",
        env="",
        deadline_s=600.0,
        sudo=False,
    ):
        import shlex

        # Aliased, so the test's own `session` import is never shadowed.
        from nails_e2e import session as _session

        log = "/mnt/data/" + label + ".log"
        timings = _session.follow_soft_reboot(
            machine,
            "set -o pipefail; "
            + env
            + (" sudo" if sudo else "")
            + " nails --config "
            + shlex.quote(config_path)
            + " activate -y "
            + extra_args
            + " 2>&1 | tee "
            + log
            + " > "
            + _session.SERIAL_CONSOLE,
            label,
            deadline_s=deadline_s,
        )
        print(machine.succeed("cat " + log + " || true"))
        _session.assert_hidden_root(machine)
        return timings
  '';
}
