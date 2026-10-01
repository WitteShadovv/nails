# Shared test helper functions for E2E tests
# Provides common Python functions as string snippets that can be interpolated into testScripts
{
  # Python function to write the standard headless config file.
  # Usage in testScript: ${testHelpers.writeHeadlessConfigFn}
  # Then call: write_headless_config("/run/nails-tests/nails-headless.yaml")
  writeHeadlessConfigFn = ''
    def write_headless_config(path):
        import os
        import shlex

        parent_dir = os.path.dirname(path) or "."
        machine.succeed("mkdir -p " + shlex.quote(parent_dir))
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: root
        lower: /root
        upper: /mnt/hidden-volume/root
        work: /mnt/hidden-volume/.work/root
        target: /root
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
      - name: tmp
        lower: /tmp
        upper: /mnt/hidden-volume/tmp
        work: /mnt/hidden-volume/.work/tmp
        target: /tmp
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

  readStatusJsonFn = ''
    def read_status_json(config_path=None):
        import json
        import shlex

        command = "nails"
        if config_path is not None:
            command += " --config " + shlex.quote(config_path)
        command += " status --json"

        machine.succeed(
            "bash -lc "
            + shlex.quote(
                command
                + " > /tmp/nails-status.stdout 2>/tmp/nails-status.stderr"
            )
        )
        return json.loads(machine.succeed("cat /tmp/nails-status.stdout"))
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
                actual = str(payload.get("state", "")).lower()
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

  runVerifyFn = ''
    def run_verify(args="", config_path=None):
        import json
        import shlex

        command = "nails"
        if config_path is not None:
            command += " --config " + shlex.quote(config_path)
        command += " verify --json"
        if args:
            command += f" {args}"

        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + " > /tmp/verify.stdout 2>/tmp/verify.stderr; "
                + "printf \"%s\" \"$?\" > /tmp/verify.rc"
            )
        )
        status = int(machine.succeed("cat /tmp/verify.rc"))
        output = machine.succeed("cat /tmp/verify.stdout")
        return status, json.loads(output)
  '';

  # Deactivation powers the VM off. The driver's wait_for_shutdown() waits on
  # QEMU without a deadline, so a deactivation that never finished held the
  # test until globalTimeout and reported nothing. This waits on the QEMU
  # process with a deadline and fails with guest diagnostics instead.
  canonicalDeactivateFn = ''
    def canonical_deactivate(
        config_path,
        unit_name="nails-deactivate",
        shutdown_timeout=300,
        diagnostics_timeout=90,
    ):
        import shlex
        import subprocess
        import threading

        def collect_shutdown_diagnostics():
            quoted_unit = shlex.quote(unit_name)
            commands = [
                (
                    f"systemctl status {unit_name}",
                    f"systemctl status {quoted_unit} --no-pager --full",
                ),
                (
                    f"journal of {unit_name}",
                    f"journalctl -u {quoted_unit} -n 100 -o short-precise --no-pager",
                ),
                ("journal tail", "journalctl -b -n 200 -o short-precise --no-pager"),
                ("pending systemd jobs", "systemctl list-jobs --no-pager"),
                (
                    "process list",
                    "ps -eo pid,ppid,stat,etimes,wchan:32,args --forest",
                ),
            ]
            sections = []

            def run_commands():
                for label, command in commands:
                    _, output = machine.execute(
                        f"timeout 10s {command} 2>&1 || true",
                        check_return=False,
                        timeout=30,
                    )
                    sections.append(f"--- {label} ---\n{output.rstrip()}")

            # Once shutdown has begun the guest's backdoor shell may already be
            # gone, and execute() then blocks reading from it forever (its
            # timeout runs inside the guest). Collect on a daemon thread so a
            # dead shell cannot hang the test a second time.
            collector = threading.Thread(target=run_commands, daemon=True)
            collector.start()
            collector.join(diagnostics_timeout)
            collected = list(sections)
            if collector.is_alive():
                console_tail = machine.get_console_log().splitlines()[-100:]
                collected.append(
                    "--- guest shell unresponsive; serial console tail ---\n"
                    + "\n".join(console_tail)
                )
            return "\n".join(collected)

        machine.succeed(
            "systemd-run --unit "
            + shlex.quote(unit_name)
            + " --no-block --service-type=exec /bin/sh -lc "
            + shlex.quote(
                "nails --config " + shlex.quote(config_path) + " deactivate"
            )
        )

        # Wait on QEMU itself rather than polling the guest: the guest shell
        # goes away during power-off, so only the host process is reliable.
        timed_out = False
        process = machine.process
        if process is not None:
            with machine.nested(
                f"waiting up to {shutdown_timeout}s for the VM to power off"
            ):
                try:
                    process.wait(timeout=shutdown_timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
        if timed_out:
            raise AssertionError(
                f"canonical_deactivate: VM did not power off within "
                f"{shutdown_timeout}s after starting {unit_name}\n"
                + collect_shutdown_diagnostics()
            )

        # QEMU has exited, so this returns at once; it also resets the driver's
        # booted/connected state so the machine can be started again.
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
  '';

  writeExtendedConfigFn = ''
    def write_extended_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: root
        lower: /root
        upper: /mnt/hidden-volume/root
        work: /mnt/hidden-volume/.work/root
        target: /root
      - name: var
        lower: /var
        upper: /mnt/hidden-volume/var
        work: /mnt/hidden-volume/.work/var
        target: /var
      - name: tmp
        lower: /tmp
        upper: /mnt/hidden-volume/tmp
        work: /mnt/hidden-volume/.work/tmp
        target: /tmp
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
      - name: opt
        lower: /opt
        upper: /mnt/hidden-volume/opt
        work: /mnt/hidden-volume/.work/opt
        target: /opt
    EOF""" % path
        )
  '';

  writeEphemeralConfigFn = ''
    def write_ephemeral_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    # Harness fixture for unsupported extended_overlays coverage.
    # This is not a supported ephemeral mode; activation is expected to fail in preflight.
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: root
        lower: /root
        upper: /mnt/hidden-volume/root
        work: /mnt/hidden-volume/.work/root
        target: /root
    extended_overlays:
      enabled: true
      directories:
        - path: /var
          tmpfs_upper_size: 256M
          tmpfs_work_size: 128M
        - path: /tmp
          tmpfs_upper_size: 256M
          tmpfs_work_size: 128M
        - path: /srv
          tmpfs_upper_size: 128M
          tmpfs_work_size: 64M
        - path: /opt
          tmpfs_upper_size: 128M
          tmpfs_work_size: 64M
    EOF""" % path
        )
  '';
}
