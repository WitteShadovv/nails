# Shared test helper functions for E2E tests
# Provides common Python functions as string snippets that can be interpolated into testScripts
{
  # Python function to write the standard headless config file.
  # Usage in testScript: ${testHelpers.writeHeadlessConfigFn}
  # Then call: write_headless_config("/run/nails-tests/nails-headless.toml")
  #
  # The overlay set covers every base-OS tree that exists as a real directory on
  # the NixOS test host. The writable-trees pre-flight check refuses activation
  # when a core binary root (/usr, /bin, /lib64 here) is left neither overlaid nor
  # read-only, since a hidden-session write there would reach the decoy disk, so
  # the explicit config must overlay them just as auto mode does.
  writeHeadlessConfigFn = ''
    def write_headless_config(path):
        import os
        import shlex

        parent_dir = os.path.dirname(path) or "."
        machine.succeed("mkdir -p " + shlex.quote(parent_dir))
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    [[overlays]]
    name = "etc"
    lower = "/etc"
    upper = "/mnt/data/etc"
    work = "/mnt/data/.work/etc"
    target = "/etc"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"

    [[overlays]]
    name = "root"
    lower = "/root"
    upper = "/mnt/data/root"
    work = "/mnt/data/.work/root"
    target = "/root"

    [[overlays]]
    name = "srv"
    lower = "/srv"
    upper = "/mnt/data/srv"
    work = "/mnt/data/.work/srv"
    target = "/srv"

    [[overlays]]
    name = "tmp"
    lower = "/tmp"
    upper = "/mnt/data/tmp"
    work = "/mnt/data/.work/tmp"
    target = "/tmp"

    [[overlays]]
    name = "usr"
    lower = "/usr"
    upper = "/mnt/data/usr"
    work = "/mnt/data/.work/usr"
    target = "/usr"

    [[overlays]]
    name = "bin"
    lower = "/bin"
    upper = "/mnt/data/bin"
    work = "/mnt/data/.work/bin"
    target = "/bin"

    [[overlays]]
    name = "lib64"
    lower = "/lib64"
    upper = "/mnt/data/lib64"
    work = "/mnt/data/.work/lib64"
    target = "/lib64"
    EOF""" % path
        )
  '';

  # Python function to write an auto-mode config. Auto mode derives the overlay
  # set from the live base OS itself — every writable base tree, including /var
  # and /nix — rather than listing overlays explicitly, which is the product
  # default. Tests that must exercise the real default (not the hand-listed
  # explicit set) use this instead of write_headless_config.
  writeAutoConfigFn = ''
    def write_auto_config(path):
        import os
        import shlex

        parent_dir = os.path.dirname(path) or "."
        machine.succeed("mkdir -p " + shlex.quote(parent_dir))
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "auto"
    risky_services = "skip"
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
        payload = json.loads(machine.succeed("cat /tmp/nails-status.stdout"))
        # status --json is an envelope: callers work against its typed `data`.
        return payload.get("data", payload)
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
                state = payload.get("state", "")
                kind = state.get("kind", "") if isinstance(state, dict) else str(state)
                actual = kind.lower()
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
        payload = json.loads(output)
        # verify --json is an envelope: callers work against its typed `data`.
        return status, payload.get("data", payload)
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
                "nails --config " + shlex.quote(config_path) + " deactivate -y"
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
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    [[overlays]]
    name = "etc"
    lower = "/etc"
    upper = "/mnt/data/etc"
    work = "/mnt/data/.work/etc"
    target = "/etc"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"

    [[overlays]]
    name = "root"
    lower = "/root"
    upper = "/mnt/data/root"
    work = "/mnt/data/.work/root"
    target = "/root"

    [[overlays]]
    name = "var"
    lower = "/var"
    upper = "/mnt/data/var"
    work = "/mnt/data/.work/var"
    target = "/var"

    [[overlays]]
    name = "tmp"
    lower = "/tmp"
    upper = "/mnt/data/tmp"
    work = "/mnt/data/.work/tmp"
    target = "/tmp"

    [[overlays]]
    name = "srv"
    lower = "/srv"
    upper = "/mnt/data/srv"
    work = "/mnt/data/.work/srv"
    target = "/srv"

    [[overlays]]
    name = "opt"
    lower = "/opt"
    upper = "/mnt/data/opt"
    work = "/mnt/data/.work/opt"
    target = "/opt"
    EOF""" % path
        )
  '';
}
