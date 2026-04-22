{
  capturedCommandFns = ''
    def _parse_systemd_show(output):
        props = {}
        for line in output.strip().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                props[key] = value
        return props

    def _capture_paths(prefix):
        import os

        return {
            "stdout": prefix + ".stdout",
            "stderr": prefix + ".stderr",
            "rc": prefix + ".rc",
            "parent": os.path.dirname(prefix) or ".",
        }

    def _read_optional_file(path):
        import shlex

        return machine.succeed("cat " + shlex.quote(path) + " 2>/dev/null || true")

    def _wait_for_console_regex(regex, timeout=60, start_index=0):
        import re
        import time

        compiled = re.compile(regex, re.S)
        deadline = time.time() + timeout
        last_console = ""

        while time.time() < deadline:
            console_log = machine.get_console_log()[start_index:]
            match = compiled.search(console_log)
            if match is not None:
                return console_log, match
            last_console = console_log
            time.sleep(0.2)

        raise AssertionError(
            f"Timed out after {timeout}s waiting for console regex {regex!r}. "
            f"Recent console tail: {last_console[-2000:]!r}"
        )

    def _timeout_seconds(timeout):
        return max(1, int(timeout))

    def _rc_from_systemd_props(props, fallback=None):
        exec_main_code = props.get("ExecMainCode", "")
        exec_main_status = props.get("ExecMainStatus", "0") or "0"

        try:
            status = int(exec_main_status)
        except ValueError:
            return fallback if fallback is not None else 1

        if exec_main_code == "exited":
            return status
        if exec_main_code == "killed":
            return 128 + status
        if exec_main_code:
            return status

        return fallback if fallback is not None else status

    def _collect_unit_diagnostics(unit_name):
        import json
        import shlex

        diagnostics = {}
        diagnostic_commands = {
            "systemctl_show": (
                "timeout 10s systemctl show "
                + shlex.quote(unit_name)
                + " -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus -p MainPID || true"
            ),
            "systemctl_status": (
                "timeout 10s systemctl status "
                + shlex.quote(unit_name)
                + " --no-pager --full || true"
            ),
            "journalctl": (
                "timeout 10s journalctl -u "
                + shlex.quote(unit_name)
                + " --no-pager -n 200 -o short-precise || true"
            ),
        }

        for label, command in diagnostic_commands.items():
            status, output = machine.execute(command)
            diagnostics[label] = {
                "status": status,
                "output": output.strip(),
            }

        return json.dumps(diagnostics, indent=2, sort_keys=True)

    def _read_optional_systemd_show(unit_name):
        import shlex

        status, output = machine.execute(
            "timeout 10s systemctl show "
            + shlex.quote(unit_name)
            + " -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus -p MainPID"
        )
        if status != 0:
            return {}
        return _parse_systemd_show(output)

    def _wait_for_unit_terminal_state(unit_name, timeout=60):
        import time

        deadline = time.time() + timeout
        last_props = {}

        while time.time() < deadline:
            props = _read_optional_systemd_show(unit_name)
            if props:
                last_props = props
                active_state = props.get("ActiveState", "")
                result = props.get("Result", "")
                exec_main_code = props.get("ExecMainCode", "")

                if active_state in ("inactive", "failed") and result and exec_main_code:
                    return props

            time.sleep(0.2)

        diagnostics = "\nBounded diagnostics:\n" + _collect_unit_diagnostics(unit_name)
        raise AssertionError(
            f"Timed out after {timeout}s waiting for terminal state for unit {unit_name}. "
            f"Last observed props: {last_props!r}{diagnostics}"
        )

    def _wait_for_unit_console_completion(unit_name, timeout=60, start_index=0):
        import re
        import time

        deadline = time.time() + timeout
        unit_re = re.escape(unit_name) + r"\.service"
        success_re = re.compile(unit_re + r": Deactivated successfully\.")
        failure_re = re.compile(unit_re + r": Failed with result '.*'\.")

        while time.time() < deadline:
            console_log = machine.get_console_log()[start_index:]
            if success_re.search(console_log) or failure_re.search(console_log):
                return
            time.sleep(0.2)

        diagnostics = "\nBounded diagnostics:\n" + _collect_unit_diagnostics(unit_name)
        raise AssertionError(
            f"Timed out after {timeout}s waiting for console completion for unit {unit_name}.{diagnostics}"
        )

    def _wait_for_result_file(path, timeout=60, unit_name=None):
        import shlex
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            status, _ = machine.execute("test -e " + shlex.quote(path))
            if status == 0:
                return
            time.sleep(0.2)

        diagnostics = ""
        if unit_name is not None:
            diagnostics = "\nBounded diagnostics:\n" + _collect_unit_diagnostics(unit_name)

        raise AssertionError(
            f"Timed out after {timeout}s waiting for result file {path}.{diagnostics}"
        )

    def run_captured_command(prefix, command, unit_name=None, background=False, timeout=60):
        import shlex
        import uuid

        paths = _capture_paths(prefix)
        stdout_path = paths["stdout"]
        stderr_path = paths["stderr"]
        rc_path = paths["rc"]
        machine.succeed("mkdir -p " + shlex.quote(paths["parent"]))

        machine.succeed(
            "rm -f "
            + shlex.quote(stdout_path)
            + " "
            + shlex.quote(stderr_path)
            + " "
            + shlex.quote(rc_path)
        )

        if unit_name is None:
            unit_name = "nails-capture-" + uuid.uuid4().hex

        assert command.strip(), f"Command must not be empty: {command!r}"

        shell_command = (
            "set +e; "
            + command
            + " > "
            + shlex.quote(stdout_path)
            + " 2> "
            + shlex.quote(stderr_path)
            + "; rc=$?; printf \"%s\" \"$rc\" > "
            + shlex.quote(rc_path)
            + "; exit \"$rc\""
        )

        systemd_run = (
            "systemd-run --unit "
            + shlex.quote(unit_name)
            + " --service-type=exec --property "
            + shlex.quote("RuntimeMaxSec=" + str(_timeout_seconds(timeout)))
        )
        if background:
            systemd_run += " --no-block"
        else:
            systemd_run += " --wait"
        systemd_run += " /bin/sh -lc " + shlex.quote(shell_command)

        machine.succeed(
            "systemctl reset-failed " + shlex.quote(unit_name) + " >/dev/null 2>&1 || true"
        )

        if background:
            machine.succeed(systemd_run)
        else:
            machine.execute(systemd_run)

        return {
            "unit_name": unit_name,
            "stdout": stdout_path,
            "stderr": stderr_path,
            "rc": rc_path,
        }

    def run_shellless_transient_command(prefix, argv, unit_name=None, timeout=60):
        import shlex
        import uuid

        assert isinstance(argv, (list, tuple)), f"argv must be a list/tuple, got: {type(argv)!r}"
        assert argv, "argv must not be empty"
        assert all(isinstance(arg, str) and arg for arg in argv), f"argv entries must be non-empty strings: {argv!r}"

        paths = _capture_paths(prefix)
        stdout_path = paths["stdout"]
        stderr_path = paths["stderr"]
        machine.succeed("mkdir -p " + shlex.quote(paths["parent"]))
        machine.succeed(
            "rm -f "
            + shlex.quote(stdout_path)
            + " "
            + shlex.quote(stderr_path)
            + " "
            + shlex.quote(paths["rc"])
        )

        if unit_name is None:
            unit_name = "nails-capture-exec-" + uuid.uuid4().hex

        runtime_max = _timeout_seconds(timeout)
        systemd_run = (
            "timeout 15s systemd-run --unit "
            + shlex.quote(unit_name)
            + " --no-block --service-type=exec --property "
            + shlex.quote("RuntimeMaxSec=" + str(runtime_max))
            + " --property "
            + shlex.quote("StandardOutput=file:" + stdout_path)
            + " --property "
            + shlex.quote("StandardError=file:" + stderr_path)
            + " -- "
            + " ".join(shlex.quote(arg) for arg in argv)
        )

        machine.succeed(
            "systemctl reset-failed " + shlex.quote(unit_name) + " >/dev/null 2>&1 || true"
        )

        machine.succeed(systemd_run)
        props = _wait_for_unit_terminal_state(unit_name, timeout=timeout)
        stdout = _read_optional_file(stdout_path)
        stderr = _read_optional_file(stderr_path)

        result = {
            "unit_name": unit_name,
            "stdout": stdout,
            "stderr": stderr,
            "systemd": props,
            "rc": _rc_from_systemd_props(props),
        }

        if props.get("Result") != "success":
            result["diagnostics"] = _collect_unit_diagnostics(unit_name)

        return result

    def read_command_result(prefix, unit_name=None, timeout=60):
        rc_path = prefix + ".rc"
        _wait_for_result_file(rc_path, timeout=timeout, unit_name=unit_name)
        stdout = _read_optional_file(prefix + ".stdout")
        stderr = _read_optional_file(prefix + ".stderr")
        rc = int(_read_optional_file(rc_path).strip() or "0")
        props = _read_optional_systemd_show(unit_name) if unit_name is not None else {}

        return {
            "stdout": stdout,
            "stderr": stderr,
            "rc": rc,
            "unit": unit_name,
            "systemd": props,
        }

    def read_unit_main_status(unit_name):
        import shlex

        props = _parse_systemd_show(
            machine.succeed(
                "timeout 10s systemctl show "
                + shlex.quote(unit_name)
                + " -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus -p MainPID"
            )
        )

        return {
            "rc": _rc_from_systemd_props(props),
            "systemd": props,
        }

    def wait_for_command_result(prefix, unit_name=None, timeout=60):
        return read_command_result(prefix, unit_name=unit_name, timeout=timeout)

    def wait_for_file_contains(path, needle, timeout=30, unit_name=None):
        import time

        deadline = time.time() + timeout
        last_content = ""
        while time.time() < deadline:
            last_content = _read_optional_file(path)
            if needle in last_content:
                return last_content
            time.sleep(0.2)

        diagnostics = ""
        if unit_name is not None:
            diagnostics = "\nBounded diagnostics:\n" + _collect_unit_diagnostics(unit_name)

        raise AssertionError(
            f"Timed out after {timeout}s waiting for {needle!r} in {path}. "
            f"Current content was: {last_content!r}{diagnostics}"
        )
  '';

  transitionalStateFns = ''
    import json
    import shlex

    def backup_state_file(state_path, backup_path):
        machine.succeed(
            "cp " + shlex.quote(state_path) + " " + shlex.quote(backup_path)
        )

    def restore_state_file(state_path, backup_path):
        machine.succeed(
            "cp " + shlex.quote(backup_path) + " " + shlex.quote(state_path)
        )

    def force_state_file_state(state_path, target_state):
        script = f"""python3 - <<'PY'
    import json

    state_path = {json.dumps(state_path)}
    target_state = {json.dumps(target_state)}

    with open(state_path, 'r', encoding='utf-8') as handle:
        payload = json.load(handle)

    state = payload['state']

    if isinstance(state, dict):
        previous = next(iter(state.values())) or {{}}
        timestamp = (
            previous.get('started_at')
            or previous.get('activated_at')
            or previous.get('triggered_at')
            or '1970-01-01T00:00:00Z'
        )
        if target_state in ('Activating', 'Deactivating'):
            payload['state'] = {{target_state: {{'started_at': timestamp}}}}
        elif target_state == 'Inactive':
            payload['state'] = 'Inactive'
        else:
            raise SystemExit(f'Unsupported target state: {{target_state}}')
    elif isinstance(state, str):
        payload['state'] = target_state
    else:
        raise SystemExit(f'Unsupported state encoding: {{state!r}}')

    payload.pop('checksum', None)

    with open(state_path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle)
    PY"""
        machine.succeed(script)
  '';
}
