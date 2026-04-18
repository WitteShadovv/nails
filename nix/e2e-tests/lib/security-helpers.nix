{
  capturedCommandFns = ''
    def run_captured_command(prefix, command, unit_name=None, background=False):
        import shlex

        stdout_path = prefix + ".stdout"
        stderr_path = prefix + ".stderr"
        rc_path = prefix + ".rc"

        machine.succeed(
            "rm -f "
            + shlex.quote(stdout_path)
            + " "
            + shlex.quote(stderr_path)
            + " "
            + shlex.quote(rc_path)
        )

        shell_command = (
            "set +e; "
            + command
            + " > "
            + shlex.quote(stdout_path)
            + " 2> "
            + shlex.quote(stderr_path)
            + "; printf \"%s\" \"$?\" > "
            + shlex.quote(rc_path)
        )

        if background:
            assert unit_name is not None, "unit_name is required for background commands"
            run_detached_command(unit_name, shell_command)
        else:
            machine.succeed("/bin/sh -lc " + shlex.quote(shell_command))

        return {
            "stdout": stdout_path,
            "stderr": stderr_path,
            "rc": rc_path,
        }

    def read_command_result(prefix):
        import shlex

        stdout_path = prefix + ".stdout"
        stderr_path = prefix + ".stderr"
        rc_path = prefix + ".rc"
        rc = int(machine.succeed("cat " + shlex.quote(rc_path)).strip())
        stdout = machine.succeed("cat " + shlex.quote(stdout_path) + " 2>/dev/null || true")
        stderr = machine.succeed("cat " + shlex.quote(stderr_path) + " 2>/dev/null || true")
        return {
            "stdout": stdout,
            "stderr": stderr,
            "rc": rc,
        }

    def wait_for_command_result(prefix):
        import shlex

        rc_path = prefix + ".rc"
        machine.wait_until_succeeds("test -e " + shlex.quote(rc_path))
        return read_command_result(prefix)
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
            machine.succeed("/bin/sh -lc " + shlex.quote(script))
  '';
}
