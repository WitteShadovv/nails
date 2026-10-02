{
  writeNotificationConfigFn = ''
    def write_notification_config(path, hidden_volume_root="/mnt/hidden-volume"):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "%s"
    EOF""" % (path, hidden_volume_root)
        )
  '';

  installNotifySendStubFn = ''
    def install_notify_send_stub(bin_dir, log_path):
        import shlex

        stub_path = f"{bin_dir}/notify-send"
        machine.succeed("mkdir -p " + shlex.quote(bin_dir))
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "cat > "
                + shlex.quote(stub_path)
                + " <<'EOF'\n"
                + "#!/bin/sh\n"
                + "set -eu\n"
                + "{\n"
                + "  printf '__CALL__\\n'\n"
                + "  for arg in \"$@\"; do\n"
                + "    printf '%s\\n' \"$arg\"\n"
                + "  done\n"
                + "} >> "
                + shlex.quote(log_path)
                + "\n"
                + "exit 0\n"
                + "EOF\n"
                + "chmod 0755 "
                + shlex.quote(stub_path)
                + "\n"
                + ": > "
                + shlex.quote(log_path)
                + "\n"
                + "chmod 0666 "
                + shlex.quote(log_path)
            )
        )
  '';

  # Stage a pre-queued signal for tests that exercise the dispatcher on its
  # own. It is laid out the way nails leaves a queued signal: the queue
  # directory belongs to the dispatching account with mode 0700, and the file
  # is written by that account with mode 0600, so the fixture needs no
  # ownership fix-up afterwards. Signals nails writes itself are covered by
  # the activation-driven tests, which must not use these helpers.
  writeNotificationSignalFn = ''
    def write_notification_signal(
        path,
        title,
        body,
        urgency="normal",
        icon=None,
        created_at="2026-01-01T00:00:00Z",
        owner="testuser",
    ):
        import json
        import os
        import shlex

        payload = {
            "title": title,
            "body": body,
            "urgency": urgency,
            "created_at": created_at,
        }
        if icon is not None:
            payload["icon"] = icon

        group = machine.succeed("id -gn " + shlex.quote(owner)).strip()
        machine.succeed(
            "install -d -m 0700 -o " + shlex.quote(owner) + " -g " + shlex.quote(group)
            + " " + shlex.quote(os.path.dirname(path))
        )
        machine.succeed(
            "setpriv --reuid=" + shlex.quote(owner) + " --regid=" + shlex.quote(group)
            + " --init-groups /bin/sh -c "
            + shlex.quote("umask 077 && cat > " + shlex.quote(path))
            + " <<'EOF'\n"
            + json.dumps(payload, indent=2)
            + "\nEOF"
        )
  '';

  writeRawNotificationFileFn = ''
    def write_raw_notification_file(path, contents, owner="testuser"):
        import os
        import shlex

        group = machine.succeed("id -gn " + shlex.quote(owner)).strip()
        machine.succeed(
            "install -d -m 0700 -o " + shlex.quote(owner) + " -g " + shlex.quote(group)
            + " " + shlex.quote(os.path.dirname(path))
        )
        machine.succeed(
            "setpriv --reuid=" + shlex.quote(owner) + " --regid=" + shlex.quote(group)
            + " --init-groups /bin/sh -c "
            + shlex.quote("umask 077 && cat > " + shlex.quote(path))
            + " <<'EOF'\n"
            + contents
            + "\nEOF"
        )
  '';

  runCommandCaptureFn = ''
    def run_command_capture(command, prefix):
        import shlex

        stdout_path = prefix + ".stdout"
        stderr_path = prefix + ".stderr"
        rc_path = prefix + ".rc"

        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + " > "
                + shlex.quote(stdout_path)
                + " 2> "
                + shlex.quote(stderr_path)
                + "; printf \"%s\" \"$?\" > "
                + shlex.quote(rc_path)
            )
        )

        return {
            "rc": int(machine.succeed("cat " + shlex.quote(rc_path)).strip()),
            "stdout": machine.succeed("cat " + shlex.quote(stdout_path)),
            "stderr": machine.succeed("cat " + shlex.quote(stderr_path)),
        }
  '';

  readStubCallsFn = ''
    def read_stub_calls(log_path):
        import shlex

        raw = machine.succeed(
            "/bin/sh -lc "
            + shlex.quote(
                "if [ -f "
                + shlex.quote(log_path)
                + " ]; then cat "
                + shlex.quote(log_path)
                + "; fi"
            )
        )

        calls = []
        current = None
        for line in raw.splitlines():
            if line == "__CALL__":
                if current is not None:
                    calls.append(current)
                current = []
            elif current is not None:
                current.append(line)

        if current is not None:
            calls.append(current)

        return calls
  '';

  # notify-dispatch --json prints the standard envelope; return its `data`
  # after checking the envelope reports success for that command.
  dispatchResultFn = ''
    def dispatch_result(stdout):
        import json

        payload = json.loads(stdout.strip())
        assert payload.get("ok") is True, payload
        assert payload.get("command") == "notify-dispatch", payload
        return payload["data"]
  '';
}
