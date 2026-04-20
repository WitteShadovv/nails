{
  writeNotificationConfigFn = ''
    def write_notification_config(path, hidden_volume_root="/mnt/hidden-volume"):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_path: "%s"
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
            )
        )
  '';

  writeNotificationSignalFn = ''
    def write_notification_signal(path, title, body, urgency="normal", icon=None, created_at="2026-01-01T00:00:00Z"):
        import json
        import shlex

        payload = {
            "title": title,
            "body": body,
            "urgency": urgency,
            "created_at": created_at,
        }
        if icon is not None:
            payload["icon"] = icon

        machine.succeed("mkdir -p /mnt/hidden-volume/notifications")
        machine.succeed("chmod 700 /mnt/hidden-volume/notifications")
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "cat > "
                + shlex.quote(path)
                + " <<'EOF'\n"
                + json.dumps(payload, indent=2)
                + "\nEOF\n"
                + "chmod 600 "
                + shlex.quote(path)
            )
        )
  '';

  writeRawNotificationFileFn = ''
    def write_raw_notification_file(path, contents):
        import shlex

        machine.succeed("mkdir -p /mnt/hidden-volume/notifications")
        machine.succeed("chmod 700 /mnt/hidden-volume/notifications")
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "cat > "
                + shlex.quote(path)
                + " <<'EOF'\n"
                + contents
                + "\nEOF\n"
                + "chmod 600 "
                + shlex.quote(path)
            )
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
}
