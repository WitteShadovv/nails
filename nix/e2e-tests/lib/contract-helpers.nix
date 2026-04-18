{
  runCommandCaptureFn = ''
    def run_command_capture(name, command):
        import shlex

        prefix = f"/tmp/{name}"
        stdout_path = f"{prefix}.stdout"
        stderr_path = f"{prefix}.stderr"
        rc_path = f"{prefix}.rc"
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + f" > {stdout_path} 2> {stderr_path}; "
                + f"printf \"%s\" \"$?\" > {rc_path}"
            )
        )
        stdout = machine.succeed(f"cat {shlex.quote(stdout_path)} || true")
        stderr = machine.succeed(f"cat {shlex.quote(stderr_path)} || true")
        return {
            "rc": int(machine.succeed(f"cat {shlex.quote(rc_path)}")),
            "stdout": stdout,
            "stderr": stderr,
            "combined": stdout + stderr,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
        }
  '';

  runPtyCommandCaptureFn = ''
    def run_pty_command_capture(name, command):
        import shlex

        prefix = f"/tmp/{name}"
        typescript = f"{prefix}.typescript"
        stderr_path = f"{prefix}.script.stderr"
        rc_path = f"{prefix}.rc"
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                f"rm -f {typescript} {stderr_path}; "
                + "set +e; "
                + f"script -qefc {shlex.quote(command)} {shlex.quote(typescript)} >/dev/null 2>{stderr_path}; "
                + f"printf \"%s\" \"$?\" > {rc_path}"
            )
        )
        stdout = machine.succeed(f"cat {shlex.quote(typescript)} || true")
        stderr = machine.succeed(f"cat {shlex.quote(stderr_path)} || true")
        return {
            "rc": int(machine.succeed(f"cat {shlex.quote(rc_path)}")),
            "stdout": stdout,
            "stderr": stderr,
            "combined": stdout + stderr,
            "stdout_path": typescript,
            "stderr_path": stderr_path,
        }
  '';

  assertJsonSchemaValidFn = ''
    def assert_json_schema_valid(schema_path, instance_path, label):
        machine.succeed(
            "python3 - <<'PY'\n"
            + "import json\n"
            + "from pathlib import Path\n"
            + "import jsonschema\n"
            + f"schema = json.loads(Path({schema_path!r}).read_text())\n"
            + f"instance = json.loads(Path({instance_path!r}).read_text())\n"
            + "jsonschema.Draft7Validator.check_schema(schema)\n"
            + "jsonschema.validate(instance=instance, schema=schema)\n"
            + "PY"
        )
  '';

  assertNoAnsiFn = ''
    import re

    _ansi_escape_re = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

    def assert_no_ansi(text, label):
        assert _ansi_escape_re.search(text) is None, f"Expected no ANSI escapes in {label}, got: {text!r}"

    def assert_has_ansi(text, label):
        assert _ansi_escape_re.search(text) is not None, f"Expected ANSI escapes in {label}, got: {text!r}"
  '';

  assertAsciiOnlyFn = ''
    def assert_ascii_only(text, label):
        assert text.isascii(), f"Expected ASCII-only output for {label}, got: {text!r}"
  '';

  countNonEmptyLinesFn = ''
    def count_nonempty_lines(text):
        return sum(1 for line in text.splitlines() if line.strip())
  '';

  assertNoBlockedSubstringsFn = ''
    def assert_no_blocked_substrings(text, blocked, label):
        for needle in blocked:
            assert needle not in text, f"Found blocked substring {needle!r} in {label}: {text!r}"
  '';
}
