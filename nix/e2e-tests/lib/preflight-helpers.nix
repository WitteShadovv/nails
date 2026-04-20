{
  writeTextFileFn = ''
    import shlex

    def write_text_file(path, content):
        delimiter = "NAILS_EOF"
        while delimiter in content:
            delimiter = f"{delimiter}_X"

        quoted_path = shlex.quote(path)
        quoted_parent = shlex.quote(path.rsplit("/", 1)[0] if "/" in path else ".")
        machine.succeed(
            "mkdir -p "
            + quoted_parent
            + " && cat > "
            + quoted_path
            + " <<'"
            + delimiter
            + "'\n"
            + content
            + delimiter
        )
  '';

  runCommandCaptureFn = ''
    import uuid

    def run_command_capture(label, command):
        stem = f"/tmp/{label}-{uuid.uuid4().hex}"
        machine.succeed(
            "bash -lc "
            + __import__("shlex").quote(
                "set +e; "
                + command
                + f" > {stem}.stdout 2> {stem}.stderr; "
                + f"printf '%s' \"$?\" > {stem}.rc"
            )
        )
        return {
            "rc": int(machine.succeed(f"cat {stem}.rc")),
            "stdout": machine.succeed(f"cat {stem}.stdout"),
            "stderr": machine.succeed(f"cat {stem}.stderr"),
        }
  '';

  commandAssertionsFn = ''
    def assert_command_failed(result):
        assert result["rc"] != 0, f"Expected command failure, got: {result}"

    def assert_command_succeeded(result):
        assert result["rc"] == 0, f"Expected command success, got: {result}"

    def assert_result_contains(result, needles, stream="stderr"):
        haystack = result[stream]
        for needle in needles:
            assert needle in haystack, (
                f"Expected {needle!r} in {stream}, got: {haystack!r}"
            )

    def assert_result_not_contains(result, needles, stream="stderr"):
        haystack = result[stream]
        for needle in needles:
            assert needle not in haystack, (
                f"Did not expect {needle!r} in {stream}, got: {haystack!r}"
            )

    def assert_text_contains(text, needles):
        for needle in needles:
            assert needle in text, f"Expected {needle!r} in: {text!r}"

    def assert_contains_in_order(text, needles):
        cursor = -1
        for needle in needles:
            position = text.find(needle, cursor + 1)
            assert position != -1, f"Expected {needle!r} in order within: {text!r}"
            cursor = position
  '';
}
