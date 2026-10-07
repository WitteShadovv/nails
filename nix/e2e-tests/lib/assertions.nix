{
  assertStatusStateFn = ''
    def _normalize_status_state(value):
        import re

        # The envelope renders state as a tagged object {"kind": ...}; older
        # callers may still pass a bare string.
        if isinstance(value, dict):
            value = value.get("kind", "")
        if isinstance(value, str):
            match = re.match(r"([A-Za-z]+)", value)
            return match.group(1).lower() if match else value.lower()
        return str(value).lower()

    def assert_status_state(expected, payload=None, config_path=None):
        status = payload if payload is not None else read_status_json(config_path=config_path)
        actual = _normalize_status_state(status["state"])
        assert actual == expected.lower(), f"Expected state {expected!r}, got: {status}"
        return status
  '';

  assertOverlayMountedFn = ''
    def assert_overlay_mounted(path):
        import shlex

        quoted_path = shlex.quote(path)
        machine.succeed(f"mountpoint -q {quoted_path}")
        fs_type = machine.succeed(f"findmnt -n -o FSTYPE {quoted_path}").strip()
        assert fs_type == "overlay", f"Expected overlay mount at {path}, got {fs_type!r}"
  '';

  assertNoOverlaysFn = ''
    def assert_no_overlays(paths):
        import shlex

        for path in paths:
            quoted_path = shlex.quote(path)
            machine.fail(
                "/bin/sh -lc "
                + shlex.quote(
                    f"mountpoint -q {quoted_path} && [ \"$(findmnt -n -o FSTYPE {quoted_path})\" = overlay ]"
                )
            )
  '';
}
