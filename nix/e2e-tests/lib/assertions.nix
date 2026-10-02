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

  # Assert `path` (not following a final symlink) is owned by `owner` given as
  # "user:group" and has octal permission bits `mode` (e.g. "644").
  # Ownership is compared by name after stat resolves the numeric ids, so a
  # file left to root, or chowned to a per-user group the account does not
  # have (NixOS isNormalUser accounts have the primary group `users`), fails.
  assertOwnedByFn = ''
    def assert_owned_by(path, owner, mode):
        import shlex

        actual = machine.succeed("stat -c '%U:%G %a' " + shlex.quote(path)).strip()
        expected = f"{owner} {mode}"
        assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"
  '';

  assertHiddenVolumeHasFn = ''
    def assert_hidden_volume_has(path):
        import os
        import shlex

        relative_path = path[1:] if path.startswith("/") else path
        full_path = os.path.join("/mnt/data", relative_path)
        machine.succeed(f"test -e {shlex.quote(full_path)}")
        return full_path
  '';

  assertVerifyCleanFn = ''
    def assert_verify_clean(config_path=None, deep=False):
        verify_args = "--deep" if deep else ""
        status, payload = run_verify(args=verify_args, config_path=config_path)
        findings = payload.get("findings", [])
        assert findings == [], f"Expected clean verify result, got: {payload}"
        return status, payload
  '';
}
