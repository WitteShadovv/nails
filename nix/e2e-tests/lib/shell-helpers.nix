let
  baseOs = import ./base-os-overlays.nix;
in
{
  runCommandCaptureFn = ''
    def run_command_capture(label, command):
        import shlex

        prefix = "/run/" + label
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + " > "
                + shlex.quote(prefix + ".stdout")
                + " 2> "
                + shlex.quote(prefix + ".stderr")
                + "; printf \"%s\" \"$?\" > "
                + shlex.quote(prefix + ".rc")
            )
        )
        return {
            "rc": int(machine.succeed("cat " + shlex.quote(prefix + ".rc")).strip()),
            "stdout": machine.succeed("cat " + shlex.quote(prefix + ".stdout")),
            "stderr": machine.succeed("cat " + shlex.quote(prefix + ".stderr")),
        }
  '';

  # NAILS runs as root and resolves the operator it acts for from the
  # privilege-escalation environment (SUDO_UID/SUDO_USER), never from HOME/USER.
  # These helpers therefore inject the escalation identity for `user` instead of
  # faking a login environment: HOME under a real `sudo` is /root, so the old
  # HOME/USER injection described a context the real invocation never produces.
  # The genuine end-to-end `sudo nails` path (no injected variables at all) is
  # covered by tests/shell/45-shell-history-real-sudo.nix.
  activateForUserFn = ''
    def activate_for_user(
        config_path,
        shell_path,
        extra_args="--overlay-only --session keep -y",
        user="testuser",
    ):
        import shlex

        command = (
            "env SUDO_UID=$(id -u "
            + shlex.quote(user)
            + ") SUDO_USER="
            + shlex.quote(user)
            + " SHELL="
            + shlex.quote(shell_path)
            + " nails --config "
            + shlex.quote(config_path)
            + " activate "
            + extra_args
        )
        return machine.succeed(command)
  '';

  canonicalDeactivateForUserFn = ''
    def canonical_deactivate_for_user(
        config_path,
        shell_path,
        user="testuser",
        unit_name="nails-deactivate-user",
    ):
        import shlex

        command = (
            "env SUDO_UID=$(id -u "
            + shlex.quote(user)
            + ") SUDO_USER="
            + shlex.quote(user)
            + " SHELL="
            + shlex.quote(shell_path)
            + " nails --config "
            + shlex.quote(config_path)
            + " deactivate -y"
        )
        run_detached_command(unit_name, command)
        # Bounded: the driver's wait_for_shutdown() has no deadline, so a
        # power-off that never comes would hold the test until globalTimeout.
        _nails_qemu = machine.process
        if _nails_qemu is not None:
            try:
                _nails_qemu.wait(timeout=300)
            except __import__("subprocess").TimeoutExpired:
                raise AssertionError(
                    f"canonical_deactivate_for_user ({unit_name}): VM did not power off within 300s\n"
                    + "--- serial console tail ---\n"
                    + "\n".join(machine.get_console_log().splitlines()[-100:])
                ) from None
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
  '';

  writeNixOverlayConfigFn = ''
    def write_nix_overlay_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    # The base-OS trees are overlaid as well, which the writable-trees
    # pre-flight check requires before activation.
    ${baseOs.toml}
    [[overlays]]
    name = "nix"
    lower = "/nix"
    upper = "/mnt/data/nix"
    work = "/mnt/data/.work/nix"
    target = "/nix"
    EOF""" % path
        )
  '';
}
