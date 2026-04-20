{
  runCommandCaptureFn = ''
    def run_command_capture(label, command):
        import shlex

        prefix = "/tmp/" + label
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

  activateForUserFn = ''
    def activate_for_user(
        config_path,
        shell_path,
        extra_args="--overlay-only --no-kill-session -y",
        user="testuser",
        home="/home/testuser",
    ):
        import shlex

        command = (
            "env HOME="
            + shlex.quote(home)
            + " USER="
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
        home="/home/testuser",
        unit_name="nails-deactivate-user",
    ):
        import shlex

        command = (
            "env HOME="
            + shlex.quote(home)
            + " USER="
            + shlex.quote(user)
            + " SHELL="
            + shlex.quote(shell_path)
            + " nails --config "
            + shlex.quote(config_path)
            + " deactivate"
        )
        run_detached_command(unit_name, command)
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
  '';

  writeNixOverlayConfigFn = ''
    def write_nix_overlay_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: nix
        lower: /nix
        upper: /mnt/hidden-volume/nix
        work: /mnt/hidden-volume/.work/nix
        target: /nix
    EOF""" % path
        )
  '';
}
