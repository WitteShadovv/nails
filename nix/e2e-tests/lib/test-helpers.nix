# Shared test helper functions for E2E tests
# Provides common Python functions as string snippets that can be interpolated into testScripts
{
  # Python function to write the standard headless config file.
  # Usage in testScript: ${testHelpers.writeHeadlessConfigFn}
  # Then call: write_headless_config("/tmp/nails-headless.yaml")
  writeHeadlessConfigFn = ''
    def write_headless_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: root
        lower: /root
        upper: /mnt/hidden-volume/root
        work: /mnt/hidden-volume/.work/root
        target: /root
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
      - name: tmp
        lower: /tmp
        upper: /mnt/hidden-volume/tmp
        work: /mnt/hidden-volume/.work/tmp
        target: /tmp
    EOF""" % path
        )
  '';

  # Launch a command from a transient systemd unit so the test harness shell
  # returns immediately before the unit tears down shell processes or reboots.
  runDetachedCommandFn = ''
    def run_detached_command(unit_name, command):
        import shlex

        machine.succeed(
            "systemd-run --unit "
            + shlex.quote(unit_name)
            + " --no-block --service-type=exec /bin/sh -lc "
            + shlex.quote(command)
        )
  '';

  readStatusJsonFn = ''
    def read_status_json(config_path=None):
        import json
        import shlex

        command = "nails"
        if config_path is not None:
            command += " --config " + shlex.quote(config_path)
        command += " status --json"

        machine.succeed(
            "bash -lc "
            + shlex.quote(
                command
                + " > /tmp/nails-status.stdout 2>/tmp/nails-status.stderr"
            )
        )
        return json.loads(machine.succeed("cat /tmp/nails-status.stdout"))
  '';

  runVerifyFn = ''
    def run_verify(args="", config_path=None):
        import json
        import shlex

        command = "nails"
        if config_path is not None:
            command += " --config " + shlex.quote(config_path)
        command += " verify --json"
        if args:
            command += f" {args}"

        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + " > /tmp/verify.stdout 2>/tmp/verify.stderr; "
                + "printf \"%s\" \"$?\" > /tmp/verify.rc"
            )
        )
        status = int(machine.succeed("cat /tmp/verify.rc"))
        output = machine.succeed("cat /tmp/verify.stdout")
        return status, json.loads(output)
  '';

  canonicalDeactivateFn = ''
    def canonical_deactivate(config_path, unit_name="nails-deactivate"):
        import shlex

        machine.succeed(
            "systemd-run --unit "
            + shlex.quote(unit_name)
            + " --no-block --service-type=exec /bin/sh -lc "
            + shlex.quote(f"nails --config {config_path} deactivate")
        )
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
  '';

  writeExtendedConfigFn = ''
    def write_extended_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: root
        lower: /root
        upper: /mnt/hidden-volume/root
        work: /mnt/hidden-volume/.work/root
        target: /root
      - name: var
        lower: /var
        upper: /mnt/hidden-volume/var
        work: /mnt/hidden-volume/.work/var
        target: /var
      - name: tmp
        lower: /tmp
        upper: /mnt/hidden-volume/tmp
        work: /mnt/hidden-volume/.work/tmp
        target: /tmp
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
      - name: opt
        lower: /opt
        upper: /mnt/hidden-volume/opt
        work: /mnt/hidden-volume/.work/opt
        target: /opt
    EOF""" % path
        )
  '';

  writeEphemeralConfigFn = ''
    def write_ephemeral_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    # Current harness equivalent of the plan's proposed overlay_mode: ephemeral.
    # The application currently models ephemeral overlays via extended_overlays.
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: root
        lower: /root
        upper: /mnt/hidden-volume/root
        work: /mnt/hidden-volume/.work/root
        target: /root
    extended_overlays:
      enabled: true
      directories:
        - path: /var
          tmpfs_upper_size: 256M
          tmpfs_work_size: 128M
        - path: /tmp
          tmpfs_upper_size: 256M
          tmpfs_work_size: 128M
        - path: /srv
          tmpfs_upper_size: 128M
          tmpfs_work_size: 64M
        - path: /opt
          tmpfs_upper_size: 128M
          tmpfs_work_size: 64M
    EOF""" % path
        )
  '';
}
