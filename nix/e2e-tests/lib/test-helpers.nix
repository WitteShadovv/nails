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
    import shlex

    def run_detached_command(unit_name, command):
        machine.succeed(
            "systemd-run --unit "
            + shlex.quote(unit_name)
            + " --no-block --service-type=exec /bin/sh -lc "
            + shlex.quote(command)
        )
  '';
}
