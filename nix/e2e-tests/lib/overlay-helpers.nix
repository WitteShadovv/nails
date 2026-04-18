{
  writeBootOnlyConfigFn = ''
    def write_boot_only_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: boot
        lower: /boot
        upper: /mnt/hidden-volume/boot
        work: /mnt/hidden-volume/.work/boot
        target: /boot
    EOF""" % path
        )
  '';

  writeOrderedOverlayConfigFn = ''
    def write_ordered_overlay_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
    EOF""" % path
        )
  '';

  writeSrvOnlyConfigFn = ''
    def write_srv_only_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
    EOF""" % path
        )
  '';

  readHiddenStateJsonFn = ''
    def read_hidden_state_json(path="/mnt/hidden-volume/state.json"):
        import json
        import shlex

        return json.loads(machine.succeed("cat " + shlex.quote(path)))
  '';
}
