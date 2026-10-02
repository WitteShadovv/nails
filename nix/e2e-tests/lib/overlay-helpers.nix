{
  writeBootOnlyConfigFn = ''
    def write_boot_only_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    [[overlays]]
    name = "boot"
    lower = "/boot"
    upper = "/mnt/data/boot"
    work = "/mnt/data/.work/boot"
    target = "/boot"
    EOF""" % path
        )
  '';

  writeOrderedOverlayConfigFn = ''
    def write_ordered_overlay_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"

    [[overlays]]
    name = "etc"
    lower = "/etc"
    upper = "/mnt/data/etc"
    work = "/mnt/data/.work/etc"
    target = "/etc"

    [[overlays]]
    name = "srv"
    lower = "/srv"
    upper = "/mnt/data/srv"
    work = "/mnt/data/.work/srv"
    target = "/srv"
    EOF""" % path
        )
  '';

  writeSrvOnlyConfigFn = ''
    def write_srv_only_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    [[overlays]]
    name = "srv"
    lower = "/srv"
    upper = "/mnt/data/srv"
    work = "/mnt/data/.work/srv"
    target = "/srv"
    EOF""" % path
        )
  '';

  readHiddenStateJsonFn = ''
    def read_hidden_state_json(path="/mnt/data/state.json"):
        import json
        import shlex

        return json.loads(machine.succeed("cat " + shlex.quote(path)))
  '';
}
