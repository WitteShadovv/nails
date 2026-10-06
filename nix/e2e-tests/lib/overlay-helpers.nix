# Each config keeps the subset under test and also overlays the base-OS trees
# (see base-os-overlays.nix), which the writable-trees pre-flight check
# requires before it lets the session activate. The base-OS stanzas come first,
# so the subset under test is mounted last and unmounted first.
let
  baseOs = import ./base-os-overlays.nix;
in
{
  writeBootOnlyConfigFn = ''
    def write_boot_only_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    ${baseOs.toml}
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

    ${baseOs.toml}
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

    ${baseOs.toml}
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

  # The per-activation runtime scaffolding root has a random name under /run, so
  # tests read it from the state file instead of hard-coding a path. Capture it
  # while the hidden volume is still mounted (before deactivate/emergency).
  nailsRuntimeRootFn = ''
    def nails_runtime_root(path="/mnt/data/state.json"):
        import json
        import shlex

        data = json.loads(machine.succeed("cat " + shlex.quote(path)))
        root = data.get("runtime_root")
        assert root, "state.json recorded no runtime_root: %r" % (data,)
        return root
  '';
}
