# Test 27: Activate Full Rebuild
# Checklist: subtests, deterministic waits, hard assertions, meta.tags, shared helpers, forensic invariants preserved.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "activate-full-rebuild";
  meta.tags = [ "nixos" ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
      nix.settings.experimental-features = [
        "nix-command"
        "flakes"
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    import json
    import re

    def current_system_generation():
        target = machine.succeed(
            "bash -lc 'if [ -L /nix/var/nix/profiles/system ]; then readlink /nix/var/nix/profiles/system; fi'"
        ).strip()
        if not target:
            return None, None
        match = re.search(r"system-(\d+)-link$", target)
        assert match, f"Could not parse system generation from {target!r}"
        return match.group(1), target

    def install_nixos_rebuild_wrapper(log_path, marker_path):
        machine.succeed(
            f"""mkdir -p /tmp/nails-wrapper/bin
    rm -f {log_path}
    cat > /tmp/nails-wrapper/bin/nixos-rebuild <<'EOF'
    #!/bin/sh
    printf '%s\\n' "$*" >> {log_path}
    if [ "$1" = test ]; then
      mkdir -p "$(dirname {marker_path})"
      printf '%s\\n' 'legacy-rebuild-active' > {marker_path}
    fi
    exit 0
    EOF
    chmod 755 /tmp/nails-wrapper/bin/nixos-rebuild"""
        )
        return "PATH=/tmp/nails-wrapper/bin:$PATH"

    def read_status_json_local(config_path):
        return json.loads(machine.succeed(f"nails --config {config_path} status --json"))

    def assert_status_state_local(expected, config_path):
        payload = read_status_json_local(config_path)
        actual = str(payload["state"]).lower()
        assert actual.startswith(expected.lower()), f"Expected {expected!r}, got: {payload}"
        return payload

    def assert_overlay_mounted_local(path):
        machine.succeed(f"mountpoint -q {path}")
        assert machine.succeed(f"findmnt -n -o FSTYPE {path}").strip() == "overlay"

    def assert_no_overlays_local(paths):
        for path in paths:
            machine.fail(f"/bin/sh -lc 'mountpoint -q {path} && [ \"$(findmnt -n -o FSTYPE {path})\" = overlay ]'")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    with subtest("prepare hidden module and capture decoy baseline"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("""cat > /mnt/hidden-volume/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      documentation.nixos.enable = false;
      environment.etc."nails-hidden-marker".text = "legacy-rebuild-active";
    }
        EOF""")
        assert_status_state_local("Inactive", headless_config)
        baseline_generation, baseline_generation_target = current_system_generation()
        wrapper_env = install_nixos_rebuild_wrapper(
            "/tmp/nixos-rebuild-full.log",
            "/etc/nails-hidden-marker",
        )

    with subtest("activate performs full nixos rebuild path"):
        machine.succeed(
            f"{wrapper_env} nails --config {headless_config} activate --no-kill-session -y"
        )
        rebuild_log = machine.succeed("cat /tmp/nixos-rebuild-full.log")
        assert "test" in rebuild_log, f"Expected nixos-rebuild test invocation, got: {rebuild_log!r}"
        assert "-I nixos-config=/etc/nixos/configuration.nix" in rebuild_log, \
            f"Expected legacy nixos-rebuild invocation, got: {rebuild_log!r}"

    with subtest("active system exposes rebuilt runtime state"):
        active_status = assert_status_state_local("Active", headless_config)
        active_generation = active_status.get("nixos_generation")
        assert_overlay_mounted_local("/etc")
        assert_overlay_mounted_local("/home")
        machine.succeed("test -L /etc/nixos/nails/configuration.nix")
        symlink_target = machine.succeed("readlink -f /etc/nixos/nails/configuration.nix").strip()
        assert symlink_target == "/mnt/hidden-volume/config/nixos/configuration.nix", \
            f"Unexpected hidden config symlink target: {symlink_target!r}"
        machine.succeed("grep -Fx 'legacy-rebuild-active' /etc/nails-hidden-marker")
        active_generation_now, active_generation_target = current_system_generation()
        if active_generation is not None:
            machine.succeed(f"test -e /nix/var/nix/profiles/system-{active_generation}-link")
        if baseline_generation is not None:
            assert active_generation_now == baseline_generation, \
                f"Expected simulated rebuild to preserve decoy generation {baseline_generation!r}, got {active_generation_now!r}"
            assert active_generation_target == baseline_generation_target, \
                f"Expected simulated rebuild to preserve decoy generation target {baseline_generation_target!r}, got {active_generation_target!r}"

    with subtest("deactivate restores decoy runtime closure"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-full-rebuild")
        assert_status_state_local("Inactive", headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
        machine.fail("test -e /etc/nails-hidden-marker")
        restored_generation, restored_generation_target = current_system_generation()
        assert restored_generation == baseline_generation, \
            f"Expected decoy generation {baseline_generation!r}, got {restored_generation!r}"
        assert restored_generation_target == baseline_generation_target, \
            f"Expected decoy generation target {baseline_generation_target!r}, got {restored_generation_target!r}"
  '';
}
