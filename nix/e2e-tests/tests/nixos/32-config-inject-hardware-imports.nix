# Test 32: Config Inject Hardware Imports
# Checklist: subtests, deterministic waits, hard assertions, meta.tags, shared helpers, forensic invariants preserved.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "config-inject-hardware-imports";
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

    def read_status_json_local(config_path):
        return json.loads(machine.succeed(f"nails --config {config_path} status --json"))

    def assert_status_state_local(expected, config_path):
        payload = read_status_json_local(config_path)
        actual = str(payload["state"]).lower()
        assert actual.startswith(expected.lower()), f"Expected {expected!r}, got: {payload}"

    def assert_overlay_mounted_local(path):
        machine.succeed(f"mountpoint -q {path}")
        assert machine.succeed(f"findmnt -n -o FSTYPE {path}").strip() == "overlay"

    def assert_no_overlays_local(paths):
        for path in paths:
            machine.fail(f"/bin/sh -lc 'mountpoint -q {path} && [ \"$(findmnt -n -o FSTYPE {path})\" = overlay ]'")

    def install_nixos_rebuild_wrapper(log_path):
        machine.succeed(
            f"""mkdir -p /var/lib/nails-tests/nails-wrapper/bin
    rm -f {log_path}
    cat > /var/lib/nails-tests/nails-wrapper/bin/nixos-rebuild <<'EOF'
    #!/bin/sh
    printf '%s\\n' "$*" >> {log_path}
    exit 0
    EOF
    chmod 755 /var/lib/nails-tests/nails-wrapper/bin/nixos-rebuild"""
        )
        return "PATH=/var/lib/nails-tests/nails-wrapper/bin:$PATH"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/var/lib/nails-tests/nails-headless.yaml"
    write_headless_config(headless_config)
    wrapper_env = install_nixos_rebuild_wrapper("/var/lib/nails-tests/nixos-rebuild-hardware-imports.log")

    with subtest("first full activation auto-creates hidden hardware config with import"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.fail("test -e /mnt/hidden-volume/etc/nixos/hardware-configuration.nix")
        machine.succeed("""cat > /mnt/hidden-volume/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      documentation.nixos.enable = false;
    }
    EOF""")
        machine.succeed(f"{wrapper_env} nails --config {headless_config} activate --no-kill-session -y")
        assert_status_state_local("Active", headless_config)
        assert_overlay_mounted_local("/etc")
        first_rebuild_log = machine.succeed("cat /var/lib/nails-tests/nixos-rebuild-hardware-imports.log")
        assert "test" in first_rebuild_log, f"Expected nixos-rebuild test invocation, got: {first_rebuild_log!r}"
        assert "-I nixos-config=/etc/nixos/configuration.nix" in first_rebuild_log, \
            f"Expected legacy nixos-rebuild invocation, got: {first_rebuild_log!r}"
        first_hidden_hardware = machine.succeed("cat /mnt/hidden-volume/etc/nixos/hardware-configuration.nix")
        assert first_hidden_hardware.count("./nails/configuration.nix") == 1, \
            f"Expected exactly one injected import after first activation, got: {first_hidden_hardware!r}"
        machine.succeed("test -L /mnt/hidden-volume/etc/nixos/nails/configuration.nix")
        machine.succeed("test -L /etc/nixos/nails/configuration.nix")

    with subtest("second full activation is idempotent for hidden hardware import"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-hardware-imports-phase-1")
        assert_status_state_local("Inactive", headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        before_second_activation = machine.succeed("cat /mnt/hidden-volume/etc/nixos/hardware-configuration.nix")
        assert before_second_activation.count("./nails/configuration.nix") == 1, \
            f"Expected one injected import before second activation, got: {before_second_activation!r}"
        machine.succeed(f"{wrapper_env} nails --config {headless_config} activate --no-kill-session -y")
        assert_status_state_local("Active", headless_config)
        rebuild_log = machine.succeed("cat /var/lib/nails-tests/nixos-rebuild-hardware-imports.log")
        assert rebuild_log.count("test -I nixos-config=/etc/nixos/configuration.nix") == 2, \
            f"Expected two full activation rebuild invocations, got: {rebuild_log!r}"
        after_second_activation = machine.succeed("cat /mnt/hidden-volume/etc/nixos/hardware-configuration.nix")
        assert after_second_activation.count("./nails/configuration.nix") == 1, \
            f"Expected exactly one injected import after second activation, got: {after_second_activation!r}"
        assert after_second_activation == before_second_activation, \
            "Hidden hardware-configuration.nix changed on second activation despite idempotent import staging"

    with subtest("final deactivate restores decoy state cleanly"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-hardware-imports-phase-2")
        assert_status_state_local("Inactive", headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
  '';
}
