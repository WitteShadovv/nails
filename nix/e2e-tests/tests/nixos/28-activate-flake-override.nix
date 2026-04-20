# Test 28: Activate Flake Override
# Checklist: subtests, deterministic waits, hard assertions, meta.tags, shared helpers, forensic invariants preserved.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  nixpkgsPath = pkgs.path;
in {
  name = "activate-flake-override";
  meta.tags = [ "nixos" ];

  nodes.machine = { pkgs, ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages =
      [ self.packages.x86_64-linux.nails pkgs.python3 ];
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
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
        real_nixos_rebuild = machine.succeed("bash -lc 'command -v nixos-rebuild'").strip()
        machine.succeed(
            f"""mkdir -p /tmp/nails-wrapper/bin
    rm -f {log_path}
    cat > /tmp/nails-wrapper/bin/nixos-rebuild <<'EOF'
    #!/bin/sh
    printf '%s\\n' "$*" >> {log_path}
    exec {real_nixos_rebuild} "$@"
    EOF
    chmod 755 /tmp/nails-wrapper/bin/nixos-rebuild"""
        )
        return "PATH=/tmp/nails-wrapper/bin:$PATH"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    flake_ref = "/mnt/hidden-volume/nixos#nails-e2e"
    write_headless_config(headless_config)

    with subtest("prepare hidden flake override"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/hidden-volume/nixos")
        machine.succeed("""cat > /mnt/hidden-volume/nixos/flake.nix <<'EOF'
    {
      description = "NAILS flake override E2E";
      inputs.nixpkgs.url = "path:${nixpkgsPath}";
      outputs = { self, nixpkgs }: {
        nixosConfigurations.nails-e2e = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            /etc/nixos/configuration.nix
            ({ ... }: {
              documentation.nixos.enable = false;
              environment.etc."nails-flake-marker".text = "flake-override-active";
            })
          ];
        };
      };
    }
    EOF""")
        wrapper_env = install_nixos_rebuild_wrapper("/tmp/nixos-rebuild-flake.log")

    with subtest("explicit flake override dispatches to nixos-rebuild --flake"):
        machine.succeed(
            f"{wrapper_env} nails --config {headless_config} activate --no-kill-session -y --flake {flake_ref}"
        )
        rebuild_log = machine.succeed("cat /tmp/nixos-rebuild-flake.log")
        assert f"--flake {flake_ref}" in rebuild_log, \
            f"Expected explicit flake ref in nixos-rebuild invocation, got: {rebuild_log!r}"
        assert "-I nixos-config=/etc/nixos/configuration.nix" not in rebuild_log, \
            f"Did not expect legacy nixos-config path when using --flake, got: {rebuild_log!r}"

    with subtest("flake-selected system becomes active"):
        assert_status_state_local("Active", headless_config)
        assert_overlay_mounted_local("/etc")
        machine.succeed("grep -Fx 'flake-override-active' /etc/nails-flake-marker")
        machine.succeed("test -L /etc/nixos/nails/configuration.nix")

    with subtest("deactivate removes flake-selected runtime state"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-flake-override")
        assert_status_state_local("Inactive", headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /etc/nails-flake-marker")
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
  '';
}
