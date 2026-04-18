# Test 29: Activate Dry Run
# Checklist: subtests, deterministic waits, hard assertions, meta.tags, shared helpers, forensic invariants preserved.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  nixpkgsPath = pkgs.path;
in {
  name = "activate-dry-run";
  meta.tags = [ "nixos" ];

  nodes.machine = { pkgs, ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages =
      [ self.packages.x86_64-linux.nails pkgs.python3 ];
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}

    import json
    import shlex
    import uuid

    def run_command_capture(label, command):
        stem = f"/tmp/{label}-{uuid.uuid4().hex}"
        machine.succeed(
            "bash -lc "
            + shlex.quote(
                "set +e; "
                + command
                + f" > {stem}.stdout 2> {stem}.stderr; "
                + f"printf '%s' \"$?\" > {stem}.rc"
            )
        )
        return (
            int(machine.succeed(f"cat {stem}.rc")),
            machine.succeed(f"cat {stem}.stdout"),
            machine.succeed(f"cat {stem}.stderr"),
        )

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

    def assert_inactive_status_local(config_path):
        payload = json.loads(machine.succeed(f"nails --config {config_path} status --json"))
        assert str(payload["state"]).lower() == "inactive", f"Expected inactive state, got: {payload}"

    def assert_no_overlays_local(paths):
        for path in paths:
            machine.fail(f"/bin/sh -lc 'mountpoint -q {path} && [ \"$(findmnt -n -o FSTYPE {path})\" = overlay ]'")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    flake_ref = "/mnt/hidden-volume/nixos#dry-run-e2e"
    write_headless_config(headless_config)

    with subtest("prepare hidden flake and rebuild wrapper"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/hidden-volume/nixos")
        machine.succeed("""cat > /mnt/hidden-volume/nixos/flake.nix <<'EOF'
    {
      description = "NAILS dry-run flake E2E";
      inputs.nixpkgs.url = "path:${nixpkgsPath}";
      outputs = { self, nixpkgs }: {
        nixosConfigurations.dry-run-e2e = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [ /etc/nixos/configuration.nix ];
        };
      };
    }
    EOF""")
        wrapper_env = install_nixos_rebuild_wrapper("/tmp/nixos-rebuild-dry-run.log")
        machine.fail("test -e /mnt/hidden-volume/state.json")

    with subtest("dry-run prints plan without mutations"):
        rc, stdout, stderr = run_command_capture(
            "activate-dry-run",
            f"{wrapper_env} nails --config {headless_config} activate --dry-run --no-kill-session --flake {flake_ref}",
        )
        assert rc == 0, f"Expected dry-run success, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"
        assert "NAILS Dry-Run: Activation Preview" in stdout, f"Unexpected dry-run output: {stdout!r}"
        assert "Overlay Targets" in stdout, f"Expected overlay plan in stdout, got: {stdout!r}"
        assert f"NixOS flake: {flake_ref} — would build and switch profile" in stdout, \
            f"Expected explicit flake plan in stdout, got: {stdout!r}"
        machine.fail("test -s /tmp/nixos-rebuild-dry-run.log")

    with subtest("state and filesystem remain untouched"):
        assert_inactive_status_local(headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /mnt/hidden-volume/state.json")
        machine.fail("test -e /mnt/hidden-volume/config/nixos/configuration.nix")
        machine.fail("test -e /mnt/hidden-volume/etc/nixos/nails/configuration.nix")
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
  '';
}
