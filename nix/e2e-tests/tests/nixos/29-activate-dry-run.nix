# Test 29: Activate Dry Run

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  nixpkgsPath = pkgs.path;
in
{
  name = "activate-dry-run";
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
        payload = json.loads(machine.succeed(f"nails --config {config_path} status --json"))["data"]
        assert str(payload["state"]["kind"]) == "inactive", f"Expected inactive state, got: {payload}"

    def assert_no_overlays_local(paths):
        for path in paths:
            machine.fail(f"/bin/sh -lc 'mountpoint -q {path} && [ \"$(findmnt -n -o FSTYPE {path})\" = overlay ]'")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    flake_ref = "/mnt/data/nixos#dry-run-e2e"
    write_headless_config(headless_config)

    with subtest("prepare hidden flake and rebuild wrapper"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        machine.succeed("""cat > /mnt/data/nixos/flake.nix <<'EOF'
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
        machine.fail("test -e /mnt/data/state.json")

    with subtest("check reports readiness without mutating anything"):
        check_rc, check_stdout, check_stderr = run_command_capture(
            "nails-check",
            f"{wrapper_env} nails --config {headless_config} check --flake {flake_ref}",
        )
        assert "NAILS Readiness Check" in check_stdout, f"Unexpected check output: {check_stdout!r}"
        assert "Pre-flight checks:" in check_stdout, f"Expected the check list, got: {check_stdout!r}"
        assert "Overlay targets:" in check_stdout, f"Expected overlay targets, got: {check_stdout!r}"
        assert "NixOS profile:" in check_stdout, f"Expected a profile section, got: {check_stdout!r}"
        # The hidden layout was never staged, so the read-only check refuses
        # (exit 4) instead of creating it.
        assert check_rc == 4, f"Expected check to refuse (rc=4), got rc={check_rc}, stderr={check_stderr!r}"
        machine.fail("test -s /tmp/nixos-rebuild-dry-run.log")

    with subtest("activate --dry-run is a thin alias for check"):
        dry_rc, dry_stdout, _ = run_command_capture(
            "activate-dry-run",
            f"{wrapper_env} nails --config {headless_config} activate --dry-run --session keep --flake {flake_ref}",
        )
        assert dry_rc == check_rc, f"dry-run rc={dry_rc} must match check rc={check_rc}"
        assert dry_stdout == check_stdout, "dry-run and check must produce identical output"
        machine.fail("test -s /tmp/nixos-rebuild-dry-run.log")

    with subtest("state and filesystem remain untouched"):
        assert_inactive_status_local(headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /mnt/data/state.json")
        machine.fail("test -e /mnt/data/config/nixos/configuration.nix")
        machine.fail("test -e /mnt/data/etc/nixos/nails/configuration.nix")
        machine.fail("test -e /mnt/data/etc/nixos/hardware-configuration.nix")
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
  '';
}
