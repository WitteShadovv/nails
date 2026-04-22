# Test 31: Verify Base Config Clean
# Checklist: subtests, deterministic waits, hard assertions, meta.tags, shared helpers, forensic invariants preserved.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "verify-base-config-clean";
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
        payload = json.loads(machine.succeed(f"nails --config {config_path} status --json"))
        assert str(payload["state"]).lower() == "inactive", f"Expected inactive state, got: {payload}"

    def assert_no_overlays_local(paths):
        for path in paths:
            machine.fail(f"/bin/sh -lc 'mountpoint -q {path} && [ \"$(findmnt -n -o FSTYPE {path})\" = overlay ]'")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    with subtest("prepare hidden volume and dirty decoy nixos tree"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /tmp/dirty-etc-nixos")
        machine.succeed("cp -L /etc/nixos/configuration.nix /tmp/dirty-etc-nixos/configuration.nix")
        machine.succeed("""cat > /tmp/dirty-etc-nixos/hardware-configuration.nix <<'EOF'
    { ... }: {
      imports = [
        ./nails/configuration.nix
      ];
    }
    EOF""")
        machine.succeed("mount --bind /tmp/dirty-etc-nixos /etc/nixos")
        wrapper_env = install_nixos_rebuild_wrapper("/tmp/nixos-rebuild-clean-check.log")

    with subtest("activation refuses dirty base config before overlay mount"):
        rc, stdout, stderr = run_command_capture(
            "verify-base-config-clean",
            f"{wrapper_env} nails --config {headless_config} activate --no-kill-session -y",
        )
        assert rc != 0, f"Expected activation refusal, got rc=0 stdout={stdout!r} stderr={stderr!r}"
        combined_output = stdout + stderr
        assert "not forensically clean" in combined_output, \
            f"Expected forensic cleanliness diagnostic, got: {combined_output!r}"
        machine.fail("test -s /tmp/nixos-rebuild-clean-check.log")

    with subtest("refusal leaves system inactive and unmounted"):
        assert_inactive_status_local(headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
  '';
}
