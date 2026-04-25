{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "service-restart-failure-nonfatal";
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

    def read_status_json_local(config_path):
        return json.loads(machine.succeed(f"nails --config {config_path} status --json"))

    def assert_overlay_mounted_local(path):
        machine.succeed(f"mountpoint -q {path}")
        assert machine.succeed(f"findmnt -n -o FSTYPE {path}").strip() == "overlay"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    with subtest("prepare hidden config and non-fatal rebuild wrapper"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("""cat > /mnt/hidden-volume/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      documentation.nixos.enable = false;
      environment.etc."nails-nonfatal-marker".text = "service-restart-warning";
    }
        EOF""")
        machine.succeed("""mkdir -p /tmp/nails-wrapper/bin
    cat > /tmp/nails-wrapper/bin/nixos-rebuild <<'EOF'
    #!/bin/sh
    printf '%s\n' "$*" >> /tmp/nixos-rebuild-nonfatal.log
    printf '%s\n' 'warning: error(s) occurred while switching to the new configuration' 1>&2
    printf '%s\n' 'The following units failed: home-manager-amnesia.service' 1>&2
    printf '%s\n' 'service-restart-warning' > /etc/nails-nonfatal-marker
    exit 4
    EOF
    chmod 755 /tmp/nails-wrapper/bin/nixos-rebuild""")

    with subtest("activation stays successful when only service restarts fail"):
        rc, stdout, stderr = run_command_capture(
            "service-restart-nonfatal",
            f"PATH=/tmp/nails-wrapper/bin:$PATH nails --config {headless_config} activate --no-kill-session -y",
        )
        assert rc == 0, f"Expected activation success, got rc={rc} stdout={stdout!r} stderr={stderr!r}"
        combined = stdout + stderr
        assert "Activation complete" in combined, combined
        assert "NixOS build+switch failed" not in combined, combined
        payload = read_status_json_local(headless_config)
        assert str(payload["state"]).lower() == "active", payload
        assert_overlay_mounted_local("/etc")
        assert_overlay_mounted_local("/home")
        machine.succeed("grep -Fx 'service-restart-warning' /etc/nails-nonfatal-marker")
        rebuild_log = machine.succeed("cat /tmp/nixos-rebuild-nonfatal.log")
        assert "test" in rebuild_log, rebuild_log
  '';
}
