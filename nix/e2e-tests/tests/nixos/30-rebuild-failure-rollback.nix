# Test 30: A failed hidden switch is reported truthfully, and `nails reapply`
# applies the configuration once it is fixed.
#
# With `nixos_switch_required = false` a broken hidden configuration must not
# roll the overlays back: activation keeps the overlays and the session, exits
# with the dedicated success-with-warnings code (9), and reports
# `success_with_warnings` with a warnings array under `--json`. After the hidden
# configuration is fixed, `nails reapply` re-runs the build + switch in place
# (no reboot) and applies the hidden marker.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "rebuild-failure-rollback";
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

    def last_json_line(text):
        lines = [line for line in text.splitlines() if line.strip()]
        assert lines, f"expected at least one output line, got: {text!r}"
        return json.loads(lines[-1])

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

    def write_broken_hidden_config():
        machine.succeed("""cat > /mnt/data/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      environment.etc."nails-hidden-marker".text = ;
    }
    EOF""")

    def write_fixed_hidden_config():
        machine.succeed("""cat > /mnt/data/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      environment.etc."nails-hidden-marker".text = "present";
    }
    EOF""")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    # Keep the overlays and session on a failed switch instead of rolling back,
    # so the warning outcome is observable.
    machine.succeed(
        f"printf '\\nnixos_switch_required = false\\n' >> {shlex.quote(headless_config)}"
    )

    with subtest("prepare a broken hidden configuration"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_broken_hidden_config()
        wrapper_env = install_nixos_rebuild_wrapper("/run/nixos-rebuild-failure.log")

    with subtest("a failed switch exits 9 and reports success_with_warnings"):
        rc, stdout, stderr = run_command_capture(
            "rebuild-failure",
            f"{wrapper_env} nails --config {headless_config} activate --session keep -y --json",
        )
        assert rc == 9, f"expected success-with-warnings exit code 9, got rc={rc} stderr={stderr!r}"
        result = last_json_line(stdout)
        assert result["status"] == "success_with_warnings", result
        assert result["ok"] is True, result
        warnings = result.get("warnings", [])
        assert warnings, f"expected a non-empty warnings array, got: {result}"
        assert any("not applied" in w for w in warnings), warnings

    with subtest("the failed switch leaves overlays mounted and state active"):
        payload = json.loads(
            machine.succeed(f"nails --config {headless_config} status --json")
        )["data"]
        assert str(payload["state"]["kind"]).startswith("active"), payload
        assert payload.get("hidden_config_warning"), \
            f"status must report the hidden configuration as not applied, got: {payload}"
        machine.succeed("mountpoint -q /etc")
        machine.succeed("mountpoint -q /home")

    with subtest("reapply applies the hidden marker once the config is fixed"):
        write_fixed_hidden_config()
        rc, stdout, stderr = run_command_capture(
            "reapply",
            f"{wrapper_env} nails --config {headless_config} reapply --json",
        )
        assert rc == 0, f"expected reapply to succeed, got rc={rc} stdout={stdout!r} stderr={stderr!r}"
        result = last_json_line(stdout)
        assert result["status"] == "success", result
        machine.succeed("test -e /etc/nails-hidden-marker")
        machine.succeed("grep -q present /etc/nails-hidden-marker")

    with subtest("status no longer reports the hidden configuration as unapplied"):
        payload = json.loads(
            machine.succeed(f"nails --config {headless_config} status --json")
        )["data"]
        assert not payload.get("hidden_config_warning"), \
            f"a clean reapply must clear the status warning, got: {payload}"
  '';
}
