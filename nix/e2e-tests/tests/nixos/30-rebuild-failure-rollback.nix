# Test 30: Rebuild Failure Rollback
# Checklist: subtests, deterministic waits, hard assertions, meta.tags, shared helpers, forensic invariants preserved.

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

    def run_current_system_target():
        return machine.succeed("readlink -f /run/current-system").strip()

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

    def assert_inactive_state_file(path):
        payload = json.loads(machine.succeed("cat " + shlex.quote(path)))
        assert str(payload["state"]).lower() == "inactive", payload
        assert payload.get("overlay_status", {}) == {}, payload
        return payload

    def assert_inactive_status_local(config_path):
        payload = json.loads(machine.succeed(f"nails --config {config_path} status --json"))
        assert str(payload["state"]).lower() == "inactive", f"Expected inactive state, got: {payload}"

    def path_exists(path):
        rc, _stdout, _stderr = run_command_capture(
            "path-exists",
            f"test -e {shlex.quote(path)}",
        )
        return rc == 0

    def assert_no_overlays_local(paths):
        for path in paths:
            machine.fail(
                "/bin/sh -lc "
                + shlex.quote(
                    "while IFS=' ' read -r _ mountpoint fstype _; do "
                    + f"[ \"$mountpoint\" = {shlex.quote(path)} ] && [ \"$fstype\" = overlay ] && exit 0; "
                    + "done < /proc/self/mounts; exit 1"
                )
            )

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    with subtest("prepare broken hidden configuration"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("""cat > /mnt/hidden-volume/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      environment.etc."nails-broken-marker".text = ;
    }
    EOF""")
        baseline_run_current = run_current_system_target()
        wrapper_env = install_nixos_rebuild_wrapper("/run/nixos-rebuild-failure.log")

    with subtest("failed rebuild rolls activation back to inactive"):
        rc, stdout, stderr = run_command_capture(
            "rebuild-failure",
            f"{wrapper_env} nails --config {headless_config} activate --no-kill-session -y",
        )
        assert rc != 0, f"Expected activation failure, got rc=0 stdout={stdout!r} stderr={stderr!r}"
        combined_output = stdout + stderr
        assert "Activation started" in combined_output, \
            f"Expected activation attempt output before rollback, got: {combined_output!r}"
        assert path_exists("/run/nixos-rebuild-failure.log"), \
            f"Expected wrapper log proving nixos-rebuild execution, got output: {combined_output!r}"
        rebuild_log = machine.succeed("cat /run/nixos-rebuild-failure.log")
        assert rebuild_log.strip(), "Expected non-empty nixos-rebuild wrapper log"
        assert "test" in rebuild_log, \
            f"Expected wrapped nixos-rebuild test invocation before rollback, got: {rebuild_log!r}"

    with subtest("rollback cleans mounts, state, and decoy /etc"):
        assert_inactive_status_local(headless_config)
        assert_no_overlays_local(["/etc", "/home", "/root", "/srv", "/tmp"])
        machine.fail("test -e /etc/nixos/nails/configuration.nix")
        machine.fail("grep -F './nails/configuration.nix' /etc/nixos/hardware-configuration.nix")
        restored_run_current = run_current_system_target()
        assert restored_run_current == baseline_run_current, \
            f"Expected rollback to restore /run/current-system {baseline_run_current!r}, got {restored_run_current!r}"
        state_payload = assert_inactive_state_file("/mnt/hidden-volume/state.json")
        assert state_payload.get("failed_overlays", []) == [], \
            f"Expected rollback cleanup to leave no failed overlay residue, got: {state_payload}"
  '';
}
