# Test 53: State Guard Rollback

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  stateHelpers = import ./../../lib/state-helpers.nix;
in
{
  name = "state-guard-rollback";
  meta.tags = [ "state" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  # A graphical node is needed for the post-mount failure case: the overlays
  # mount, then the after-overlay session restart fails because the display
  # manager has been masked. That is the failure the rollback must handle, and
  # it only exists where there is a graphical session to restart.
  nodes.graphical =
    { ... }:
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    import json

    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${stateHelpers.captureCommandFns}

    def write_partial_failure_config(path):
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"

    [[overlays]]
    name = "doomed"
    lower = "/etc"
    upper = "/mnt/data/doomed"
    work = "/mnt/data/.work/doomed"
    target = "/state-rollback-missing-target"
    EOF"""
            % path
        )

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/state-guard-rollback.toml"
    state_path = "/mnt/data/state.json"

    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_partial_failure_config(config_path)
    machine.succeed("mkdir -p /mnt/data/doomed /mnt/data/.work/doomed")

    with subtest("prepare deterministic mount failure after state transition"):
        machine.fail("test -e /state-rollback-missing-target")
        assert_status_state("Inactive", config_path=config_path)

    with subtest("failed activation rolls state back to inactive"):
        rc, stdout, stderr = capture_command(
            "state-guard-rollback-activate",
            f"nails --config {config_path} activate --overlay-only --session keep -y",
        )
        assert rc == 1, f"Expected activation failure, got rc={rc}, stdout={stdout!r}, stderr={stderr!r}"

        payload = read_status_json(config_path=config_path)
        assert_status_state("Inactive", payload=payload)

        combined = stdout + stderr
        assert combined.strip(), "Expected non-empty activation diagnostics on rollback failure"

    with subtest("rollback removes all partial mounts and stale overlay tracking"):
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        state_doc = json.loads(machine.succeed(f"cat {state_path}"))
        assert state_doc["state"] == "Inactive", f"Expected persisted rollback state, got: {state_doc}"
        assert state_doc["overlay_status"] == {}, f"Expected empty overlay tracking after rollback, got: {state_doc}"

    # Post-mount failure: the overlays mount, then the after-overlay session
    # restart fails because the display manager is masked. The rollback must
    # unmount every overlay and persist the decoy (Inactive) state, and must do
    # so before the session is restarted onto the decoy.
    graphical_config = "/tmp/state-guard-rollback-graphical.toml"

    def write_post_mount_config(path):
        graphical.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

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
    EOF"""
            % path
        )

    graphical.start()
    graphical.wait_for_unit("display-manager.service")
    graphical.wait_until_succeeds("systemctl is-active user@1000.service")

    with subtest("prepare hidden volume and a masked display manager"):
        graphical.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_post_mount_config(graphical_config)
        graphical.fail("mountpoint -q /home")
        # Mask the display manager so the after-overlay restart cannot succeed.
        graphical.succeed("systemctl mask display-manager.service")

    with subtest("post-mount failure unmounts overlays and restores the decoy"):
        # Killing the graphical session makes the CLI detach into a transient
        # system-slice unit, so this returns immediately; the activation then
        # fails at the session restart and rolls back on its own.
        graphical.succeed(
            "env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + f"nails --config {graphical_config} activate --session kill -y"
        )

        # The rollback persists Inactive once every overlay is unmounted.
        graphical.wait_until_succeeds(
            "grep -q '\"state\": \"Inactive\"' /mnt/data/state.json"
        )

        for path in ["/home", "/etc"]:
            graphical.fail(
                "/bin/sh -lc "
                + __import__("shlex").quote(
                    f"mountpoint -q {path} && [ \"$(findmnt -n -o FSTYPE {path})\" = overlay ]"
                )
            )

        graphical_state = json.loads(
            graphical.succeed("cat /mnt/data/state.json")
        )
        assert graphical_state["state"] == "Inactive", (
            f"Expected decoy state after post-mount rollback, got: {graphical_state}"
        )
        assert graphical_state["overlay_status"] == {}, (
            f"Expected empty overlay tracking after rollback, got: {graphical_state}"
        )
  '';
}
