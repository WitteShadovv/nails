# Test 42: Shell Alias Setup
# Self-check: subtests used, no sleep sync, hard assertions, shell tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
in {
  name = "shell-alias-setup";
  meta.tags = [ "shell" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${shellHelpers.runCommandCaptureFn}
    ${shellHelpers.activateForUserFn}
    ${shellHelpers.canonicalDeactivateForUserFn}
    ${assertions.assertStatusStateFn}
    ${testHelpers.readStatusJsonFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-headless.yaml"
    shell_path = "/run/current-system/sw/bin/bash"
    alias_command = (
        "sudo -u testuser env HOME=/home/testuser "
        + shell_path
        + " -ic 'alias nails'"
    )
    write_headless_config(config_path)

    with subtest("alias is absent before activation"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("cat > /home/testuser/.bashrc <<'EOF'\nexport PS1=\"decoy$ \"\nEOF")
        machine.succeed("chown testuser:users /home/testuser/.bashrc")
        before = run_command_capture("alias-before", alias_command)
        assert before["rc"] != 0, before

    with subtest("activation defines the nails alias in interactive shells"):
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)
        active = run_command_capture("alias-active", alias_command)
        assert active["rc"] == 0, active
        assert "alias nails='sudo " in active["stdout"], active

    with subtest("alias disappears again after deactivation"):
        canonical_deactivate_for_user(
            config_path,
            shell_path,
            unit_name="nails-deactivate-shell-alias-setup",
        )
        after = run_command_capture("alias-after", alias_command)
        assert after["rc"] != 0, after
        assert_status_state("inactive", config_path=config_path)
  '';
}
