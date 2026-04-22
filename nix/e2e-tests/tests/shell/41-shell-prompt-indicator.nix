# Test 41: Shell Prompt Indicator
# Self-check: subtests used, no sleep sync, hard assertions, shell tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
in
{
  name = "shell-prompt-indicator";
  meta.tags = [ "shell" ];

  nodes.machine =
    { ... }:
    {
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
    write_headless_config(config_path)

    prompt_command = (
        "sudo -u testuser env HOME=/home/testuser "
        + shell_path
        + " -ic 'printf %s \"$PS1\"'"
    )

    with subtest("prompt is ordinary before activation"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("cat > /home/testuser/.bashrc <<'EOF'\nexport PS1=\"decoy$ \"\nEOF")
        machine.succeed("chown testuser:users /home/testuser/.bashrc")
        before = run_command_capture("prompt-before", prompt_command)
        assert before["rc"] == 0, before
        assert "NAILS-ACTIVE" not in before["stdout"], before

    with subtest("prompt gains active indicator while overlays are mounted"):
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)
        active = run_command_capture("prompt-active", prompt_command)
        assert active["rc"] == 0, active
        assert "NAILS-ACTIVE" in active["stdout"], active

    with subtest("prompt indicator disappears after deactivation"):
        canonical_deactivate_for_user(
            config_path,
            shell_path,
            unit_name="nails-deactivate-shell-prompt-indicator",
        )
        after = run_command_capture("prompt-after", prompt_command)
        assert after["rc"] == 0, after
        assert "NAILS-ACTIVE" not in after["stdout"], after
        assert_status_state("inactive", config_path=config_path)
  '';
}
