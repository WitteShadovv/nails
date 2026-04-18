# Test 43: Shell Color Scheme
# Self-check: subtests used, no sleep sync, hard assertions, shell tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
in {
  name = "shell-color-scheme";
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
    osc_sequence = "\x1b]11;#1a1a2e\x07\x1b]10;#e0e0e0\x07"
    shell_command = (
        "sudo -u testuser env HOME=/home/testuser "
        + shell_path
        + " -ic ':'"
    )
    write_headless_config(config_path)

    with subtest("interactive shell startup emits no hidden color scheme before activation"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("cat > /home/testuser/.bashrc <<'EOF'\nexport PS1=\"decoy$ \"\nEOF")
        machine.succeed("chown testuser:users /home/testuser/.bashrc")
        before = run_command_capture("color-before", shell_command)
        assert before["rc"] == 0, before
        assert osc_sequence not in before["stdout"], before

    with subtest("interactive shell startup emits hidden color scheme while active"):
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)
        active = run_command_capture("color-active", shell_command)
        assert active["rc"] == 0, active
        assert osc_sequence in active["stdout"], repr(active["stdout"])

    with subtest("interactive shell startup stops emitting hidden color scheme after deactivation"):
        canonical_deactivate_for_user(
            config_path,
            shell_path,
            unit_name="nails-deactivate-shell-color-scheme",
        )
        after = run_command_capture("color-after", shell_command)
        assert after["rc"] == 0, after
        assert osc_sequence not in after["stdout"], repr(after["stdout"])
        assert_status_state("inactive", config_path=config_path)
  '';
}
