# Test 38: Shell RC Integration Bash
# Self-check: subtests used, no sleep sync, hard assertions, shell tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
in {
  name = "shell-rc-integration-bash";
  meta.tags = [ "shell" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${shellHelpers.activateForUserFn}
    ${shellHelpers.canonicalDeactivateForUserFn}
    ${assertions.assertStatusStateFn}
    ${testHelpers.readStatusJsonFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-headless.yaml"
    shell_path = "/run/current-system/sw/bin/bash"
    rc_path = "/home/testuser/.bashrc"
    expected_lower = "# lower bashrc\nexport LOWER_BASH_RC=1\n"
    write_headless_config(config_path)

    with subtest("prepare lower rc file and activate"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("cat > " + rc_path + " <<'EOF'\n" + expected_lower + "EOF")
        machine.succeed("chown testuser:users " + rc_path)
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)

    with subtest("activation injects bash integration block into overlaid rc file"):
        rc_contents = machine.succeed("cat " + rc_path)
        assert expected_lower in rc_contents, rc_contents
        assert "# >>> NAILS shell integration" in rc_contents, rc_contents
        assert "source /mnt/hidden-volume/scripts/nails_prompt.bash" in rc_contents, rc_contents
        assert "source /mnt/hidden-volume/scripts/nails_alias.sh" in rc_contents, rc_contents

    with subtest("deactivation restores lower bashrc without integration block"):
        canonical_deactivate_for_user(
            config_path,
            shell_path,
            unit_name="nails-deactivate-shell-rc-bash",
        )
        rc_after = machine.succeed("cat " + rc_path)
        assert rc_after == expected_lower, rc_after
        assert_status_state("inactive", config_path=config_path)
  '';
}
