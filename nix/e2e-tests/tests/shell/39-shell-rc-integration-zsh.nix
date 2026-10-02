# Test 39: Shell RC Integration Zsh

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
in
{
  name = "shell-rc-integration-zsh";
  meta.tags = [ "shell" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      programs.zsh.enable = true;
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.zsh
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${shellHelpers.activateForUserFn}
    ${shellHelpers.canonicalDeactivateForUserFn}
    ${assertions.assertStatusStateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertOwnedByFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-headless.toml"
    shell_path = "/run/current-system/sw/bin/zsh"
    rc_path = "/home/testuser/.zshrc"
    config_dir = "/home/testuser/.config"
    autostart_dir = config_dir + "/autostart"
    desktop_path = autostart_dir + "/nails-notify.desktop"
    write_headless_config(config_path)

    # Unlike the bash and fish tests there is no lower rc file and no
    # ~/.config: every file and directory below is created by nails, which is
    # the case that used to leave them owned by root.
    with subtest("activate with no rc file or config directory in the home"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.fail("test -e " + rc_path)
        machine.fail("test -e " + config_dir)
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)

    with subtest("activation creates the zsh rc file with the integration block"):
        rc_contents = machine.succeed("cat " + rc_path)
        assert rc_contents.startswith("# >>> managed shell integration"), rc_contents
        assert "source /mnt/data/scripts/nails_prompt.zsh" in rc_contents, rc_contents
        assert "source /mnt/data/scripts/nails_alias.sh" in rc_contents, rc_contents

    with subtest("files and directories nails creates belong to the operator"):
        assert_owned_by(rc_path, "testuser:users", "644")
        assert_owned_by(config_dir, "testuser:users", "700")
        assert_owned_by(autostart_dir, "testuser:users", "700")
        assert_owned_by(desktop_path, "testuser:users", "644")

    with subtest("deactivation leaves no zshrc behind in the decoy home"):
        canonical_deactivate_for_user(
            config_path,
            shell_path,
            unit_name="nails-deactivate-shell-rc-zsh",
        )
        machine.fail("test -e " + rc_path)
        machine.fail("test -e " + config_dir)
        assert_status_state("inactive", config_path=config_path)
  '';
}
