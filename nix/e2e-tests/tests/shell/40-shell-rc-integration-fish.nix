# Test 40: Shell RC Integration Fish

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
in
{
  name = "shell-rc-integration-fish";
  meta.tags = [ "shell" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      programs.fish.enable = true;
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.fish
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
    shell_path = "/run/current-system/sw/bin/fish"
    rc_path = "/home/testuser/.config/fish/config.fish"
    autostart_dir = "/home/testuser/.config/autostart"
    desktop_path = autostart_dir + "/nails-notify.desktop"
    expected_lower = "# lower fish config\nset -gx LOWER_FISH_RC 1\n"
    write_headless_config(config_path)

    with subtest("prepare lower fish config and activate"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            "install -d -m 0755 -o testuser -g users /home/testuser/.config /home/testuser/.config/fish"
        )
        machine.succeed("cat > " + rc_path + " <<'EOF'\n" + expected_lower + "EOF")
        machine.succeed("chown testuser:users " + rc_path)
        machine.succeed("chmod 0644 " + rc_path)
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)

    with subtest("activation injects fish integration block into overlaid config"):
        rc_contents = machine.succeed("cat " + rc_path)
        assert expected_lower in rc_contents, rc_contents
        assert "# >>> managed shell integration" in rc_contents, rc_contents
        assert "source /mnt/data/scripts/nails_prompt.fish" in rc_contents, rc_contents
        assert "source /mnt/data/scripts/nails_alias.fish" in rc_contents, rc_contents

    with subtest("files written into the overlaid home belong to the operator"):
        assert_owned_by(rc_path, "testuser:users", "644")
        assert_owned_by(autostart_dir, "testuser:users", "700")
        assert_owned_by(desktop_path, "testuser:users", "644")

    with subtest("deactivation restores lower fish config without integration block"):
        canonical_deactivate_for_user(
            config_path,
            shell_path,
            unit_name="nails-deactivate-shell-rc-fish",
        )
        rc_after = machine.succeed("cat " + rc_path)
        assert rc_after == expected_lower, rc_after
        assert_status_state("inactive", config_path=config_path)
  '';
}
