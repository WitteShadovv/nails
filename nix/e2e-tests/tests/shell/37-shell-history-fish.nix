# Test 37: Shell History Fish

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
in
{
  name = "shell-history-fish";
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

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-headless.toml"
    shell_path = "/run/current-system/sw/bin/fish"
    history_path = "/home/testuser/.local/share/fish/fish_history"
    write_headless_config(config_path)

    with subtest("prepare lower-disk fish history and activate"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("install -d -m 0755 -o testuser -g users /home/testuser/.local/share/fish")
        machine.succeed(
            "sudo -u testuser env HOME=/home/testuser /bin/sh -lc "
            + "\"printf '%s\\n' '- cmd: lower-fish-entry' '  when: 1' > ~/.local/share/fish/fish_history\""
        )
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)

    with subtest("active session writes structured fish history into overlay"):
        machine.succeed("chown testuser:users " + history_path)
        machine.succeed(
            "sudo -u testuser env HOME=/home/testuser "
            + shell_path
            + " -lc \"printf '%s\\n' '- cmd: nails activate' '  when: 1700000000' '- cmd: secret-fish-entry' '  when: 1700000001' > ~/.local/share/fish/fish_history\""
        )
        machine.succeed("test -s " + history_path)

    with subtest("deactivate leaves the decoy fish history untouched; session entries were overlay-only"):
        # New T-105 behaviour: no post-unmount write to the decoy disk. The
        # in-session fish entries lived in the discarded overlay upper; the
        # pre-existing lower-disk entry is preserved.
        canonical_deactivate_for_user(
            config_path,
            shell_path,
            unit_name="nails-deactivate-shell-history-fish",
        )
        machine.succeed("test -f " + history_path)
        machine.succeed("grep -q 'lower-fish-entry' " + history_path)
        machine.fail("grep -q -e 'secret-fish-entry' -e 'nails activate' " + history_path)
        assert_status_state("inactive", config_path=config_path)
  '';
}
