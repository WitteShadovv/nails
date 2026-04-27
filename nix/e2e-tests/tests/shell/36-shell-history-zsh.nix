# Test 36: Shell History Zsh
# Self-check: subtests used, no sleep sync, hard assertions, shell tag, shared helpers only.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
in
{
  name = "shell-history-zsh";
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

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-headless.yaml"
    shell_path = "/run/current-system/sw/bin/zsh"
    write_headless_config(config_path)

    with subtest("prepare lower-disk zsh history and activate"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("install -m 0644 -o testuser -g users /dev/null /home/testuser/.zsh_history")
        machine.succeed("printf 'lower-history-entry\n' > /home/testuser/.zsh_history")
        activate_for_user(config_path, shell_path)
        assert_status_state("active", config_path=config_path)

    with subtest("active session writes zsh history into overlay"):
        machine.succeed(
            "sudo -u testuser env HOME=/home/testuser "
            + shell_path
            + " -lc \"printf 'nails activate\\nsecret-zsh-entry\\n' > ~/.zsh_history\""
        )
        machine.succeed("test -s /home/testuser/.zsh_history")

    with subtest("deactivate truncates visible zsh history on decoy disk"):
        canonical_deactivate_for_user(
            config_path,
            shell_path,
            unit_name="nails-deactivate-shell-history-zsh",
        )
        machine.succeed("test -f /home/testuser/.zsh_history")
        machine.succeed("test ! -s /home/testuser/.zsh_history")
        assert_status_state("inactive", config_path=config_path)
  '';
}
