# Test 45: Shell History under a real `sudo nails` invocation

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "shell-history-real-sudo";
  meta.tags = [ "shell" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.bash
      ];
      # The test runs `sudo nails` as an unprivileged user, so sudo must find the
      # product on its secure_path and hand NAILS a PATH that includes the system
      # profile for the tools it shells out to.
      security.sudo.extraConfig = ''
        Defaults secure_path="/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin"
      '';
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${assertions.assertStatusStateFn}
    ${testHelpers.readStatusJsonFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-headless.toml"
    write_headless_config(config_path)

    with subtest("seed the operator's pre-existing decoy history (innocuous canary)"):
        # These lines predate activation: they are the operator's ordinary decoy
        # history and must survive deactivation untouched. NAILS does not write to
        # the decoy disk after unmount by default, so a pre-existing line is a
        # canary for "no post-unmount decoy write".
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            "install -m 0644 -o testuser -g users /dev/null /home/testuser/.bash_history"
        )
        machine.succeed(
            "sudo -u testuser tee /home/testuser/.bash_history >/dev/null <<'EOF'\n"
            "ls -la\n"
            "echo harmless\n"
            "vim notes.txt\n"
            "EOF"
        )
        machine.succeed("test -s /home/testuser/.bash_history")

    with subtest("real `sudo nails activate` resolves the operator with no HOME/USER override"):
        # testuser -> sudo -> root: sudo sets SUDO_UID to testuser and resets HOME
        # to /root, exactly like the documented invocation. No identity variables
        # are injected by the test.
        machine.succeed(
            "sudo -u testuser -- sudo nails --config "
            + config_path
            + " activate --overlay-only --session keep -y"
        )
        assert_status_state("active", config_path=config_path)

    with subtest("active session records sensitive commands in the overlaid history"):
        machine.succeed(
            "sudo -u testuser bash -lc "
            + "\"printf 'nails deactivate\\ncryptsetup luksClose data\\n' "
            + ">> ~/.bash_history\""
        )

    with subtest("real `sudo nails deactivate` cleans the operator's home, not root's"):
        run_detached_command(
            "nails-deactivate-shell-history-real-sudo",
            "sudo -u testuser -- sudo nails --config "
            + config_path
            + " deactivate -y",
        )
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")

    with subtest("the pre-existing decoy history is preserved, the session artifacts are gone"):
        # New T-105 behaviour: NAILS makes no post-unmount write to the decoy disk
        # by default. The hidden-session commands lived only in the overlay upper
        # and vanish when it is discarded; the operator's pre-existing decoy lines,
        # written before activation, are left exactly as they were.
        machine.succeed("test -f /home/testuser/.bash_history")
        owner = machine.succeed("stat -c '%U' /home/testuser/.bash_history").strip()
        assert owner == "testuser", f"history must stay operator-owned, got {owner!r}"
        # Pre-existing innocuous canary lines survive (no post-unmount truncation).
        machine.succeed("grep -q 'echo harmless' /home/testuser/.bash_history")
        machine.succeed("grep -q 'vim notes.txt' /home/testuser/.bash_history")
        # The sensitive commands typed during the hidden session never reach the
        # decoy disk: they were confined to the discarded overlay.
        machine.fail("grep -q -e cryptsetup -e 'nails deactivate' /home/testuser/.bash_history")
        assert_status_state("inactive", config_path=config_path)
  '';
}
