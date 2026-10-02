# Test 45: Shell History under a real `sudo nails` invocation
# Self-check: subtests used, no sleep sync, hard assertions, shell tag.
#
# Every other shell test seeds the operator's identity for NAILS (SUDO_UID /
# SUDO_USER, or — before this was fixed — HOME/USER). This test instead performs
# the genuine invocation the product documents: an unprivileged `testuser` runs
# `sudo nails ...` with NO identity variables injected at all. Under that real
# invocation `sudo` resets HOME to /root, so a resolver that trusted HOME would
# clean root's history and leave the operator's untouched. The assertions below
# prove NAILS resolves the operator from the escalation environment and cleans
# /home/testuser — and leaves those files owned by the operator, not root.

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

    with subtest("seed the operator's bash history on the decoy disk, owned by testuser"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            "install -m 0644 -o testuser -g users /dev/null /home/testuser/.bash_history"
        )
        machine.succeed(
            "sudo -u testuser tee /home/testuser/.bash_history >/dev/null <<'EOF'\n"
            "ls -la\n"
            "nails activate --overlay-only\n"
            "cryptsetup luksOpen /dev/vdb data\n"
            "echo harmless\n"
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

    with subtest("the decoy-disk history is emptied and stays owned by the operator"):
        # If the resolver had fallen back to root's HOME, this file would still
        # hold the seeded lines. It is empty, so cleanup reached /home/testuser.
        machine.succeed("test -f /home/testuser/.bash_history")
        machine.succeed("test ! -s /home/testuser/.bash_history")
        owner = machine.succeed("stat -c '%U' /home/testuser/.bash_history").strip()
        assert owner == "testuser", f"history must stay operator-owned, got {owner!r}"
        # Belt and braces: none of the sensitive lines survive.
        machine.fail("grep -q -e nails -e cryptsetup /home/testuser/.bash_history")
        assert_status_state("inactive", config_path=config_path)
  '';
}
