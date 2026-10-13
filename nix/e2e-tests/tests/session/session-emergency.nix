# Emergency and shell history in the whole-root session, from a real login
# shell on a tty, the way an operator runs it.
#
# Replaces the live-overlay emergency, invoking-shell-history, real-sudo
# history and emergency power-off tests:
#
#   1. Activation typed into an interactive bash on the decoy's tty1 (through
#      sudo): the soft-reboot ends that shell, and NAILS SIGKILLs it first, so
#      the activation command never reaches the decoy's ~/.bash_history.
#   2. In the hidden session, a login shell on tty1 runs commands and then
#      `sudo nails emergency`. Every hidden process dies at once (the login
#      session included), the machine soft-reboots back to the plain decoy and
#      the decoy greeter (here: getty) comes back; nothing typed in the hidden
#      session reaches the decoy's history file.
#   3. `nails emergency --poweroff` in the hidden session powers the machine
#      off; the next cold boot is the plain decoy with the backend closed.
_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-emergency";
  meta.tags = [
    "security"
    "shell"
    "session"
  ];
  globalTimeout = 1500;

  testScript = _: ''
    import secrets

    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}

    CONFIG = "/mnt/data/config/nails.toml"


    def write_config():
        machine.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "EOF"
        )


    def login_tty1():
        # Clear tty1 first, so a "Password:" left by an earlier phase cannot
        # match; wait for login's own prompt before typing the password (login
        # flushes typeahead when it turns echo off).
        machine.wait_for_unit("getty@tty1.service")
        machine.succeed("printf '\\033[H\\033[2J' > /dev/tty1")
        machine.send_chars("testuser\n")
        machine.wait_until_tty_matches("1", "Password: ", timeout=60)
        machine.send_chars("test\n")
        machine.wait_until_succeeds(
            "loginctl list-sessions --no-legend | grep -q testuser", timeout=60
        )


    def decoy_history():
        rc, out = machine.execute("cat /home/testuser/.bash_history 2>/dev/null")
        return out if rc == 0 else ""


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    write_config()

    activation_token = "act-" + secrets.token_hex(6)
    with subtest("activation typed on the decoy tty never reaches its history"):
        login_tty1()
        # A comment carrying the token rides along in the same command line,
        # so the token is in bash's history exactly when the command is.
        # A failed activation reports its status on the console, so the wait
        # stops at once instead of running out its deadline.
        command = (
            f"sudo nails --config {CONFIG} activate -y --overlay-only "
            f"|| echo nails-trigger-exit=$? | sudo tee /dev/console # {activation_token}\n"
        )
        session.follow_soft_reboot(
            machine,
            command.strip(),
            "activate-from-tty",
            start=lambda: machine.send_chars(command),
        )
        session.assert_hidden_root(machine)

    hidden_token = "hidden-" + secrets.token_hex(6)
    with subtest("emergency from a hidden login shell kills it and returns"):
        machine.succeed(
            "systemctl reset-failed hidden-writer.service 2>/dev/null || true; "
            + "systemd-run --unit hidden-writer --property=Type=exec "
            + "sleep infinity"
        )
        login_tty1()
        machine.send_chars(f"echo {hidden_token}\n")
        machine.wait_until_tty_matches("1", hidden_token, timeout=30)
        command = (
            f"sudo nails --config {CONFIG} emergency "
            "|| echo nails-trigger-exit=$? | sudo tee /dev/console\n"
        )
        timings = session.follow_soft_reboot(
            machine,
            command.strip(),
            "emergency-from-tty",
            start=lambda: machine.send_chars(command),
        )
        machine.log(f"emergency timings: {timings}")
        session.assert_decoy_root(machine)
        machine.fail("systemctl is-active hidden-writer.service")
        machine.fail("loginctl list-sessions --no-legend | grep -q testuser")
        machine.wait_for_unit("getty@tty1.service")
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)

    with subtest("nothing typed in either shell reached the decoy history"):
        history = decoy_history()
        assert activation_token not in history, history
        assert hidden_token not in history, history
        assert "emergency" not in history, history

    with subtest("emergency --poweroff in the hidden session powers off"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "activate-poweroff")
        machine.execute(
            f"(nails --config {CONFIG} emergency --poweroff) </dev/null >/dev/null 2>&1 &",
            check_return=False,
            check_output=False,
        )
        session.wait_for_power_off(machine, 300)

    with subtest("the next cold boot is the plain decoy with the backend closed"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")
        assert activation_token not in decoy_history()
  '';
}
