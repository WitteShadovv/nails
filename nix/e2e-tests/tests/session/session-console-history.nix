# Activation or an emergency typed into a shell that a console login started,
# a terminal window of a desktop started at the login prompt or a root shell,
# never reaches the decoy's shell history.
#
# The console logs in through util-linux's login, as Fedora and Arch do, so the
# login shell leads tty1's session. As that shell dies, the kernel hangs up
# tty1 and sends its foreground job SIGHUP: a compositor started at the prompt
# ends, and with it its terminal windows, each window's end hangs up its
# pseudo-terminal and the shell in it gets SIGHUP; `sudo -i` passes the SIGHUP
# on to the root shell it runs. bash writes its history on SIGHUP. Activation
# and the emergency SIGKILL every interactive shell on the decoy, and the shell
# that typed the command must have its SIGKILL before the login shell dies.
#
# Stand-ins replace the compositor and the terminal, so the test needs no
# graphics: `compositor` runs on tty1 in the foreground with no handler for
# SIGHUP and passes on to its window what is typed there, and `terminal` runs
# an interactive bash on a pseudo-terminal whose master it holds, and ends
# when its connection to the compositor closes. Before each activation 400
# idle processes start, about as many as a desktop session runs, so the
# activation finds about as many processes in /proc as on a desktop.
#
#   1. The window starts as sway, Hyprland and i3 start one: forked twice, in
#      a session of its own, so PID 1 adopts it and the login shell is no
#      ancestor of the activation.
#   2. The window is the compositor's own child, in its process group, as cage
#      starts its application.
#   3. No compositor: `sudo -i` at the prompt opens a root shell, and the
#      activation is typed into that.
#   4. On the plain decoy, `sudo nails emergency --poweroff` is typed into a
#      window as in 1, and the machine powers off and boots again.
#
# After each, back on the decoy, neither testuser nor root has a history
# file: no shell wrote one.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;

  # `compositor detached` or `compositor child`.
  compositor = pkgs.writeScriptBin "compositor" ''
    #!${pkgs.python3.interpreter}
    import os
    import socket
    import sys

    LAYOUT = sys.argv[1]
    display, client = socket.socketpair()
    child = os.fork()
    if child == 0:
        display.close()
        if LAYOUT == "detached":
            os.setsid()
            if os.fork() != 0:
                os._exit(0)
        null = os.open("/dev/null", os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        os.set_inheritable(client.fileno(), True)
        os.execvp("terminal", ["terminal", str(client.fileno())])
    if LAYOUT == "detached":
        os.waitpid(child, 0)
    client.close()
    while True:
        typed = os.read(0, 4096)
        if not typed:
            break
        display.sendall(typed)
  '';

  # `terminal FD`: FD is the connection to the compositor.
  terminal = pkgs.writeScriptBin "terminal" ''
    #!${pkgs.python3.interpreter}
    import os
    import pty
    import select
    import sys

    display = int(sys.argv[1])
    os.set_inheritable(display, False)
    pid, master = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash", "-i"])
    while True:
        ready, _, _ = select.select([display, master], [], [])
        if display in ready:
            typed = os.read(display, 4096)
            if not typed:
                os._exit(0)
            os.write(master, typed)
        if master in ready:
            try:
                if not os.read(master, 4096):
                    os._exit(0)
            except OSError:
                os._exit(0)
  '';
in
{
  name = "session-console-history";
  meta.tags = [
    "security"
    "shell"
    "session"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        compositor
        terminal
      ];
      # Shadow's login, NixOS's own, leads the console's session itself and
      # starts the shell in it.
      services.getty.loginProgram = "${pkgs.util-linux}/bin/login";
    };

  testScript = _: ''
    import secrets

    from nails_e2e import session

    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    HISTORIES = ("/home/testuser/.bash_history", "/root/.bash_history")
    IDLE = 400


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


    def ids(pid):
        """The parent, session and controlling terminal of `pid`."""
        ppid, sid, tty = machine.succeed(f"ps -o ppid=,sid=,tty= -p {pid}").split()
        return int(ppid), int(sid), tty


    def histories() -> dict[str, str]:
        found: dict[str, str] = {}
        for path in HISTORIES:
            rc, out = machine.execute(f"cat {path}")
            if rc == 0:
                found[path] = out
        return found


    def start_idle_processes():
        machine.succeed(
            "systemctl reset-failed desktop-processes 2>/dev/null || true; "
            "systemd-run --unit desktop-processes --property=Type=exec "
            "--setenv=PATH=/run/current-system/sw/bin "
            f"sh -c 'for i in $(seq {IDLE}); do sleep 100000 & done; wait'"
        )
        machine.wait_until_succeeds(
            f"test $(pgrep -c -f '^sleep 100000$') -ge {IDLE}", timeout=120
        )


    def start_window(layout):
        """Start the compositor at the login prompt on tty1, with its window."""
        login = int(machine.succeed("pgrep -u testuser -x bash -t tty1").strip())
        machine.send_chars(f"compositor {layout}\n")
        window = int(
            machine.wait_until_succeeds(
                "pgrep -u testuser -x bash -P $(pgrep -u testuser -f bin/terminal)",
                timeout=60,
            ).strip()
        )
        # The login shell leads tty1's session, and the window's shell a
        # session of its own on the window's pseudo-terminal.
        assert ids(login)[1] == login, ids(login)
        terminal, sid, tty = ids(window)
        assert sid == window and tty.startswith("pts/"), ids(window)
        if layout == "detached":
            # PID 1 adopted the window, in a session of its own.
            assert ids(terminal)[0] == 1 and ids(terminal)[1] != login, ids(terminal)
        else:
            # The window is the compositor's child, in the login session.
            assert ids(terminal)[1] == login, ids(terminal)


    def start_root_shell():
        login = int(machine.succeed("pgrep -u testuser -x bash -t tty1").strip())
        assert ids(login)[1] == login, ids(login)
        machine.send_chars("sudo -i\n")
        machine.wait_until_succeeds(
            'pgrep -u root -x bash -P "$(pgrep -d, -x sudo)"', timeout=60
        )


    def type_a_line():
        """Type a line into the shell in the foreground, so it has history to
        write, and log the processes around it."""
        ready = "/run/typed-" + secrets.token_hex(4)
        machine.send_chars(f"sudo touch {ready}\n")
        machine.wait_until_succeeds(f"test -e {ready}", timeout=60)
        machine.log(
            machine.succeed(
                "ps -e -o pid,ppid,pgid,sid,tpgid,tty,user,args --sort=pid "
                "| grep -E 'PID|login|bash|sudo|compositor|terminal'"
            )
        )


    def activate_typed(label):
        """Type the activation into the shell in the foreground, follow the
        switch and come back to the decoy."""
        type_a_line()
        token = "act-" + secrets.token_hex(6)
        command = (
            f"sudo nails --config {CONFIG} activate -y --overlay-only || echo "
            f"{session.TRIGGER_EXIT_MARKER}$? $(sudo systemctl is-system-running) "
            f"| sudo tee {session.SERIAL_CONSOLE} # {token}\n"
        )
        session.follow_soft_reboot(
            machine,
            command.strip(),
            label,
            start=lambda: machine.send_chars(command),
        )
        session.assert_hidden_root(machine)
        canonical_deactivate(CONFIG, f"{label}-back")
        found = histories()
        assert not found, f"{label}: a decoy shell wrote its history: {found}"


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    for layout in ("detached", "child"):
        with subtest(f"activation typed into a {layout} window of a console desktop"):
            machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
            login_tty1()
            start_idle_processes()
            start_window(layout)
            activate_typed(f"activate-from-a-{layout}-window")

    with subtest("activation typed into a root shell that sudo -i opened on the console"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        login_tty1()
        start_idle_processes()
        start_root_shell()
        activate_typed("activate-from-a-root-shell")

    with subtest("an emergency typed into a window of a console desktop on the decoy"):
        login_tty1()
        start_idle_processes()
        start_window("detached")
        type_a_line()
        token = "emg-" + secrets.token_hex(6)
        machine.send_chars(f"sudo nails emergency --poweroff # {token}\n")
        session.wait_for_power_off(machine, 300)
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        found = histories()
        assert not found, f"a decoy shell wrote its history at the emergency: {found}"
  '';
}
