# Session: the window's launcher in the hidden session
#
# A build with the window (the `gui` cargo feature, and the window's program
# at <hidden-root>/gui/bin/session) writes at every activation a menu entry
# "Session" and a polkit action for the window's helper. On NixOS both go into
# the hidden root's upper: the entry into the operator's
# ~/.local/share/applications, the action into /etc/polkit-1/actions.
#
# The engine here is the static musl `nails` with that feature, run from the
# hidden volume as an operator runs it (sudo from testuser), with the gui
# workspace's window beside it. A driver plays the window (helper_driver.py):
# it activates through the helper, sees each step and the point of no return
# come before the answer, and comes back the same way. In the hidden session
# the test shows:
#
#   - the entry, valid for desktop-file-validate, runs the window with the
#     engine whose helper it starts;
#   - polkit knows the action (`pkaction --verbose`): the neutral message, an
#     administrator's password every time, the engine's path and `helper` as
#     its first argument;
#   - pkexec takes that action for `<engine> helper --stdio`: a test-only
#     rule grants this action alone, so the helper starts as root through
#     pkexec and greets the window that is not there, while another command
#     line of the engine stays pkexec's own action and is refused. The action
#     matches the engine and its first argument only, so it also covers
#     `<engine> helper --stdio --config <file>`; the helper refuses that one
#     and starts nothing;
#   - the entry's own command, run as the desktop runs it on an X server of
#     the test's, opens the window, which starts the helper through pkexec:
#     the helper runs as root, the window's child, and keeps its session
#     with the window until the window closes; the window's command line,
#     once it started itself again, names no path; on a session bus whose
#     services only record that they were started, the window never starts
#     the settings portal, while AccessKit's status read starts the
#     accessibility bus;
#   - both files lie on the hidden volume, and the decoy root, mounted
#     read-only beside the session, has neither;
#   - the helper plans a deactivation with its token for each ending;
#   - `sudo <engine> gui` opens the window: its own directory in the
#     operator's runtime directory, handed over by root, and the window as
#     the operator with no supplementary group and no_new_privs.
#
# After the way back the decoy has neither file and polkit no such action, and
# the decoy disk image, read from the host after a power-off, holds none of
# their text.
{ self, pkgs, ... }:
let
  inherit (pkgs) lib;
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  diskForensics = import ./../../lib/disk-forensics.nix { inherit pkgs; };
  packages = self.packages.x86_64-linux;
  # The release binary with the window's helper, launcher and launcher writer
  # built in: the `gui` cargo feature, which no release enables yet.
  windowEngine = packages.nails.overrideAttrs (old: {
    pname = "nails-window";
    cargoBuildFlags = old.cargoBuildFlags ++ [
      "--features"
      "gui"
    ];
  });
  # The window's program with the libraries its toolkit opens at run time on
  # its RPATH: NixOS has no system library directory, and the window clears
  # LD_LIBRARY_PATH from its environment.
  windowProgram = pkgs.runCommand "session-window" { nativeBuildInputs = [ pkgs.patchelf ]; } ''
    install -D -m 0755 ${packages.nails-gui}/bin/session $out/bin/session
    patchelf --add-rpath ${
      lib.makeLibraryPath [
        pkgs.fontconfig.lib
        pkgs.libxkbcommon
        pkgs.libx11
        pkgs.libxcb
        pkgs.libxcursor
        pkgs.libxext
        pkgs.libxi
        pkgs.libxrandr
        pkgs.libxrender
      ]
    } $out/bin/session
  '';
in
{
  name = "session-window-launcher";
  meta.tags = [ "session" ];

  # Two soft-reboots, a power-off and the scan of the decoy image.
  globalTimeout = 1500;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      security.polkit = {
        enable = true;
        enablePkexecWrapper = true;
        # Test-only: no one can answer a password prompt here, so testuser is
        # granted the window's action and nothing else. pkexec of any other
        # command line still asks for a password, and fails.
        extraConfig = ''
          polkit.addRule(function (action, subject) {
            if (action.id == "session.open" && subject.user == "testuser") {
              return polkit.Result.YES;
            }
          });
        '';
      };
      environment.systemPackages = [
        pkgs.desktop-file-utils
        pkgs.python3
      ];
      # A font for the window's pages.
      fonts.packages = [ pkgs.dejavu_fonts ];
      system.extraDependencies = [
        windowEngine
        windowProgram
        pkgs.xvfb
        pkgs.dbus
      ];
    };

  testScript = _: ''
    import base64
    import json
    import shlex

    ${diskForensics.pythonSetup}

    from nails_e2e import session

    CONFIG = "/mnt/data/config/nails.toml"
    DRIVER = "python3 -P ${./../../lib/helper_driver.py}"
    # The window's helper as the window starts it on the decoy: sudo from the
    # operator's account.
    HELPER = f"su testuser -c 'sudo /mnt/data/nails --config {CONFIG} helper --stdio'"
    # The marker of the driver's lines on the serial console.
    FRAME = "HELPER-FRAME "
    UPPER = "/mnt/data/root/upper"
    PEEK = "/run/decoy-peek"
    ENTRY = "/home/testuser/.local/share/applications/session.desktop"
    ACTION = "/etc/polkit-1/actions/session.open.policy"
    # Text only the launcher writes: none of it may reach the decoy disk.
    TOKENS = [
        "Session needs your password each time it opens.",
        '"/mnt/data/gui/bin/session" --engine "/mnt/data/nails"',
        "TryExec=/mnt/data/gui/bin/session",
        '<annotate key="org.freedesktop.policykit.exec.path">/mnt/data/nails</annotate>',
    ]
    # Written to the decoy on purpose at the end: the scan must find it.
    CONTROL = "LAUNCHER_SCAN_CONTROL_7f3a"


    def no_such_action():
        """polkit answers, and knows no window action."""
        machine.succeed("pkaction --action-id org.freedesktop.policykit.exec")
        out = machine.fail("pkaction --action-id session.open 2>&1")
        assert "No action with action id session.open" in out, out


    def frames(lines):
        """The helper's frames among `lines`, as the driver wrote them."""
        return [json.loads(line) for line in lines if line.strip()]


    def console_frames(since):
        """The frames the driver wrote to the serial console after `since`."""
        found = []
        for line in machine.full_console_log[since:]:
            if FRAME in line:
                found.append(json.loads(line.split(FRAME, 1)[1].strip()))
        return found


    def answers(found):
        """The result frames among `found`, in order."""
        return [frame["result"] for frame in found if "result" in frame]


    def peek_decoy(decoy_dev, command):
        """Run `command` against a read-only mount of the decoy root at PEEK.

        The decoy superblock is still mounted read-write (it is the overlay's
        lower), so mount it, then make this mount read-only."""
        machine.succeed(
            f"mkdir -p {PEEK} && mount {decoy_dev} {PEEK} && mount -o remount,bind,ro {PEEK}"
        )
        try:
            return machine.succeed(command)
        finally:
            machine.succeed(f"umount {PEEK} && rmdir {PEEK}")


    machine.start()
    machine.wait_for_unit("multi-user.target")
    decoy_dev = machine.succeed("findmnt -no SOURCE /").strip()

    with subtest("a build with the window on the hidden volume, nothing on the decoy"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("install -m 0755 ${windowEngine}/bin/nails /mnt/data/nails")
        machine.succeed(
            "install -D -m 0755 ${windowProgram}/bin/session /mnt/data/gui/bin/session"
        )
        machine.succeed(
            "mkdir -p /mnt/data/config && "
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            "EOF"
        )
        machine.succeed(f"test ! -e {ENTRY} && test ! -e {ACTION}")
        no_such_action()

    with subtest("activate through the window's helper: each step, then the point of no return"):
        # The frames land on the hidden volume as they come, before the
        # switch stops the driver.
        activation = "/mnt/data/helper-activate"
        session.follow_soft_reboot(
            machine,
            f"{DRIVER} {activation}.jsonl {activation}.err activate -- {HELPER}",
            "activate",
        )
        session.assert_hidden_root(machine, UPPER)
        found = frames(machine.succeed(f"cat {activation}.jsonl").splitlines())
        stderr = machine.succeed(f"cat {activation}.err")
        print(stderr)
        assert "launcher was not written" not in stderr, stderr
        events = [frame["event"]["event"]["type"] for frame in found if "event" in frame]
        print(events)
        assert "step" in events and "check" in events, events
        results = answers(found)
        # The hello, the plan with its token, and the apply: entering, after
        # the point of no return, which comes after every step.
        assert len(results) == 3, results
        plan, applied = results[1], results[2]
        assert plan["envelope"]["data"]["builds_hidden_system"] is False, plan
        assert len(plan["envelope"]["data"]["token"]) == 32, plan
        assert applied["exit"] == 0, applied
        assert applied["envelope"]["command"] == "activate", applied
        assert applied["envelope"]["data"]["status"].startswith("entering"), applied
        # The point of no return comes after the last step and before the
        # answer, which is the last frame.
        point = events.index("point_of_no_return")
        assert "step" not in events[point:], events
        assert "result" in found[-1], found
        assert found[-1]["result"] == applied, found

    with subtest("the entry runs the window with the engine whose helper it starts"):
        entry = machine.succeed(f"cat {ENTRY}")
        print(entry)
        for line in (
            "Name=Session",
            'Exec="/mnt/data/gui/bin/session" --engine "/mnt/data/nails"',
            "TryExec=/mnt/data/gui/bin/session",
        ):
            assert line in entry.splitlines(), f"{line!r} not in {entry!r}"
        machine.succeed(f"desktop-file-validate {ENTRY}")
        owner = machine.succeed(f"stat -c '%U %a' {ENTRY}").strip()
        assert owner == "testuser 644", owner

    with subtest("polkit knows the action: neutral, the helper only, a password every time"):
        out = machine.succeed("pkaction --action-id session.open --verbose")
        print(out)
        for line in (
            "session.open:",
            "  description:       Session",
            "  message:           Session needs your password each time it opens.",
            "  implicit any:      auth_admin",
            "  implicit inactive: auth_admin",
            "  implicit active:   auth_admin",
            "  annotation:        org.freedesktop.policykit.exec.path -> /mnt/data/nails",
            "  annotation:        org.freedesktop.policykit.exec.argv1 -> helper",
        ):
            assert line in out.splitlines(), f"{line!r} not in {out!r}"
        assert "nails" not in out.split("annotation:")[0], out

    with subtest("pkexec takes the action for the helper, which takes no other argument"):
        # A session of its own, without the driver's console as a terminal,
        # and no text agent: nothing can wait on a password prompt.
        def pkexec(command):
            return (
                "su testuser -c 'setsid -w timeout 60 pkexec --disable-internal-agent "
                f"{command} < /dev/null'"
            )

        hello = machine.succeed(pkexec("/mnt/data/nails helper --stdio"))
        print(hello)
        frame = json.loads(hello.splitlines()[0])
        assert frame["hello"]["protocol"] == 1, frame
        # Another command line of the engine is pkexec's own action, which the
        # rule does not grant, and no agent can ask for a password here.
        machine.fail(pkexec("/mnt/data/nails status"))
        # The action matches the engine and `helper` alone, so it covers a
        # longer line too, behind the same neutral dialog. The helper refuses
        # it: no configuration the window names reaches a root helper.
        machine.succeed("echo 'hidden_volume_root = \"/tmp\"' > /tmp/x.toml")
        refused = machine.fail(
            pkexec("/mnt/data/nails helper --stdio --config /tmp/x.toml") + " 2>&1"
        )
        print(refused)
        assert '"hello"' not in refused, refused
        assert "only as `helper --stdio`" in refused, refused

    with subtest("the entry's own command opens the window, whose pkexec starts the helper"):
        # The command the desktop runs for the entry, read from the entry.
        exec_line = next(
            line.removeprefix("Exec=") for line in entry.splitlines() if line.startswith("Exec=")
        )
        argv = shlex.split(exec_line)
        assert argv == ["/mnt/data/gui/bin/session", "--engine", "/mnt/data/nails"], argv
        uid = machine.succeed("id -u testuser").strip()
        # What a desktop session gives it: the operator's runtime directory
        # in RAM, which logind makes at a login (nothing here logs in), and a
        # display, the test's own X server.
        machine.succeed(f"install -d -m 0700 -o testuser -g users /run/user/{uid}")
        machine.succeed("install -d -m 1777 /tmp/.X11-unix")
        machine.succeed(
            "su testuser -c 'setsid ${pkgs.xvfb}/bin/Xvfb :7 -nolisten tcp "
            "-screen 0 1024x768x24 < /dev/null > /dev/null 2>&1 &'"
        )
        machine.wait_until_succeeds("test -S /tmp/.X11-unix/X7", timeout=60)
        # And the operator's session bus, in the runtime directory as a
        # desktop runs it, whose two activatable services only record that the
        # bus started them: the settings portal the window's toolkit reads,
        # and the accessibility bus AccessKit asks.
        bus = "/run/session-test-bus"
        machine.succeed(f"install -d -m 0755 -o testuser -g users {bus} {bus}/services")
        machine.succeed(
            f"cat > {bus}/started.sh <<'EOF'\n"
            "#!/bin/sh\n"
            f"echo \"$1\" >> {bus}/started\n"
            "EOF\n"
            f"chmod 0755 {bus}/started.sh"
        )
        for name in ("org.freedesktop.portal.Desktop", "org.a11y.Bus"):
            machine.succeed(
                f"printf '[D-BUS Service]\\nName={name}\\nExec={bus}/started.sh {name}\\n' "
                f"> {bus}/services/{name}.service"
            )
        machine.succeed(
            f"cat > {bus}/bus.conf <<'EOF'\n"
            "<busconfig>\n"
            "  <type>session</type>\n"
            f"  <listen>unix:path=/run/user/{uid}/bus</listen>\n"
            "  <auth>EXTERNAL</auth>\n"
            f"  <servicedir>{bus}/services</servicedir>\n"
            "  <policy context='default'>\n"
            "    <allow send_destination='*' eavesdrop='true'/>\n"
            "    <allow eavesdrop='true'/>\n"
            "    <allow own='*'/>\n"
            "  </policy>\n"
            "</busconfig>\n"
            "EOF"
        )
        machine.succeed(
            f"su testuser -c 'setsid ${pkgs.dbus}/bin/dbus-daemon --config-file={bus}/bus.conf "
            "--nofork --nopidfile --nosyslog < /dev/null > /dev/null 2>&1 &'"
        )
        machine.wait_until_succeeds(f"test -S /run/user/{uid}/bus", timeout=60)
        command = " ".join(shlex.quote(word) for word in argv)
        # Only the window goes to the background, with its streams on
        # /dev/null: a background list would keep the driver's output open
        # for as long as the window runs.
        machine.succeed(
            f"su testuser -c 'cd; DISPLAY=:7 XDG_RUNTIME_DIR=/run/user/{uid} "
            f"setsid {command} < /dev/null > /dev/null 2>&1 &'"
        )
        window = machine.wait_until_succeeds("pgrep -u testuser -x session", timeout=60).strip()
        # pkexec became root: it started the helper, which runs as the
        # window's child.
        helper_of_window = f"pgrep -u root -P {window} -f '^/mnt/data/nails helper --stdio$'"
        helper = machine.wait_until_succeeds(helper_of_window, timeout=90).strip()

        def field(pid, key):
            return machine.succeed(f"grep '^{key}:' /proc/{pid}/status | cut -f2").strip()

        assert field(helper, "Uid") == "0", "the helper does not run as root"
        assert field(helper, "NoNewPrivs") == "0", "pkexec ran under no_new_privs"
        assert field(window, "NoNewPrivs") == "1", "the window did not limit itself"
        # Started again by its name alone, with the engine on its standard
        # input: a log that quotes its command line names no place.
        cmdline = base64.b64decode(machine.succeed(f"base64 -w0 /proc/{window}/cmdline"))
        assert cmdline == b"session\x00--engine\x00-\x00", cmdline
        # The window took the helper's hello and keeps the session: a window
        # that refused it, or could not open, would have closed its end of
        # the pair, and the helper would have ended with it.
        # sync-lint: allow sleep -- the window and its helper must still run five seconds after the hello
        machine.sleep(5)
        machine.succeed(f"kill -0 {window} && {helper_of_window}")
        # On its session bus the window never started the settings portal:
        # its reads carry NO_AUTO_START. AccessKit's status read did start
        # the accessibility bus, which shows that the window talked on it.
        started = machine.succeed(f"cat {bus}/started 2>/dev/null || true").split()
        print(f"services the bus started for the window: {started}")
        assert "org.freedesktop.portal.Desktop" not in started, started
        assert "org.a11y.Bus" in started, started
        # Closing the window closes its end: the helper ends too.
        machine.succeed(f"kill {window}")
        machine.wait_until_fails(f"kill -0 {helper}", timeout=30)
        machine.wait_until_fails(f"kill -0 {window}", timeout=30)
        machine.succeed("pkill -u testuser -x Xvfb")
        machine.wait_until_fails("pgrep -u testuser -x Xvfb", timeout=30)
        machine.succeed("pkill -u testuser -x dbus-daemon")
        machine.wait_until_fails("pgrep -u testuser -x dbus-daemon", timeout=30)

    with subtest("both files lie on the hidden volume, and the decoy has neither"):
        machine.succeed(f"test -f {UPPER}{ENTRY} && test -f {UPPER}{ACTION}")
        peek_decoy(decoy_dev, f"test ! -e {PEEK}{ENTRY} && test ! -e {PEEK}{ACTION}")

    with subtest("the helper plans a deactivation for each ending, with its token"):
        found = frames(
            machine.succeed(f"{DRIVER} /dev/stdout /tmp/plans.err plans -- {HELPER}").splitlines()
        )
        results = answers(found)
        assert len(results) == 4, results
        for result, poweroff in ((results[1], False), (results[2], True)):
            assert result["exit"] == 0, result
            data = result["envelope"]["data"]
            assert data["poweroff"] is poweroff, data
            assert isinstance(data["warnings"], list), data
            assert len(data["token"]) == 32, data
        assert results[1]["envelope"]["data"]["token"] != results[2]["envelope"]["data"]["token"]

    with subtest("sudo <engine> gui opens the window as the operator, in its own directory"):
        machine.succeed("loginctl enable-linger testuser")
        uid = machine.succeed("id -u testuser").strip()
        gid = machine.succeed("id -g testuser").strip()
        machine.wait_until_succeeds(f"findmnt -no FSTYPE /run/user/{uid} | grep -qx tmpfs", timeout=60)
        # A bundle whose window writes, with shell builtins alone, what it
        # runs as into its home: the directory the launcher made for it.
        probe = "/mnt/data/probe"
        machine.succeed(
            f"mkdir -p {probe}/gui/bin && cp /mnt/data/nails {probe}/nails && "
            f"cat > {probe}/gui/bin/session <<'EOF'\n"
            "#!/bin/sh\n"
            "while read -r key rest; do case $key in "
            "Uid:|Gid:|Groups:|NoNewPrivs:) echo \"$key $rest\";; esac; "
            "done < /proc/self/status > \"$HOME/status\"\n"
            "echo done >> \"$HOME/status\"\n"
            "EOF\n"
            f"chmod 0755 {probe}/gui/bin/session"
        )
        opened = json.loads(
            machine.succeed(f"su testuser -c 'sudo {probe}/nails --config {CONFIG} --json gui'")
        )
        print(opened)
        assert opened["ok"] is True, opened
        machine.wait_until_succeeds(f"grep -qx done /run/user/{uid}/*/status", timeout=60)
        own = machine.succeed(f"dirname /run/user/{uid}/*/status").strip()
        owner = machine.succeed(f"stat -c '%U %a' {own}").strip()
        assert owner == "testuser 700", owner
        status = machine.succeed(f"cat {own}/status").splitlines()
        print(status)
        for line in (
            f"Uid: {uid} {uid} {uid} {uid}",
            f"Gid: {gid} {gid} {gid} {gid}",
            "Groups:",
            "NoNewPrivs: 1",
        ):
            assert line in [" ".join(entry.split()) for entry in status], (line, status)

    with subtest("after the way back the decoy has neither file, and polkit no action"):
        # The way back through the helper of the same build from the store,
        # as the other session tests run the way back, so nothing on the
        # hidden volume is busy when it closes. Its frames go to the serial
        # console, which outlives the switch.
        since = len(machine.full_console_log)
        store_helper = (
            f"su testuser -c 'sudo ${windowEngine}/bin/nails --config {CONFIG} helper --stdio'"
        )
        session.follow_soft_reboot(
            machine,
            f"{DRIVER} /dev/ttyS0 /dev/ttyS0 {FRAME.strip()} deactivate -- {store_helper}",
            "deactivate",
        )
        session.assert_decoy_root(machine)
        results = answers(console_frames(since))
        print(results)
        assert len(results) == 3, results
        plan, applied = results[1], results[2]
        assert plan["envelope"]["data"]["poweroff"] is False, plan
        assert applied["exit"] == 0, applied
        assert applied["envelope"]["data"]["status"] == "return_requested", applied
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
        machine.succeed(f"test ! -e {ENTRY} && test ! -e {ACTION}")
        no_such_action()

    with subtest("the decoy disk image holds none of the launcher's text"):
        machine.succeed(f"echo {CONTROL} > /root/scan-control && sync")
        image = disk_forensics.snapshot(machine, "post-way-back", restart=False)
        hits = disk_forensics.run_strings_scan(image, TOKENS + [CONTROL])
        assert CONTROL in hits, "the scan did not find the control it was given"
        leaked = sorted(hits - {CONTROL})
        assert not leaked, f"the decoy disk holds the launcher's text: {leaked}"
  '';
}
