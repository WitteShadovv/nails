# Session: the window's launcher in the hidden session
#
# A build with the window (the `gui` cargo feature, and the window's program
# at <hidden-root>/gui/bin/nails-gui) writes at every activation a menu entry
# "Session" and a polkit action for the window's helper. On NixOS both go into
# the hidden root's upper: the entry into the operator's
# ~/.local/share/applications, the action into /etc/polkit-1/actions.
#
# The engine here is the static musl `nails` with that feature, run from the
# hidden volume as an operator runs it (sudo from testuser), with the gui
# workspace's binary in place of the window. In the hidden session the test
# shows:
#
#   - the entry, valid for desktop-file-validate, runs the window with the
#     engine whose helper it starts;
#   - polkit knows the action (`pkaction --verbose`): the neutral message, an
#     administrator's password every time, the engine's path and `helper` as
#     its first argument;
#   - pkexec takes that action for exactly `<engine> helper --stdio`: a
#     test-only rule grants this action alone, so the helper starts as root
#     through pkexec and greets the window that is not there, while another
#     command line of the engine stays pkexec's own action and is refused;
#   - both files lie on the hidden volume, and the decoy root, mounted
#     read-only beside the session, has neither.
#
# After the way back the decoy has neither file and polkit no such action, and
# the decoy disk image, read from the host after a power-off, holds none of
# their text.
{ self, pkgs, ... }:
let
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
      environment.systemPackages = [ pkgs.desktop-file-utils ];
      system.extraDependencies = [
        windowEngine
        packages.nails-gui
      ];
    };

  testScript = _: ''
    import json

    ${diskForensics.pythonSetup}

    from nails_e2e import session

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"
    PEEK = "/run/decoy-peek"
    ENTRY = "/home/testuser/.local/share/applications/session.desktop"
    ACTION = "/etc/polkit-1/actions/session.open.policy"
    # Text only the launcher writes: none of it may reach the decoy disk.
    TOKENS = [
        "Session needs your password each time it opens.",
        '"/mnt/data/gui/bin/nails-gui" --engine "/mnt/data/nails"',
        "TryExec=/mnt/data/gui/bin/nails-gui",
        '<annotate key="org.freedesktop.policykit.exec.path">/mnt/data/nails</annotate>',
    ]
    # Written to the decoy on purpose at the end: the scan must find it.
    CONTROL = "LAUNCHER_SCAN_CONTROL_7f3a"


    def no_such_action():
        """polkit answers, and knows no window action."""
        machine.succeed("pkaction --action-id org.freedesktop.policykit.exec")
        out = machine.fail("pkaction --action-id session.open 2>&1")
        assert "No action with action id session.open" in out, out


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
            "install -D -m 0755 ${packages.nails-gui}/bin/nails-gui /mnt/data/gui/bin/nails-gui"
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

    with subtest("activate through sudo as the operator"):
        activate_log = "/mnt/data/activate.log"
        session.follow_soft_reboot(
            machine,
            f"su testuser -c 'sudo /mnt/data/nails --config {CONFIG} activate -y --overlay-only' "
            f"> {activate_log} 2>&1",
            "activate",
        )
        activation = machine.succeed(f"cat {activate_log}")
        print(activation)
        assert "launcher was not written" not in activation, activation
        session.assert_hidden_root(machine, UPPER)

    with subtest("the entry runs the window with the engine whose helper it starts"):
        entry = machine.succeed(f"cat {ENTRY}")
        print(entry)
        for line in (
            "Name=Session",
            'Exec="/mnt/data/gui/bin/nails-gui" --engine "/mnt/data/nails"',
            "TryExec=/mnt/data/gui/bin/nails-gui",
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

    with subtest("pkexec takes the action for the helper's command line and no other"):
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

    with subtest("both files lie on the hidden volume, and the decoy has neither"):
        machine.succeed(f"test -f {UPPER}{ENTRY} && test -f {UPPER}{ACTION}")
        peek_decoy(decoy_dev, f"test ! -e {PEEK}{ENTRY} && test ! -e {PEEK}{ACTION}")

    with subtest("after the way back the decoy has neither file, and polkit no action"):
        # The same build from the store, as the other session tests run the way
        # back, so nothing on the hidden volume is busy when it closes.
        session.follow_soft_reboot(
            machine,
            f"su testuser -c 'sudo ${windowEngine}/bin/nails --config {CONFIG} deactivate -y'",
            "deactivate",
        )
        session.assert_decoy_root(machine)
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
