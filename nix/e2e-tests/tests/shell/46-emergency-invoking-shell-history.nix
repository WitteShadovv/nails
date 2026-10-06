# Test 46: the shell that runs `sudo nails emergency` writes no history
#
# The pre-unmount shell kill spares the teardown's own invocation so its output
# is not lost. The operator's invoking shell was started inside the hidden
# session, so if it survived it would append the session's commands to the
# history file in the (by then decoy) home on exit. Emergency therefore
# SIGKILLs that interactive shell as its very last step. This drives the real
# flow on a console: an interactive bash started inside the hidden session runs
# `sudo nails emergency`, and afterwards the decoy history must not hold the
# commands typed in it.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "shell-emergency-invoking-shell-history";
  meta.tags = [
    "shell"
    "security"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.bash
      ];
      services.getty.autologinUser = "testuser";
      security.sudo.extraConfig = ''
        Defaults secure_path="/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin"
      '';
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}

    marker = "hidden_tty_marker_93f1"
    history = "/home/testuser/.bash_history"

    machine.start()
    machine.wait_for_unit("multi-user.target")
    config_path = "/tmp/nails-headless.toml"
    write_headless_config(config_path)
    machine.succeed("chmod 0644 " + config_path)

    with subtest("activate and start an interactive shell inside the hidden session"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"nails --config {config_path} activate --overlay-only --session keep -y")
        assert_status_state("active", config_path=config_path)
        machine.wait_for_unit("getty@tty1.service")
        machine.send_key("alt-f1")
        machine.wait_until_succeeds("pgrep -u testuser -t tty1 -x bash")
        # A fresh login shell, started now that /home is overlaid: its history
        # file is the hidden-session one, and it is the shell that will run
        # the emergency.
        machine.send_chars("exec bash -l\n", delay=0)
        machine.send_chars("export PS1='HIDDEN_READY$ '\n", delay=0)
        machine.wait_until_tty_matches("1", r"HIDDEN_READY\$", timeout=60)
        shell_pid = machine.succeed("pgrep -u testuser -t tty1 -x bash").strip()
        machine.send_chars(f"echo {marker}\n", delay=0)
        machine.wait_until_tty_matches("1", marker, timeout=30)

    with subtest("sudo nails emergency from that shell kills it as the last step"):
        machine.send_chars(f"sudo nails --config {config_path} emergency\n", delay=0)
        machine.wait_until_succeeds("! findmnt -rn -t overlay /home", timeout=60)
        machine.wait_until_succeeds("! pgrep -x nails", timeout=60)
        machine.wait_until_fails(f"kill -0 {shell_pid}", timeout=30)
        # Before the fix the invoking shell survived; leaving it would flush
        # its in-memory history on this exit. Now these keys reach the freshly
        # respawned autologin shell instead.
        machine.send_chars("exit\n", delay=0)
        assert_no_overlays(["/home", "/etc"])

    with subtest("the decoy history holds nothing typed in the hidden session"):
        content = machine.succeed(f"cat {history} 2>/dev/null || true")
        assert marker not in content, content
        assert "nails --config" not in content, content
  '';
}
