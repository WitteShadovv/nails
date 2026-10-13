# Test 37: fish history typed in the hidden session lands in the upper only
#
# The decoy user has a fish history on the decoy disk. In the hidden session a
# login on tty1 starts an interactive fish and types a command; fish saves its
# history after every command. That write is a copy-up into the hidden root's
# upper (/mnt/data/root/upper/home/testuser/.local/share/fish/fish_history) on
# the hidden volume, and after `nails deactivate` the decoy history file is
# byte-for-byte what it was before activation.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
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
    import secrets

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"
    HISTORY = "/home/testuser/.local/share/fish/fish_history"


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


    def history_hash():
        return machine.succeed(f"sha256sum {HISTORY} | cut -d' ' -f1").strip()


    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("prepare a decoy fish history and activate"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_headless_config(CONFIG)
        machine.succeed(
            "install -d -m 0700 -o testuser -g users /home/testuser/.local "
            "/home/testuser/.local/share /home/testuser/.local/share/fish"
        )
        machine.succeed(
            f"install -m 0600 -o testuser -g users /dev/null {HISTORY}"
            f" && printf '%s\\n' '- cmd: lower-fish-entry' '  when: 1' > {HISTORY}"
        )
        decoy_hash = history_hash()
        canonical_activate(CONFIG, "--overlay-only", "activate")

    token = "secret-fish-" + secrets.token_hex(6)
    with subtest("a command typed into a hidden fish is saved to the upper"):
        login_tty1()
        machine.send_chars("fish\n")
        machine.wait_until_succeeds("pgrep -u testuser -x fish", timeout=30)
        machine.send_chars("echo fish-ready-(math 40 + 2)\n")
        machine.wait_until_tty_matches("1", "fish-ready-42", timeout=60)
        machine.send_chars(f"echo {token}\n")
        machine.wait_until_succeeds(f"grep -q {token} {UPPER}{HISTORY}", timeout=30)
        machine.succeed(f"grep -q {token} {HISTORY}")
        machine.send_chars("exit\n")
        machine.send_chars("exit\n")

    with subtest("deactivate: the decoy fish history is unchanged"):
        canonical_deactivate(CONFIG, "deactivate")
        assert history_hash() == decoy_hash, "the decoy fish history changed"
        machine.succeed(f"grep -q lower-fish-entry {HISTORY}")
        machine.fail(f"grep -q {token} {HISTORY}")
  '';
}
