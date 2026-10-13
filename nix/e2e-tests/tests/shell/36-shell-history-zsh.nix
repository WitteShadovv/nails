# Test 36: zsh history typed in the hidden session lands in the upper only
#
# The decoy user has a zsh history on the decoy disk. In the hidden session a
# login on tty1 starts an interactive zsh and types a command; zsh writes its
# history file on exit. That write is a copy-up into the hidden root's upper
# (/mnt/data/root/upper/home/testuser/.zsh_history) on the hidden volume, and
# after `nails deactivate` the decoy history file is byte-for-byte what it was
# before activation.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
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
    import secrets

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    UPPER = "/mnt/data/root/upper"
    HISTORY = "/home/testuser/.zsh_history"


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

    with subtest("prepare a decoy zsh history and activate"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_headless_config(CONFIG)
        machine.succeed(
            f"install -m 0600 -o testuser -g users /dev/null {HISTORY}"
            f" && printf 'lower-history-entry\\n' > {HISTORY}"
        )
        # Without a ~/.zshrc, zsh starts its new-user wizard, which eats what
        # the test types next.
        machine.succeed("install -m 0644 -o testuser -g users /dev/null /home/testuser/.zshrc")
        decoy_hash = history_hash()
        canonical_activate(CONFIG, "--overlay-only", "activate")

    token = "secret-zsh-" + secrets.token_hex(6)
    with subtest("a command typed into a hidden zsh is saved to the upper"):
        login_tty1()
        machine.send_chars("zsh\n")
        machine.wait_until_succeeds("pgrep -u testuser -x zsh", timeout=30)
        machine.send_chars("echo zsh-ready-$((40 + 2))\n")
        machine.wait_until_tty_matches("1", "zsh-ready-42", timeout=30)
        machine.send_chars(f"echo {token}\n")
        # zsh writes its history file when the interactive shell exits.
        machine.send_chars("exit\n")
        machine.wait_until_succeeds(f"grep -q {token} {UPPER}{HISTORY}", timeout=30)
        machine.succeed(f"grep -q {token} {HISTORY}")
        machine.send_chars("exit\n")

    with subtest("deactivate: the decoy zsh history is unchanged"):
        canonical_deactivate(CONFIG, "deactivate")
        assert history_hash() == decoy_hash, "the decoy zsh history changed"
        machine.succeed(f"grep -q lower-history-entry {HISTORY}")
        machine.fail(f"grep -q {token} {HISTORY}")
  '';
}
