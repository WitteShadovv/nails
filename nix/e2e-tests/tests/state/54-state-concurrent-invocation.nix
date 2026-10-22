# Test 54: State Concurrent Invocation
#
# Two `nails activate` runs never interleave. The first runs interactively on
# tty1 (no -y): it takes the inter-process state lock on the hidden volume and
# then waits at its logout confirmation. A second `nails activate -y` meanwhile
# fails fast, naming the live holder's PID, and prepares nothing: no next root,
# still the plain decoy. Confirming the first one then enters the hidden root
# as usual, and the session ends normally.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "state-concurrent-invocation";
  meta.tags = [ "state" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    import re

    from nails_e2e import run_command_capture, session

    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"


    def login_tty1():
        machine.wait_for_unit("getty@tty1.service")
        machine.succeed("printf '\\033[H\\033[2J' > /dev/tty1")
        machine.send_chars("testuser\n")
        machine.wait_until_tty_matches("1", "Password: ", timeout=60)
        machine.send_chars("test\n")
        machine.wait_until_succeeds(
            "loginctl list-sessions --no-legend | grep -q testuser", timeout=60
        )


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

    with subtest("an interactive activation holds the lock at its confirmation"):
        login_tty1()
        machine.send_chars(f"sudo nails --config {CONFIG} activate --overlay-only\n")
        machine.wait_until_tty_matches("1", r"Continue\? \[y/N\]", timeout=120)

    with subtest("a second activation fails fast on the inter-process lock"):
        result = run_command_capture(
            machine,
            "state-concurrent-secondary",
            f"nails --config {CONFIG} activate --overlay-only -y",
        )
        assert result["rc"] != 0, f"Expected the second activation to fail: {result}"
        match = re.search(r"another nails operation is running \(pid (\d+)\)", result["combined"])
        assert match, f"Expected a lock refusal naming the holder: {result['combined']!r}"
        holder = match.group(1)
        cmdline = machine.succeed(f"tr '\\0' ' ' < /proc/{holder}/cmdline")
        assert "activate" in cmdline, f"pid {holder} is not the waiting activation: {cmdline!r}"
        session.assert_decoy_root(machine)
        machine.fail("test -e /run/nextroot/etc")
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "decoy", status

    with subtest("confirming the first activation enters the hidden root"):
        session.follow_soft_reboot(
            machine,
            "y (confirming the waiting activation on tty1)",
            "state-concurrent-primary",
            start=lambda: machine.send_chars("y\n"),
        )
        session.assert_hidden_root(machine)
        status = read_status_json(config_path=CONFIG)
        assert status["place"] == "hidden", status

    with subtest("the session ends normally"):
        canonical_deactivate(CONFIG, "state-concurrent-deactivate")
  '';
}
